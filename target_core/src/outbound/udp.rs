use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UdpSocket;
use uuid::Uuid;
use bytes::BufMut;
use std::net::SocketAddr;
use std::collections::HashMap;
use socket2::{Socket, Domain, Type, Protocol};

use crate::inbound::InboundTransportStream;
use crate::outbound::OutboundHandler;
use crate::state::EngineState;

pub struct UdpOutbound {
    outbound_proxy: Option<String>,
    bind_address: Option<String>,
}

impl UdpOutbound {
    pub fn new(outbound_proxy: Option<String>, bind_address: Option<String>) -> Self {
        Self { outbound_proxy, bind_address }
    }
}

async fn read_exact_to_buf<R: tokio::io::AsyncReadExt + Unpin>(
    stream: &mut R,
    buf: &mut bytes::BytesMut,
    needed: usize,
) -> std::io::Result<()> {
    let current_len = buf.len();
    if current_len < needed {
        buf.resize(needed, 0);
        stream.read_exact(&mut buf[current_len..needed]).await?;
    }
    Ok(())
}

fn current_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct OutboundSession {
    socket: Arc<tokio::net::UdpSocket>,
    handle: tokio::task::JoinHandle<()>,
    last_active: Arc<AtomicU64>,
    send_target: SocketAddr,
    _assoc: Option<tokio::net::TcpStream>,
}

#[async_trait]
impl OutboundHandler for UdpOutbound {
    async fn handle(
        &self,
        inbound_stream: InboundTransportStream,
        dest_addr: &str,
        dest_port: u16,
        rx_counter: Arc<AtomicU64>,
        tx_counter: Arc<AtomicU64>,
        engine_state: &Arc<EngineState>,
        client_email: &Option<String>,
        _conn_id: &Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if dest_addr == "sp.packet-addr.v2fly.arpa" {
            self.handle_packetaddr(inbound_stream, rx_counter, tx_counter, engine_state, client_email).await
        } else if dest_addr == "0.0.0.0" && dest_port == 0 {
            self.handle_multiplexed(inbound_stream, rx_counter, tx_counter, engine_state, client_email).await
        } else {
            self.handle_standard(inbound_stream, dest_addr, dest_port, rx_counter, tx_counter, engine_state, client_email).await
        }
    }
}

pub async fn create_outbound_udp(
    dest_host: &str,
    dest_port: u16,
    outbound_proxy: &Option<String>,
    bind_ip: &Option<String>,
) -> Result<(Arc<UdpSocket>, Option<tokio::net::TcpStream>, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ref proxy) = outbound_proxy {
        let assoc = crate::transport::socks5_udp_associate(proxy, bind_ip).await?;
        let bind_addr = if assoc.proxy_udp_addr.is_ipv4() {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        Ok((Arc::new(socket), Some(assoc.association_stream), assoc.proxy_udp_addr))
    } else {
        let target_addr = if let Ok(ip) = dest_host.parse::<std::net::IpAddr>() {
            SocketAddr::new(ip, dest_port)
        } else {
            let addrs = tokio::net::lookup_host(format!("{}:{}", dest_host, dest_port)).await?;
            addrs.into_iter().next().ok_or("Failed to resolve UDP target")?
        };
        let bind_addr = if target_addr.is_ipv4() {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        };
        let domain = if target_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = socket2::Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        let _ = socket.set_recv_buffer_size(64 * 1024);
        let _ = socket.set_send_buffer_size(64 * 1024);
        socket.bind(&bind_addr.into())?;
        let std_socket: std::net::UdpSocket = socket.into();
        std_socket.set_nonblocking(true)?;
        let tokio_socket = UdpSocket::from_std(std_socket)?;
        Ok((Arc::new(tokio_socket), None, target_addr))
    }
}

impl UdpOutbound {
    async fn handle_packetaddr(
        &self,
        inbound_stream: InboundTransportStream,
        rx_counter: Arc<AtomicU64>,
        tx_counter: Arc<AtomicU64>,
        engine_state: &Arc<EngineState>,
        client_email: &Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let user_stats = engine_state.get_user_stats(client_email);
        let (mut in_reader, mut in_writer) = tokio::io::split(inbound_stream);
        let mut buf = bytes::BytesMut::with_capacity(65536);
        let (downlink_tx, mut downlink_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(128);

        tokio::spawn(async move {
            while let Some(buf) = downlink_rx.recv().await {
                if in_writer.write_all(&buf).await.is_err() {
                    break;
                }
            }
        });

        let mut sockets: HashMap<SocketAddr, OutboundSession> = HashMap::new();
        let mut last_cleanup = std::time::Instant::now();
        let mut buf_offset = 0;

        loop {
            let atyp_needed = buf_offset + 1;
            if read_exact_to_buf(&mut in_reader, &mut buf, atyp_needed).await.is_err() {
                break;
            }
            let atyp = buf[buf_offset];

            let (dest_host, dest_port, next_offset) = match atyp {
                1 => {
                    let needed = buf_offset + 1 + 4 + 2;
                    if read_exact_to_buf(&mut in_reader, &mut buf, needed).await.is_err() {
                        break;
                    }
                    let ip_start = buf_offset + 1;
                    let port_start = ip_start + 4;
                    let octets: [u8; 4] = buf[ip_start..port_start].try_into()?;
                    let port = u16::from_be_bytes([buf[port_start], buf[port_start + 1]]);
                    (std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)).to_string(), port, needed)
                }
                3 => {
                    let len_needed = buf_offset + 1 + 1;
                    if read_exact_to_buf(&mut in_reader, &mut buf, len_needed).await.is_err() {
                        break;
                    }
                    let domain_len = buf[buf_offset + 1] as usize;
                    let needed = buf_offset + 1 + 1 + domain_len + 2;
                    if read_exact_to_buf(&mut in_reader, &mut buf, needed).await.is_err() {
                        break;
                    }
                    let domain_start = buf_offset + 1 + 1;
                    let port_start = domain_start + domain_len;
                    let domain_slice = &buf[domain_start..port_start];
                    let domain_str = match std::str::from_utf8(domain_slice) {
                        Ok(s) => s.to_string(),
                        Err(_) => break,
                    };
                    let port = u16::from_be_bytes([buf[port_start], buf[port_start + 1]]);
                    (domain_str, port, needed)
                }
                4 => {
                    let needed = buf_offset + 1 + 16 + 2;
                    if read_exact_to_buf(&mut in_reader, &mut buf, needed).await.is_err() {
                        break;
                    }
                    let ip_start = buf_offset + 1;
                    let port_start = ip_start + 16;
                    let octets: [u8; 16] = buf[ip_start..port_start].try_into()?;
                    let port = u16::from_be_bytes([buf[port_start], buf[port_start + 1]]);
                    (std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)).to_string(), port, needed)
                }
                _ => break,
            };

            let len_needed = next_offset + 2;
            if read_exact_to_buf(&mut in_reader, &mut buf, len_needed).await.is_err() {
                break;
            }
            let payload_len = u16::from_be_bytes([buf[next_offset], buf[next_offset + 1]]) as usize;

            if payload_len > 65535 {
                break;
            }

            let payload_needed = len_needed + payload_len;
            if read_exact_to_buf(&mut in_reader, &mut buf, payload_needed).await.is_err() {
                break;
            }

            let payload_start = len_needed;
            let payload_slice = &buf[payload_start..payload_needed];

            let dest_socket_addr = match tokio::net::lookup_host(format!("{}:{}", dest_host, dest_port)).await {
                Ok(mut a) => match a.next() {
                    Some(sa) => sa,
                    None => {
                        buf_offset = payload_needed;
                        continue;
                    }
                },
                Err(_) => {
                    buf_offset = payload_needed;
                    continue;
                }
            };

            let socket = match sockets.get(&dest_socket_addr) {
                Some(session) => {
                    session.last_active.store(current_secs(), Ordering::Relaxed);
                    Arc::clone(&session.socket)
                }
                None => {
                    let (tokio_socket, assoc_stream, send_target) = match create_outbound_udp(&dest_host, dest_port, &self.outbound_proxy, &self.bind_address).await {
                        Ok(res) => res,
                        Err(_) => {
                            buf_offset = payload_needed;
                            continue;
                        }
                    };
                    let arc_socket = tokio_socket;
                    let last_active = Arc::new(AtomicU64::new(current_secs()));

                    let socket_clone = Arc::clone(&arc_socket);
                    let rx_counter_clone = Arc::clone(&rx_counter);
                    let user_stats_clone = user_stats.clone();
                    let downlink_tx_clone = downlink_tx.clone();
                    let last_active_clone = Arc::clone(&last_active);
                    let is_socks = self.outbound_proxy.is_some();

                    let handle = tokio::spawn(async move {
                        let mut udp_buf = [0u8; 65535];
                        let mut send_buf = bytes::BytesMut::with_capacity(65535);
                        loop {
                            match socket_clone.recv_from(&mut udp_buf).await {
                                Ok((0, _)) => break,
                                Err(_) => continue,
                                Ok((n, remote_addr)) => {
                                    last_active_clone.store(current_secs(), Ordering::Relaxed);
                                    let (payload, payload_len, actual_src) = if is_socks {
                                        if let Ok((src_ip, src_port, offset)) = crate::transport::parse_socks5_udp(&udp_buf[..n]) {
                                            (&udp_buf[offset..n], n - offset, SocketAddr::new(src_ip, src_port))
                                        } else {
                                            continue;
                                        }
                                    } else {
                                        (&udp_buf[..n], n, remote_addr)
                                    };

                                    send_buf.clear();
                                    send_buf.put_u16(0);
                                    send_buf.put_u16(0);
                                    match actual_src.ip() {
                                        std::net::IpAddr::V4(ipv4) => {
                                            send_buf.put_u8(1);
                                            send_buf.put_slice(&ipv4.octets());
                                        }
                                        std::net::IpAddr::V6(ipv6) => {
                                            send_buf.put_u8(4);
                                            send_buf.put_slice(&ipv6.octets());
                                        }
                                    }
                                    send_buf.put_u16(actual_src.port());

                                    let total_len = send_buf.len() - 2 + payload_len;
                                    send_buf[0..2].copy_from_slice(&(total_len as u16).to_be_bytes());
                                    send_buf.put_slice(payload);

                                    let frozen = send_buf.split().freeze();
                                    if downlink_tx_clone.try_send(frozen).is_err() {
                                        if downlink_tx_clone.is_closed() {
                                            break;
                                        }
                                        continue;
                                    }
                                    rx_counter_clone.fetch_add(payload_len as u64, Ordering::Relaxed);
                                    if let Some(ref stats) = user_stats_clone {
                                        stats.rx.fetch_add(payload_len as u64, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    });

                    sockets.insert(dest_socket_addr, OutboundSession {
                        socket: Arc::clone(&arc_socket),
                        handle,
                        last_active,
                        send_target,
                        _assoc: assoc_stream,
                    });

                    arc_socket
                }
            };

            let is_socks = self.outbound_proxy.is_some();
            let send_res = if is_socks {
                if let Some(session) = sockets.get(&dest_socket_addr) {
                    let mut socks5_buf = Vec::with_capacity(payload_slice.len() + 30);
                    crate::transport::wrap_socks5_udp_host(&dest_host, dest_port, payload_slice, &mut socks5_buf);
                    socket.send_to(&socks5_buf, session.send_target).await
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, "Session missing"))
                }
            } else {
                socket.send_to(payload_slice, dest_socket_addr).await
            };

            if send_res.is_ok() {
                tx_counter.fetch_add(payload_len as u64, Ordering::Relaxed);
                if let Some(ref stats) = user_stats {
                    stats.tx.fetch_add(payload_len as u64, Ordering::Relaxed);
                }
            }

            buf_offset = payload_needed;
            if buf_offset > 32768 {
                let _ = buf.split_to(buf_offset);
                buf_offset = 0;
            }

            if last_cleanup.elapsed() > std::time::Duration::from_secs(10) {
                let now = current_secs();
                let mut to_remove = Vec::new();
                for (&id, session) in sockets.iter() {
                    if now.saturating_sub(session.last_active.load(Ordering::Relaxed)) > 60 {
                        to_remove.push(id);
                    }
                }
                for id in to_remove {
                    if let Some(session) = sockets.remove(&id) {
                        session.handle.abort();
                    }
                }
                last_cleanup = std::time::Instant::now();
            }
        }

        for (_, session) in sockets.drain() {
            session.handle.abort();
        }
        Ok(())
    }

    async fn handle_standard(
        &self,
        inbound_stream: InboundTransportStream,
        dest_addr: &str,
        dest_port: u16,
        rx_counter: Arc<AtomicU64>,
        tx_counter: Arc<AtomicU64>,
        engine_state: &Arc<EngineState>,
        client_email: &Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let user_stats = engine_state.get_user_stats(client_email);
        let (socket_arc, assoc_stream, send_target) = create_outbound_udp(dest_addr, dest_port, &self.outbound_proxy, &self.bind_address).await?;
        socket_arc.connect(send_target).await?;

        let (in_reader, mut in_writer) = tokio::io::split(inbound_stream);
        let mut buf_reader = BufReader::with_capacity(65536, in_reader);

        let socket_clone = Arc::clone(&socket_arc);
        let rx_counter_clone = Arc::clone(&rx_counter);
        let user_stats_clone = user_stats.clone();
        let is_socks = self.outbound_proxy.is_some();
        let _assoc = assoc_stream;

        let downlink_task = tokio::spawn(async move {
            let mut udp_buf = [0u8; 65535];
            let mut send_buf = bytes::BytesMut::with_capacity(65535);
            loop {
                match socket_clone.recv(&mut udp_buf).await {
                    Ok(0) => break,
                    Err(_) => continue,
                    Ok(n) => {
                        let (payload, payload_len) = if is_socks {
                            if let Ok((_src_ip, _src_port, offset)) = crate::transport::parse_socks5_udp(&udp_buf[..n]) {
                                (&udp_buf[offset..n], n - offset)
                            } else {
                                continue;
                            }
                        } else {
                            (&udp_buf[..n], n)
                        };
                        send_buf.clear();
                        send_buf.put_u16(payload_len as u16);
                        send_buf.put_slice(payload);

                        let frozen = send_buf.split().freeze();
                        if in_writer.write_all(&frozen).await.is_err() {
                            break;
                        }
                        rx_counter_clone.fetch_add(payload_len as u64, Ordering::Relaxed);
                        if let Some(ref stats) = user_stats_clone {
                            stats.rx.fetch_add(payload_len as u64, Ordering::Relaxed);
                        }
                    }
                }
            }
        });

        let mut header_buf = [0u8; 2];
        let mut payload_buf = [0u8; 65535];
        let mut socks5_buf = Vec::with_capacity(65535);

        loop {
            if buf_reader.read_exact(&mut header_buf).await.is_err() {
                break;
            }
            let frame_len = u16::from_be_bytes(header_buf) as usize;
            if frame_len == 0 || frame_len > 65535 {
                break;
            }
            if buf_reader.read_exact(&mut payload_buf[..frame_len]).await.is_err() {
                break;
            }

            let send_res = if is_socks {
                crate::transport::wrap_socks5_udp_host(dest_addr, dest_port, &payload_buf[..frame_len], &mut socks5_buf);
                socket_arc.send(&socks5_buf).await
            } else {
                socket_arc.send(&payload_buf[..frame_len]).await
            };

            if send_res.is_ok() {
                tx_counter.fetch_add(frame_len as u64, Ordering::Relaxed);
                if let Some(ref stats) = user_stats {
                    stats.tx.fetch_add(frame_len as u64, Ordering::Relaxed);
                }
            }
        }

        downlink_task.abort();
        Ok(())
    }

    async fn handle_multiplexed(
        &self,
        inbound_stream: InboundTransportStream,
        rx_counter: Arc<AtomicU64>,
        tx_counter: Arc<AtomicU64>,
        engine_state: &Arc<EngineState>,
        client_email: &Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let user_stats = engine_state.get_user_stats(client_email);
        let (in_reader, mut in_writer) = tokio::io::split(inbound_stream);
        let mut buf_reader = BufReader::with_capacity(65536, in_reader);
        let (downlink_tx, mut downlink_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(128);

        tokio::spawn(async move {
            while let Some(buf) = downlink_rx.recv().await {
                if in_writer.write_all(&buf).await.is_err() {
                    break;
                }
            }
        });

        let mut sockets: HashMap<u16, OutboundSession> = HashMap::new();
        let mut header_buf = [0u8; 4];
        let mut payload_buf = [0u8; 65535];
        let mut last_cleanup = std::time::Instant::now();

        loop {
            if buf_reader.read_exact(&mut header_buf).await.is_err() {
                break;
            }
            let total_len = u16::from_be_bytes([header_buf[0], header_buf[1]]) as usize;
            let assoc_id = u16::from_be_bytes([header_buf[2], header_buf[3]]);
            if total_len < 2 || total_len > 65535 {
                break;
            }
            let frame_len = total_len - 2;
            if buf_reader.read_exact(&mut payload_buf[..frame_len]).await.is_err() {
                break;
            }

            let atyp = payload_buf[0];
            let mut offset = 1;
            let (target_host, target_port, target_addr) = match atyp {
                0x01 => {
                    if frame_len < offset + 4 + 2 { continue; }
                    let mut ip = [0u8; 4];
                    ip.copy_from_slice(&payload_buf[offset..offset+4]);
                    offset += 4;
                    let port = u16::from_be_bytes([payload_buf[offset], payload_buf[offset+1]]);
                    offset += 2;
                    let sa = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)), port);
                    (sa.ip().to_string(), port, sa)
                }
                0x04 => {
                    if frame_len < offset + 16 + 2 { continue; }
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(&payload_buf[offset..offset+16]);
                    offset += 16;
                    let port = u16::from_be_bytes([payload_buf[offset], payload_buf[offset+1]]);
                    offset += 2;
                    let sa = SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)), port);
                    (sa.ip().to_string(), port, sa)
                }
                0x03 => {
                    if frame_len < offset + 1 { continue; }
                    let len = payload_buf[offset] as usize;
                    offset += 1;
                    if frame_len < offset + len + 2 { continue; }
                    let domain_bytes = &payload_buf[offset..offset+len];
                    offset += len;
                    let port = u16::from_be_bytes([payload_buf[offset], payload_buf[offset+1]]);
                    offset += 2;
                    let domain_str = match std::str::from_utf8(domain_bytes) {
                        Ok(s) => s.to_string(),
                        Err(_) => continue,
                    };
                    let addrs = match tokio::net::lookup_host(format!("{}:{}", domain_str, port)).await {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    match addrs.into_iter().next() {
                        Some(a) => (domain_str, port, a),
                        None => continue,
                    }
                }
                _ => continue,
            };

            if offset > frame_len {
                continue;
            }

            let payload = &payload_buf[offset..frame_len];
            let payload_len = payload.len();

            let socket = match sockets.get(&assoc_id) {
                Some(session) => {
                    session.last_active.store(current_secs(), Ordering::Relaxed);
                    Arc::clone(&session.socket)
                }
                None => {
                    let (tokio_socket, assoc_stream, send_target) = match create_outbound_udp(&target_host, target_port, &self.outbound_proxy, &self.bind_address).await {
                        Ok(res) => res,
                        Err(_) => continue,
                    };
                    let arc_socket = tokio_socket;
                    let last_active = Arc::new(AtomicU64::new(current_secs()));

                    let socket_clone = Arc::clone(&arc_socket);
                    let rx_counter_clone = Arc::clone(&rx_counter);
                    let user_stats_clone = user_stats.clone();
                    let downlink_tx_clone = downlink_tx.clone();
                    let last_active_clone = Arc::clone(&last_active);
                    let is_socks = self.outbound_proxy.is_some();

                    let handle = tokio::spawn(async move {
                        let mut udp_buf = [0u8; 65535];
                        let mut send_buf = bytes::BytesMut::with_capacity(65535);
                        loop {
                            match socket_clone.recv_from(&mut udp_buf).await {
                                Ok((0, _)) => break,
                                Err(_) => continue,
                                Ok((n, remote_addr)) => {
                                    last_active_clone.store(current_secs(), Ordering::Relaxed);
                                    let (payload, payload_len, actual_src) = if is_socks {
                                        if let Ok((src_ip, src_port, offset)) = crate::transport::parse_socks5_udp(&udp_buf[..n]) {
                                            (&udp_buf[offset..n], n - offset, SocketAddr::new(src_ip, src_port))
                                        } else {
                                            continue;
                                        }
                                    } else {
                                        (&udp_buf[..n], n, remote_addr)
                                    };

                                    send_buf.clear();
                                    send_buf.put_u16(0);
                                    send_buf.put_u16(assoc_id);
                                    match actual_src.ip() {
                                        std::net::IpAddr::V4(ipv4) => {
                                            send_buf.put_u8(1);
                                            send_buf.put_slice(&ipv4.octets());
                                        }
                                        std::net::IpAddr::V6(ipv6) => {
                                            send_buf.put_u8(4);
                                            send_buf.put_slice(&ipv6.octets());
                                        }
                                    }
                                    send_buf.put_u16(actual_src.port());

                                    let total_len = send_buf.len() - 2 + payload_len;
                                    send_buf[0..2].copy_from_slice(&(total_len as u16).to_be_bytes());
                                    send_buf.put_slice(payload);

                                    let frozen = send_buf.split().freeze();
                                    if downlink_tx_clone.try_send(frozen).is_err() {
                                        if downlink_tx_clone.is_closed() {
                                            break;
                                        }
                                        continue;
                                    }
                                    rx_counter_clone.fetch_add(payload_len as u64, Ordering::Relaxed);
                                    if let Some(ref stats) = user_stats_clone {
                                        stats.rx.fetch_add(payload_len as u64, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    });

                    sockets.insert(assoc_id, OutboundSession {
                        socket: Arc::clone(&arc_socket),
                        handle,
                        last_active,
                        send_target,
                        _assoc: assoc_stream,
                    });

                    arc_socket
                }
            };

            let is_socks = self.outbound_proxy.is_some();
            let send_res = if is_socks {
                if let Some(session) = sockets.get(&assoc_id) {
                    let mut socks5_buf = Vec::with_capacity(payload.len() + 30);
                    crate::transport::wrap_socks5_udp_host(&target_host, target_port, payload, &mut socks5_buf);
                    socket.send_to(&socks5_buf, session.send_target).await
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, "Session missing"))
                }
            } else {
                socket.send_to(payload, target_addr).await
            };

            if send_res.is_ok() {
                tx_counter.fetch_add(payload_len as u64, Ordering::Relaxed);
                if let Some(ref stats) = user_stats {
                    stats.tx.fetch_add(payload_len as u64, Ordering::Relaxed);
                }
            }

            if last_cleanup.elapsed() > std::time::Duration::from_secs(10) {
                let now = current_secs();
                let mut to_remove = Vec::new();
                for (&id, session) in sockets.iter() {
                    if now.saturating_sub(session.last_active.load(Ordering::Relaxed)) > 60 {
                        to_remove.push(id);
                    }
                }
                for id in to_remove {
                    if let Some(session) = sockets.remove(&id) {
                        session.handle.abort();
                    }
                }
                last_cleanup = std::time::Instant::now();
            }
        }

        for (_, session) in sockets.drain() {
            session.handle.abort();
        }
        Ok(())
    }
}
