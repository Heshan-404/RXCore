use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UdpSocket;
use uuid::Uuid;
use bytes::BufMut;

use crate::inbound::InboundTransportStream;
use crate::outbound::OutboundHandler;
use crate::state::EngineState;

use std::net::SocketAddr;
use std::collections::HashMap;
use socket2::{Socket, Domain, Type, Protocol};

pub struct UdpOutbound;

impl UdpOutbound {
    pub fn new() -> Self {
        Self
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
                    let bind_addr = if dest_socket_addr.is_ipv4() {
                        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                    } else {
                        SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
                    };
                    let domain = if dest_socket_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
                    let socket = match Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)) {
                        Ok(s) => s,
                        Err(_) => {
                            buf_offset = payload_needed;
                            continue;
                        }
                    };
                    if socket.set_recv_buffer_size(64 * 1024).is_err()
                        || socket.set_send_buffer_size(64 * 1024).is_err()
                        || socket.bind(&bind_addr.into()).is_err()
                    {
                        buf_offset = payload_needed;
                        continue;
                    }
                    let std_socket: std::net::UdpSocket = socket.into();
                    if std_socket.set_nonblocking(true).is_err() {
                        buf_offset = payload_needed;
                        continue;
                    }
                    let tokio_socket = match UdpSocket::from_std(std_socket) {
                        Ok(s) => s,
                        Err(_) => {
                            buf_offset = payload_needed;
                            continue;
                        }
                    };
                    let arc_socket = Arc::new(tokio_socket);
                    let last_active = Arc::new(AtomicU64::new(current_secs()));

                    let socket_clone = Arc::clone(&arc_socket);
                    let rx_counter_clone = Arc::clone(&rx_counter);
                    let user_stats_clone = user_stats.clone();
                    let downlink_tx_clone = downlink_tx.clone();
                    let last_active_clone = Arc::clone(&last_active);

                    let handle = tokio::spawn(async move {
                        let mut udp_buf = [0u8; 65535];
                        let mut send_buf = bytes::BytesMut::with_capacity(65535);
                        loop {
                            match socket_clone.recv_from(&mut udp_buf).await {
                                Ok((0, _)) => break,
                                Err(_) => continue,
                                Ok((n, remote_addr)) => {
                                    last_active_clone.store(current_secs(), Ordering::Relaxed);
                                    send_buf.clear();
                                    match remote_addr.ip() {
                                        std::net::IpAddr::V4(ipv4) => {
                                            send_buf.put_u8(1);
                                            send_buf.put_slice(&ipv4.octets());
                                        }
                                        std::net::IpAddr::V6(ipv6) => {
                                            send_buf.put_u8(4);
                                            send_buf.put_slice(&ipv6.octets());
                                        }
                                    }
                                    send_buf.put_u16(remote_addr.port());
                                    send_buf.put_u16(n as u16);
                                    send_buf.put_slice(&udp_buf[..n]);

                                    let frozen = send_buf.split().freeze();
                                    if downlink_tx_clone.try_send(frozen).is_err() {
                                        if downlink_tx_clone.is_closed() {
                                            break;
                                        }
                                        continue;
                                    }
                                    rx_counter_clone.fetch_add(n as u64, Ordering::Relaxed);
                                    if let Some(ref stats) = user_stats_clone {
                                        stats.rx.fetch_add(n as u64, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    });

                    sockets.insert(dest_socket_addr, OutboundSession {
                        socket: Arc::clone(&arc_socket),
                        handle,
                        last_active,
                    });

                    arc_socket
                }
            };

            if socket.send_to(payload_slice, dest_socket_addr).await.is_ok() {
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

        let target_addr = if let Ok(ip) = dest_addr.parse::<std::net::IpAddr>() {
            SocketAddr::new(ip, dest_port)
        } else {
            let addrs = tokio::net::lookup_host(format!("{}:{}", dest_addr, dest_port)).await?;
            addrs.into_iter().next().ok_or("Failed to resolve standard UDP target")?
        };

        let bind_addr = if target_addr.is_ipv4() {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        };
        let domain = if target_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_recv_buffer_size(64 * 1024)?;
        socket.set_send_buffer_size(64 * 1024)?;
        socket.bind(&bind_addr.into())?;
        
        let std_socket: std::net::UdpSocket = socket.into();
        std_socket.set_nonblocking(true)?;
        let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)?;
        tokio_socket.connect(target_addr).await?;
        let socket_arc = Arc::new(tokio_socket);

        let (in_reader, mut in_writer) = tokio::io::split(inbound_stream);
        let mut buf_reader = BufReader::with_capacity(65536, in_reader);

        let socket_clone = Arc::clone(&socket_arc);
        let rx_counter_clone = Arc::clone(&rx_counter);
        let user_stats_clone = user_stats.clone();

        let downlink_task = tokio::spawn(async move {
            let mut udp_buf = [0u8; 65535];
            let mut send_buf = bytes::BytesMut::with_capacity(65535);
            loop {
                match socket_clone.recv(&mut udp_buf).await {
                    Ok(0) => break,
                    Err(_) => continue,
                    Ok(n) => {
                        send_buf.clear();
                        send_buf.put_u16(n as u16);
                        send_buf.put_slice(&udp_buf[..n]);

                        let frozen = send_buf.split().freeze();
                        if in_writer.write_all(&frozen).await.is_err() {
                            break;
                        }
                        rx_counter_clone.fetch_add(n as u64, Ordering::Relaxed);
                        if let Some(ref stats) = user_stats_clone {
                            stats.rx.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    }
                }
            }
        });

        let mut header_buf = [0u8; 2];
        let mut payload_buf = [0u8; 65535];

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

            if socket_arc.send(&payload_buf[..frame_len]).await.is_ok() {
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
            let target_addr = match atyp {
                0x01 => {
                    if frame_len < offset + 4 + 2 { continue; }
                    let mut ip = [0u8; 4];
                    ip.copy_from_slice(&payload_buf[offset..offset+4]);
                    offset += 4;
                    let port = u16::from_be_bytes([payload_buf[offset], payload_buf[offset+1]]);
                    offset += 2;
                    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)), port)
                }
                0x04 => {
                    if frame_len < offset + 16 + 2 { continue; }
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(&payload_buf[offset..offset+16]);
                    offset += 16;
                    let port = u16::from_be_bytes([payload_buf[offset], payload_buf[offset+1]]);
                    offset += 2;
                    SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)), port)
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
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let addrs = match tokio::net::lookup_host(format!("{}:{}", domain_str, port)).await {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    match addrs.into_iter().next() {
                        Some(a) => a,
                        None => continue,
                    }
                }
                _ => continue,
            };

            if offset > frame_len {
                continue;
            }

            let payload = &payload_buf[offset..frame_len];

            let socket = match sockets.get(&assoc_id) {
                Some(session) => {
                    session.last_active.store(current_secs(), Ordering::Relaxed);
                    Arc::clone(&session.socket)
                }
                None => {
                    let bind_addr = if target_addr.is_ipv4() {
                        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                    } else {
                        SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
                    };
                    let domain = if target_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
                    let socket = match Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    if socket.set_recv_buffer_size(64 * 1024).is_err()
                        || socket.set_send_buffer_size(64 * 1024).is_err()
                        || socket.bind(&bind_addr.into()).is_err()
                    {
                        continue;
                    }
                    let std_socket: std::net::UdpSocket = socket.into();
                    if std_socket.set_nonblocking(true).is_err() {
                        continue;
                    }
                    let tokio_socket = match UdpSocket::from_std(std_socket) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let arc_socket = Arc::new(tokio_socket);
                    let last_active = Arc::new(AtomicU64::new(current_secs()));

                    let socket_clone = Arc::clone(&arc_socket);
                    let rx_counter_clone = Arc::clone(&rx_counter);
                    let user_stats_clone = user_stats.clone();
                    let downlink_tx_clone = downlink_tx.clone();
                    let last_active_clone = Arc::clone(&last_active);

                    let handle = tokio::spawn(async move {
                        let mut udp_buf = [0u8; 65535];
                        let mut send_buf = bytes::BytesMut::with_capacity(65535);
                        loop {
                            match socket_clone.recv_from(&mut udp_buf).await {
                                Ok((0, _)) => break,
                                Err(_) => continue,
                                Ok((n, remote_addr)) => {
                                    last_active_clone.store(current_secs(), Ordering::Relaxed);
                                    send_buf.clear();
                                    
                                    // Reserve 2 bytes for total frame length
                                    send_buf.put_u16(0);
                                    
                                    // Write association ID
                                    send_buf.put_u16(assoc_id);
                                    
                                    // Write remote address
                                    match remote_addr.ip() {
                                        std::net::IpAddr::V4(ipv4) => {
                                            send_buf.put_u8(1);
                                            send_buf.put_slice(&ipv4.octets());
                                        }
                                        std::net::IpAddr::V6(ipv6) => {
                                            send_buf.put_u8(4);
                                            send_buf.put_slice(&ipv6.octets());
                                        }
                                    }
                                    send_buf.put_u16(remote_addr.port());

                                    // Compute total frame length (excluding the length prefix itself)
                                    let total_len = send_buf.len() - 2 + n;
                                    
                                    // Fill in the length prefix
                                    send_buf[0..2].copy_from_slice(&(total_len as u16).to_be_bytes());
                                    
                                    // Append payload
                                    send_buf.put_slice(&udp_buf[..n]);

                                    let frozen = send_buf.split().freeze();
                                    if downlink_tx_clone.try_send(frozen).is_err() {
                                        if downlink_tx_clone.is_closed() {
                                            break;
                                        }
                                        continue; // Drop packet
                                    }
                                    rx_counter_clone.fetch_add(n as u64, Ordering::Relaxed);
                                    if let Some(ref stats) = user_stats_clone {
                                        stats.rx.fetch_add(n as u64, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    });

                    sockets.insert(assoc_id, OutboundSession {
                        socket: Arc::clone(&arc_socket),
                        handle,
                        last_active,
                    });

                    arc_socket
                }
            };

            if socket.send_to(payload, target_addr).await.is_ok() {
                tx_counter.fetch_add(payload.len() as u64, Ordering::Relaxed);
                if let Some(ref stats) = user_stats {
                    stats.tx.fetch_add(payload.len() as u64, Ordering::Relaxed);
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
