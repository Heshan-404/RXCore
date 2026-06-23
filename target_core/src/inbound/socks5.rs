use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};
use bytes::BufMut;

use crate::config::InboundConfig;
use crate::dispatcher::dispatch_connection;
use crate::state::EngineState;
use crate::inbound::InboundListener;
use async_trait::async_trait;

use socket2::{Socket, Domain, Type, Protocol};

pub struct Socks5Inbound {
    pub config: InboundConfig,
}

impl Socks5Inbound {
    pub fn new(config: InboundConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl InboundListener for Socks5Inbound {
    async fn start(self: Arc<Self>, engine_state: Arc<EngineState>) -> Result<(), std::io::Error> {
        let addr = SocketAddr::new(self.config.listen, self.config.port);
        let listener = TcpListener::bind(addr).await?;
        info!(tag = %self.config.tag, address = %addr, "SOCKS5 client inbound listener bound");

        let _ = get_udp_upstream_tx(&engine_state);

        let tag = self.config.tag.clone();

        loop {
            match listener.accept().await {
                Ok((socket, client_addr)) => {
                    let _ = socket.set_nodelay(true);

                    let engine = Arc::clone(&engine_state);
                    let inbound_tag = tag.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_socks5_connection(socket, client_addr, inbound_tag, engine).await {
                            warn!(error = %e, client = %client_addr, "SOCKS5 handshake failed");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Failed to accept SOCKS5 connection");
                }
            }
        }
    }
}

enum VlessTunnelStream {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl tokio::io::AsyncRead for VlessTunnelStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Self::Tls(ref mut s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for VlessTunnelStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Self::Tls(ref mut s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => std::pin::Pin::new(s).poll_flush(cx),
            Self::Tls(ref mut s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Self::Tls(ref mut s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub enum UdpTarget {
    Ip(std::net::IpAddr, u16),
    Domain(std::sync::Arc<str>, u16),
}

impl UdpTarget {
    pub fn host(&self) -> String {
        match self {
            UdpTarget::Ip(ip, _) => ip.to_string(),
            UdpTarget::Domain(domain, _) => domain.to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            UdpTarget::Ip(_, port) => *port,
            UdpTarget::Domain(_, port) => *port,
        }
    }
}

fn current_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone)]
pub struct ClientAssociation {
    pub client_addr: SocketAddr,
    pub socket: Arc<tokio::net::UdpSocket>,
    pub last_active: Arc<std::sync::atomic::AtomicU64>,
    pub rx_counter: Arc<AtomicU64>,
}

static ASSOC_MAP: OnceLock<parking_lot::Mutex<HashMap<u16, ClientAssociation>>> = OnceLock::new();
static CLIENT_SESSIONS: OnceLock<parking_lot::Mutex<HashMap<SocketAddr, u16>>> = OnceLock::new();
static NEXT_ASSOC_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);

fn get_assoc_map() -> &'static parking_lot::Mutex<HashMap<u16, ClientAssociation>> {
    ASSOC_MAP.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

fn get_client_sessions() -> &'static parking_lot::Mutex<HashMap<SocketAddr, u16>> {
    CLIENT_SESSIONS.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

static CLEANUP_ONCE: std::sync::Once = std::sync::Once::new();

fn spawn_association_cleanup_task() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let now = current_secs();
            let mut to_remove = Vec::new();
            
            {
                let assoc_guard = get_assoc_map().lock();
                for (&id, assoc) in assoc_guard.iter() {
                    let last_secs = assoc.last_active.load(Ordering::Relaxed);
                    if now.saturating_sub(last_secs) > 60 {
                        to_remove.push((id, assoc.client_addr));
                    }
                }
            }
            
            if !to_remove.is_empty() {
                let mut assoc_guard = get_assoc_map().lock();
                let mut sessions_guard = get_client_sessions().lock();
                for (id, client_addr) in to_remove {
                    assoc_guard.remove(&id);
                    sessions_guard.remove(&client_addr);
                }
            }
        }
    });
}

fn ensure_cleanup_task_spawned() {
    CLEANUP_ONCE.call_once(|| {
        spawn_association_cleanup_task();
    });
}

fn get_or_create_association(
    client_addr: SocketAddr,
    socket: Arc<tokio::net::UdpSocket>,
    rx_counter: Arc<AtomicU64>,
) -> u16 {
    ensure_cleanup_task_spawned();

    let mut sessions_guard = get_client_sessions().lock();
    let mut assoc_guard = get_assoc_map().lock();
    
    if let Some(&assoc_id) = sessions_guard.get(&client_addr) {
        if let Some(assoc) = assoc_guard.get(&assoc_id) {
            assoc.last_active.store(current_secs(), Ordering::Relaxed);
        }
        return assoc_id;
    }
    
    let assoc_id = NEXT_ASSOC_ID.fetch_add(1, Ordering::Relaxed);
    sessions_guard.insert(client_addr, assoc_id);
    
    assoc_guard.insert(assoc_id, ClientAssociation {
        client_addr,
        socket,
        last_active: Arc::new(std::sync::atomic::AtomicU64::new(current_secs())),
        rx_counter,
    });
    
    assoc_id
}

pub struct UdpUpstreamPacket {
    pub assoc_id: u16,
    pub target: UdpTarget,
    pub payload: bytes::Bytes,
}

static UDP_UPSTREAM_TX: OnceLock<tokio::sync::mpsc::Sender<UdpUpstreamPacket>> = OnceLock::new();

fn get_udp_upstream_tx(engine_state: &Arc<EngineState>) -> tokio::sync::mpsc::Sender<UdpUpstreamPacket> {
    UDP_UPSTREAM_TX.get_or_init(|| {
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        let engine_clone = Arc::clone(engine_state);
        tokio::spawn(async move {
            run_global_vless_udp_tunnel(rx, engine_clone).await;
        });
        tx
    }).clone()
}

async fn establish_raw_vless_stream(
    engine_state: &Arc<EngineState>,
) -> Result<VlessTunnelStream, Box<dyn std::error::Error + Send + Sync>> {
    let vless_config = {
        let config_guard = engine_state.config.read();
        let vless_outbound = config_guard.outbounds.iter().find(|o| o.protocol == "vless");
        vless_outbound.and_then(|o| o.settings.as_ref().and_then(|s| s.vless.clone()))
    };

    let cfg = match vless_config {
        Some(c) => c,
        None => return Err("VLESS config missing".into()),
    };

    let server_addr = format!("{}:{}", cfg.server, cfg.port);
    let dial_fut = TcpStream::connect(&server_addr);
    let server_tcp = tokio::time::timeout(std::time::Duration::from_secs(10), dial_fut).await??;
    let _ = server_tcp.set_nodelay(true);

    let server_stream = if let Some(ref tls_settings) = cfg.tls {
        let connector = crate::transport::tls::tls_helper::create_client_config(&tls_settings.server_name)?;
        let server_name = rustls::pki_types::ServerName::try_from(tls_settings.server_name.clone())?;
        let tls_stream = connector.connect(server_name, server_tcp).await?;
        VlessTunnelStream::Tls(tls_stream)
    } else {
        VlessTunnelStream::Plain(server_tcp)
    };

    Ok(server_stream)
}

fn bind_udp_socket_with_buffers(addr: SocketAddr) -> Result<tokio::net::UdpSocket, Box<dyn std::error::Error + Send + Sync>> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_recv_buffer_size(64 * 1024)?;
    socket.set_send_buffer_size(64 * 1024)?;
    socket.bind(&addr.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)?;
    Ok(tokio_socket)
}

async fn connect_to_vless(
    engine_state: &Arc<EngineState>,
    dest_addr: &str,
    dest_port: u16,
) -> Result<VlessTunnelStream, Box<dyn std::error::Error + Send + Sync>> {
    let mut server_stream = establish_raw_vless_stream(engine_state).await?;

    let vless_config = {
        let config_guard = engine_state.config.read();
        let vless_outbound = config_guard.outbounds.iter().find(|o| o.protocol == "vless");
        vless_outbound.and_then(|o| o.settings.as_ref().and_then(|s| s.vless.clone()))
    };

    let cfg = match vless_config {
        Some(c) => c,
        None => return Err("VLESS config missing".into()),
    };

    let uuid = uuid::Uuid::parse_str(&cfg.uuid)?;
    let mut header = Vec::with_capacity(30);
    header.push(0u8);
    header.extend_from_slice(uuid.as_bytes());
    header.push(0u8);
    header.push(2u8);
    header.extend_from_slice(&dest_port.to_be_bytes());

    if let Ok(ip_addr) = dest_addr.parse::<std::net::IpAddr>() {
        match ip_addr {
            std::net::IpAddr::V4(ipv4) => {
                header.push(1u8);
                header.extend_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                header.push(3u8);
                header.extend_from_slice(&ipv6.octets());
            }
        }
    } else {
        header.push(2u8);
        header.push(dest_addr.len() as u8);
        header.extend_from_slice(dest_addr.as_bytes());
    }

    server_stream.write_all(&header).await?;

    let mut response = [0u8; 2];
    server_stream.read_exact(&mut response).await?;
    if response[0] != 0 {
        return Err("Invalid response protocol version".into());
    }

    Ok(server_stream)
}

async fn run_global_vless_udp_tunnel(
    mut rx: tokio::sync::mpsc::Receiver<UdpUpstreamPacket>,
    engine_state: Arc<EngineState>,
) {
    loop {
        let tunnel = match connect_to_vless(&engine_state, "0.0.0.0", 0).await {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, "Failed to connect global VLESS UDP tunnel, retrying in 2 seconds...");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        info!("Global VLESS UDP tunnel connected and active");

        let (read_half, mut write_half) = tokio::io::split(tunnel);

        let downstream_task = async {
            let mut buf_reader = BufReader::with_capacity(65536, read_half);
            let mut header_buf = [0u8; 4];
            let mut payload_buf = [0u8; 65535];
            let mut reply_buf = vec![0u8; 65535 + 300];
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
                match atyp {
                    0x01 => {
                        offset += 4 + 2;
                    }
                    0x03 => {
                        let len = payload_buf[offset] as usize;
                        offset += 1 + len + 2;
                    }
                    0x04 => {
                        offset += 16 + 2;
                    }
                    _ => continue,
                };

                if offset > frame_len {
                    continue;
                }

                let payload = &payload_buf[offset..frame_len];

                let association = {
                    let guard = get_assoc_map().lock();
                    if let Some(assoc) = guard.get(&assoc_id) {
                        assoc.last_active.store(current_secs(), Ordering::Relaxed);
                        Some(assoc.clone())
                    } else {
                        None
                    }
                };

                if let Some(assoc) = association {
                    reply_buf[0] = 0x00;
                    reply_buf[1] = 0x00;
                    reply_buf[2] = 0x00;
                    
                    let header_len = 3 + offset;
                    reply_buf[3..header_len].copy_from_slice(&payload_buf[..offset]);
                    reply_buf[header_len..header_len + payload.len()].copy_from_slice(payload);

                    if assoc.socket.send_to(&reply_buf[..header_len + payload.len()], assoc.client_addr).await.is_ok() {
                        assoc.rx_counter.fetch_add(payload.len() as u64, Ordering::Relaxed);
                        if let Some(stats) = engine_state.get_user_stats(&None) {
                            stats.rx.fetch_add(payload.len() as u64, Ordering::Relaxed);
                        }
                    }
                }
            }
        };

        let upstream_task = async {
            let mut send_buf = bytes::BytesMut::with_capacity(65535);
            while let Some(packet) = rx.recv().await {
                send_buf.clear();
                let target_port = packet.target.port();
                
                // Write placeholder for frame length prefix (2 bytes)
                send_buf.put_u16(0);
                
                // Write association ID
                send_buf.put_u16(packet.assoc_id);
                
                // Write address type and address
                match &packet.target {
                    UdpTarget::Ip(ip, _) => {
                        match ip {
                            std::net::IpAddr::V4(ipv4) => {
                                send_buf.put_u8(1);
                                send_buf.put_slice(&ipv4.octets());
                            }
                            std::net::IpAddr::V6(ipv6) => {
                                send_buf.put_u8(4);
                                send_buf.put_slice(&ipv6.octets());
                            }
                        }
                    }
                    UdpTarget::Domain(domain, _) => {
                        send_buf.put_u8(3);
                        send_buf.put_u8(domain.len() as u8);
                        send_buf.put_slice(domain.as_bytes());
                    }
                }
                
                // Write target port
                send_buf.put_u16(target_port);

                // Compute total frame length (header + payload), excluding the length prefix itself
                let total_len = send_buf.len() - 2 + packet.payload.len();
                
                // Fill the length prefix at the beginning of the buffer
                send_buf[0..2].copy_from_slice(&(total_len as u16).to_be_bytes());
                
                // Append payload
                send_buf.put_slice(&packet.payload);

                if write_half.write_all(&send_buf).await.is_err() {
                    return false;
                }
            }
            true
        };

        tokio::select! {
            _ = downstream_task => {
                warn!("Global VLESS UDP tunnel read closed or failed. Reconnecting...");
            }
            res = upstream_task => {
                if res {
                    break;
                } else {
                    warn!("Global VLESS UDP tunnel write failed. Reconnecting...");
                }
            }
        }
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

async fn handle_socks5_connection(
    mut socket: TcpStream,
    client_addr: SocketAddr,
    inbound_tag: String,
    engine_state: Arc<EngineState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = bytes::BytesMut::with_capacity(128);

    read_exact_to_buf(&mut socket, &mut buf, 2).await?;

    let version = buf[0];
    let nmethods = buf[1] as usize;

    if version != 0x05 {
        return Err("Unsupported SOCKS version".into());
    }

    let min_needed = 2 + nmethods;
    read_exact_to_buf(&mut socket, &mut buf, min_needed).await?;

    let methods = &buf[2..min_needed];
    if !methods.contains(&0x00) {
        socket.write_all(&[0x05, 0xff]).await?;
        return Err("No acceptable auth methods".into());
    }

    socket.write_all(&[0x05, 0x00]).await?;

    buf.clear();

    read_exact_to_buf(&mut socket, &mut buf, 4).await?;

    let version = buf[0];
    let cmd = buf[1];
    let atyp = buf[3];

    if version != 0x05 {
        return Err("Invalid request version".into());
    }

    if cmd != 0x01 && cmd != 0x03 {
        socket.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err("Unsupported command".into());
    }

    let dest_addr_start = 4;
    let (dest_addr, dest_port_offset) = match atyp {
        0x01 => {
            let needed = dest_addr_start + 4;
            read_exact_to_buf(&mut socket, &mut buf, needed).await?;
            let octets: [u8; 4] = buf[dest_addr_start..needed].try_into()?;
            (std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)).to_string(), needed)
        }
        0x03 => {
            let needed = dest_addr_start + 1;
            read_exact_to_buf(&mut socket, &mut buf, needed).await?;
            let domain_len = buf[dest_addr_start] as usize;
            let needed = dest_addr_start + 1 + domain_len;
            read_exact_to_buf(&mut socket, &mut buf, needed).await?;
            let domain_slice = &buf[dest_addr_start + 1..needed];
            (std::str::from_utf8(domain_slice)?.to_string(), needed)
        }
        0x04 => {
            let needed = dest_addr_start + 16;
            read_exact_to_buf(&mut socket, &mut buf, needed).await?;
            let octets: [u8; 16] = buf[dest_addr_start..needed].try_into()?;
            (std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)).to_string(), needed)
        }
        _ => {
            socket.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err("Unsupported address type".into());
        }
    };

    let port_needed = dest_port_offset + 2;
    read_exact_to_buf(&mut socket, &mut buf, port_needed).await?;
    let dest_port = u16::from_be_bytes([buf[dest_port_offset], buf[dest_port_offset + 1]]);

    if cmd == 0x01 {
        socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        let dummy_uuid = [0u8; 16];
        dispatch_connection(crate::inbound::InboundTransportStream::Plain(socket), client_addr, dest_addr, dest_port, inbound_tag, dummy_uuid, 1, engine_state).await?;
    } else {
        let client_udp_socket = bind_udp_socket_with_buffers(SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))?;
        let local_addr = socket.local_addr()?;
        let bound_port = client_udp_socket.local_addr()?.port();
        let mut reply = vec![0x05, 0x00, 0x00];
        match local_addr.ip() {
            std::net::IpAddr::V4(ip) => {
                reply.push(0x01);
                reply.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                reply.push(0x04);
                reply.extend_from_slice(&ip.octets());
            }
        }
        reply.extend_from_slice(&bound_port.to_be_bytes());
        socket.write_all(&reply).await?;

        let outbound_tag = {
            let config_guard = engine_state.config.read();
            let vless_outbound = config_guard.outbounds.iter().find(|o| o.protocol == "vless");
            vless_outbound.map(|o| o.tag.clone())
        };

        let conn_id = uuid::Uuid::new_v4();
        let rx_counter = Arc::new(AtomicU64::new(0));
        let tx_counter = Arc::new(AtomicU64::new(0));

        let conn_info = crate::state::ConnectionInfo {
            id: conn_id,
            inbound_tag: inbound_tag.clone(),
            client_ip: client_addr.to_string(),
            dest_address: format!("{}:{}", dest_addr, dest_port),
            sni: None,
            outbound_tag: outbound_tag.unwrap_or_else(|| "vless".to_string()),
            rx: Arc::clone(&rx_counter),
            tx: Arc::clone(&tx_counter),
            start_time: std::time::Instant::now(),
        };
        engine_state.register_connection(conn_info);

        let socket_arc = Arc::new(client_udp_socket);
        let socket_rx = Arc::clone(&socket_arc);
        
        let mut recv_buf = [0u8; 65535];
        let mut tcp_buf = [0u8; 1024];

        loop {
            tokio::select! {
                res = socket.read(&mut tcp_buf) => {
                    match res {
                        Ok(0) | Err(_) => {
                            break;
                        }
                        _ => {}
                    }
                }
                res = socket_rx.recv_from(&mut recv_buf) => {
                    let (n, client_addr) = match res {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    if n < 4 {
                        continue;
                    }
                    let frag = match recv_buf.get(2) {
                        Some(&f) => f,
                        None => continue,
                    };
                    let atyp = match recv_buf.get(3) {
                        Some(&a) => a,
                        None => continue,
                    };
                    if frag != 0x00 {
                        continue;
                    }
                    let mut offset = 4;
                    let target = match atyp {
                        0x01 => {
                            if n < offset + 4 + 2 { continue; }
                            let mut ip_bytes = [0u8; 4];
                            ip_bytes.copy_from_slice(&recv_buf[offset..offset+4]);
                            offset += 4;
                            let port = u16::from_be_bytes([recv_buf[offset], recv_buf[offset+1]]);
                            offset += 2;
                            UdpTarget::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip_bytes)), port)
                        }
                        0x04 => {
                            if n < offset + 16 + 2 { continue; }
                            let mut ip_bytes = [0u8; 16];
                            ip_bytes.copy_from_slice(&recv_buf[offset..offset+16]);
                            offset += 16;
                            let port = u16::from_be_bytes([recv_buf[offset], recv_buf[offset+1]]);
                            offset += 2;
                            UdpTarget::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes)), port)
                        }
                        0x03 => {
                            if n < offset + 1 { continue; }
                            let len = recv_buf[offset] as usize;
                            offset += 1;
                            if n < offset + len + 2 { continue; }
                            let domain_bytes = &recv_buf[offset..offset+len];
                            offset += len;
                            let port = u16::from_be_bytes([recv_buf[offset], recv_buf[offset+1]]);
                            offset += 2;
                            let domain_str = match std::str::from_utf8(domain_bytes) {
                                Ok(s) => s,
                                Err(_) => continue,
                            };
                            UdpTarget::Domain(std::sync::Arc::from(domain_str), port)
                        }
                        _ => continue,
                    };

                    let payload_slice = match recv_buf.get(offset..n) {
                        Some(p) => p,
                        None => continue,
                    };
                    let payload = bytes::Bytes::copy_from_slice(payload_slice);

                    let assoc_id = get_or_create_association(client_addr, Arc::clone(&socket_arc), Arc::clone(&rx_counter));
                    let packet = UdpUpstreamPacket {
                        assoc_id,
                        target,
                        payload,
                    };

                    if let Err(e) = get_udp_upstream_tx(&engine_state).try_send(packet) {
                        warn!(
                            target = "socks5_udp",
                            client = %client_addr,
                            error = %e,
                            "SOCKS5 UDP packet dropped: upstream global tunnel queue is full"
                        );
                    } else {
                        tx_counter.fetch_add(payload_slice.len() as u64, Ordering::Relaxed);
                        if let Some(stats) = engine_state.get_user_stats(&None) {
                            stats.tx.fetch_add(payload_slice.len() as u64, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
        
        engine_state.deregister_connection(&conn_id);
    }
    Ok(())
}
