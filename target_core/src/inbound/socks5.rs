use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::config::InboundConfig;
use crate::dispatcher::dispatch_connection;
use crate::state::EngineState;
use crate::inbound::InboundListener;
use async_trait::async_trait;

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



async fn connect_to_vless(
    engine_state: &Arc<EngineState>,
    dest_addr: &str,
    dest_port: u16,
) -> Result<VlessTunnelStream, Box<dyn std::error::Error + Send + Sync>> {
    let (vless_config, _outbound_tag) = {
        let config_guard = engine_state.config.lock().unwrap();
        let vless_outbound = config_guard.outbounds.iter().find(|o| o.protocol == "vless");
        if let Some(outbound) = vless_outbound {
            if let Some(ref settings) = outbound.settings {
                if let Some(ref vless_settings) = settings.vless {
                    (Some(vless_settings.clone()), Some(outbound.tag.clone()))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        }
    };

    let cfg = match vless_config {
        Some(c) => c,
        None => return Err("VLESS config missing".into()),
    };

    let server_addr = format!("{}:{}", cfg.server, cfg.port);
    let dial_fut = TcpStream::connect(&server_addr);
    let server_tcp = tokio::time::timeout(std::time::Duration::from_secs(10), dial_fut).await??;
    let _ = server_tcp.set_nodelay(true);

    let mut server_stream = if let Some(ref tls_settings) = cfg.tls {
        let connector = crate::transport::tls::tls_helper::create_client_config(&tls_settings.server_name)?;
        let server_name = rustls::pki_types::ServerName::try_from(tls_settings.server_name.clone())?;
        let tls_stream = connector.connect(server_name, server_tcp).await?;
        VlessTunnelStream::Tls(tls_stream)
    } else {
        VlessTunnelStream::Plain(server_tcp)
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

async fn run_vless_udp_bridge(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    client_udp_socket: Arc<tokio::net::UdpSocket>,
    client_addr: SocketAddr,
    dest_addr: String,
    dest_port: u16,
    rx_counter: Arc<AtomicU64>,
    tx_counter: Arc<AtomicU64>,
    engine_state: Arc<EngineState>,
    sessions: Arc<std::sync::Mutex<HashMap<(SocketAddr, String, u16), (tokio::sync::mpsc::UnboundedSender<Vec<u8>>, tokio::task::JoinHandle<()>)>>>,
    session_key: (SocketAddr, String, u16),
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tunnel = match connect_to_vless(&engine_state, &dest_addr, dest_port).await {
        Ok(t) => t,
        Err(e) => {
            if let Ok(mut guard) = sessions.lock() {
                guard.remove(&session_key);
            }
            return Err(e);
        }
    };
    let (mut read_half, mut write_half) = tokio::io::split(tunnel);

    let local_tx = AtomicU64::new(0);
    let local_rx = AtomicU64::new(0);

    {
        let local_tx_ref = &local_tx;
        let local_rx_ref = &local_rx;

        let upload_task = async move {
            let mut len_bytes = [0u8; 2];
            while let Some(payload) = rx.recv().await {
                let len = payload.len();
                if len == 0 || len > 65535 {
                    continue;
                }
                len_bytes.copy_from_slice(&(len as u16).to_be_bytes());
                if write_half.write_all(&len_bytes).await.is_err() {
                    break;
                }
                if write_half.write_all(&payload).await.is_err() {
                    break;
                }
                local_tx_ref.fetch_add(len as u64, Ordering::Relaxed);
            }
        };

        let download_task = async move {
            let mut buf = [0u8; 300 + 65535];
            
            // Pre-calculate SOCKS5 UDP header since dest_addr and dest_port are constant
            let socks5_atyp = if let Ok(ip) = dest_addr.parse::<std::net::IpAddr>() {
                match ip {
                    std::net::IpAddr::V4(_) => 0x01,
                    std::net::IpAddr::V6(_) => 0x04,
                }
            } else {
                0x03
            };

            let mut temp_header = [0u8; 262];
            temp_header[0] = 0x00;
            temp_header[1] = 0x00;
            temp_header[2] = 0x00; // FRAG
            temp_header[3] = socks5_atyp;

            let mut offset = 4;
            match socks5_atyp {
                0x01 => {
                    if let Ok(std::net::IpAddr::V4(ipv4)) = dest_addr.parse::<std::net::IpAddr>() {
                        temp_header[offset..offset+4].copy_from_slice(&ipv4.octets());
                        offset += 4;
                    }
                }
                0x03 => {
                    let bytes = dest_addr.as_bytes();
                    temp_header[offset] = bytes.len() as u8;
                    offset += 1;
                    temp_header[offset..offset+bytes.len()].copy_from_slice(bytes);
                    offset += bytes.len();
                }
                0x04 => {
                    if let Ok(std::net::IpAddr::V6(ipv6)) = dest_addr.parse::<std::net::IpAddr>() {
                        temp_header[offset..offset+16].copy_from_slice(&ipv6.octets());
                        offset += 16;
                    }
                }
                _ => {}
            }
            temp_header[offset..offset+2].copy_from_slice(&dest_port.to_be_bytes());
            offset += 2;

            let header_start = 300 - offset;
            buf[header_start..300].copy_from_slice(&temp_header[..offset]);

            let mut len_bytes = [0u8; 2];
            loop {
                if read_half.read_exact(&mut len_bytes).await.is_err() {
                    break;
                }
                let len = u16::from_be_bytes(len_bytes) as usize;
                if len == 0 || len > 65535 {
                    break;
                }
                if read_half.read_exact(&mut buf[300..300 + len]).await.is_err() {
                    break;
                }
                
                if let Err(e) = client_udp_socket.send_to(&buf[header_start..300 + len], client_addr).await {
                    warn!(error = %e, "Failed to send SOCKS5 UDP response to client");
                    continue;
                }
                local_rx_ref.fetch_add(len as u64, Ordering::Relaxed);
            }
        };

        tokio::select! {
            _ = upload_task => {}
            _ = download_task => {}
        }
    }

    let final_tx = local_tx.load(Ordering::Relaxed);
    let final_rx = local_rx.load(Ordering::Relaxed);

    tx_counter.fetch_add(final_tx, Ordering::Relaxed);
    rx_counter.fetch_add(final_rx, Ordering::Relaxed);

    let target_email: Option<String> = None;
    if let Some(stats) = engine_state.get_user_stats(&target_email) {
        stats.tx.fetch_add(final_tx, Ordering::Relaxed);
        stats.rx.fetch_add(final_rx, Ordering::Relaxed);
    }

    if let Ok(mut guard) = sessions.lock() {
        guard.remove(&session_key);
    }

    Ok(())
}

async fn handle_socks5_connection(
    mut socket: TcpStream,
    client_addr: SocketAddr,
    inbound_tag: String,
    engine_state: Arc<EngineState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut header = [0u8; 2];
    socket.read_exact(&mut header).await?;

    let version = header[0];
    let nmethods = header[1] as usize;

    if version != 0x05 {
        return Err("Unsupported SOCKS version".into());
    }

    let mut methods = vec![0u8; nmethods];
    socket.read_exact(&mut methods).await?;

    if !methods.contains(&0x00) {
        socket.write_all(&[0x05, 0xff]).await?;
        return Err("No acceptable auth methods".into());
    }

    socket.write_all(&[0x05, 0x00]).await?;

    let mut request_header = [0u8; 4];
    socket.read_exact(&mut request_header).await?;

    let version = request_header[0];
    let cmd = request_header[1];
    let atyp = request_header[3];

    if version != 0x05 {
        return Err("Invalid request version".into());
    }

    if cmd != 0x01 && cmd != 0x03 {
        socket.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err("Unsupported command".into());
    }

    let dest_addr = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            socket.read_exact(&mut ip).await?;
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)).to_string()
        }
        0x03 => {
            let mut domain_len_buf = [0u8; 1];
            socket.read_exact(&mut domain_len_buf).await?;
            let domain_len = domain_len_buf[0] as usize;
            let mut domain = vec![0u8; domain_len];
            socket.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        0x04 => {
            let mut ip = [0u8; 16];
            socket.read_exact(&mut ip).await?;
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)).to_string()
        }
        _ => {
            socket.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err("Unsupported address type".into());
        }
    };

    let mut port_buf = [0u8; 2];
    socket.read_exact(&mut port_buf).await?;
    let dest_port = u16::from_be_bytes(port_buf);

    if cmd == 0x01 {
        socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        let dummy_uuid = [0u8; 16];
        dispatch_connection(crate::inbound::InboundTransportStream::Plain(socket), client_addr, dest_addr, dest_port, inbound_tag, dummy_uuid, 1, engine_state).await?;
    } else {
        let client_udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
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
            let config_guard = engine_state.config.lock().unwrap();
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
        
        let sessions: Arc<std::sync::Mutex<HashMap<(SocketAddr, String, u16), (tokio::sync::mpsc::UnboundedSender<Vec<u8>>, tokio::task::JoinHandle<()>)>>> = Arc::new(std::sync::Mutex::new(HashMap::new()));

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
                        Err(_) => break,
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
                    let (target_addr, _addr_len) = match atyp {
                        0x01 => {
                            if n < 10 { continue; }
                            let ip_slice = match recv_buf.get(offset..offset+4) {
                                Some(s) => s,
                                None => continue,
                            };
                            let mut ip = [0u8; 4];
                            ip.copy_from_slice(ip_slice);
                            offset += 4;
                            (std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)).to_string(), 4)
                        }
                        0x03 => {
                            if n < offset + 1 { continue; }
                            let len = match recv_buf.get(offset) {
                                Some(&l) => l as usize,
                                None => continue,
                            };
                            offset += 1;
                            if n < offset + len + 2 { continue; }
                            let domain_slice = match recv_buf.get(offset..offset+len) {
                                Some(s) => s,
                                None => continue,
                            };
                            let mut domain = vec![0u8; len];
                            domain.copy_from_slice(domain_slice);
                            offset += len;
                            let dest_addr = match String::from_utf8(domain) {
                                Ok(d) => d,
                                Err(_) => continue,
                            };
                            (dest_addr, len as u8)
                        }
                        0x04 => {
                            if n < 22 { continue; }
                            let ip_slice = match recv_buf.get(offset..offset+16) {
                                Some(s) => s,
                                None => continue,
                            };
                            let mut ip = [0u8; 16];
                            ip.copy_from_slice(ip_slice);
                            offset += 16;
                            (std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)).to_string(), 16)
                        }
                        _ => continue,
                    };

                    if n < offset + 2 { continue; }
                    let port_slice = match recv_buf.get(offset..offset+2) {
                        Some(s) => s,
                        None => continue,
                    };
                    let port = u16::from_be_bytes([port_slice[0], port_slice[1]]);
                    offset += 2;

                    let payload = match recv_buf.get(offset..n) {
                        Some(p) => p,
                        None => continue,
                    };

                    let session_key = (client_addr, target_addr.clone(), port);
                    let mut spawned_new = false;
                    
                    {
                        let guard = sessions.lock().unwrap();
                        if let Some((tx, _)) = guard.get(&session_key) {
                            if tx.send(payload.to_vec()).is_ok() {
                                spawned_new = true;
                            }
                        }
                    }

                    if !spawned_new {
                        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                        
                        let socket_clone = Arc::clone(&socket_rx);
                        let engine_clone = Arc::clone(&engine_state);
                        let dest_addr_clone = target_addr.clone();
                        let dest_port = port;
                        let rx_counter_clone = Arc::clone(&rx_counter);
                        let tx_counter_clone = Arc::clone(&tx_counter);
                        let sessions_clone = Arc::clone(&sessions);
                        let session_key_clone = session_key.clone();

                        let handle = tokio::spawn(async move {
                            let _ = run_vless_udp_bridge(
                                rx,
                                socket_clone,
                                client_addr,
                                dest_addr_clone,
                                dest_port,
                                rx_counter_clone,
                                tx_counter_clone,
                                engine_clone,
                                sessions_clone,
                                session_key_clone,
                            ).await;
                        });
                        let _ = tx.send(payload.to_vec());
                        let mut guard = sessions.lock().unwrap();
                        guard.insert(session_key, (tx, handle));
                    }
                }
            }
        }
        
        let mut sessions_guard = sessions.lock().unwrap();
        for (_, (_, handle)) in sessions_guard.drain() {
            handle.abort();
        }
        engine_state.deregister_connection(&conn_id);
    }
    Ok(())
}
