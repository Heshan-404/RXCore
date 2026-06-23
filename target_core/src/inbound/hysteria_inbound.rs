use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::io::Cursor;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{error, info, warn};
use async_trait::async_trait;

use crate::config::InboundConfig;
use crate::state::EngineState;
use crate::inbound::InboundListener;

pub struct HysteriaInbound {
    pub config: InboundConfig,
}

impl HysteriaInbound {
    pub fn new(config: InboundConfig) -> Self {
        Self { config }
    }
}

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, std::io::Error> {
    let certfile = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, std::io::Error> {
    let keyfile = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(keyfile);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No private key found"))?;
    Ok(key)
}

fn create_quinn_server_config(
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> Result<quinn::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let (certs, key) = if let (Some(c_path), Some(k_path)) = (cert_path, key_path) {
        let certs = load_certs(c_path)?;
        let key = load_key(k_path)?;
        (certs, key)
    } else {
        warn!("Ephemeral self-signed certificate will be generated for Hysteria 2");
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;
        let cert_der = cert.serialize_der()?;
        let key_der = cert.serialize_private_key_der();
        (vec![rustls::pki_types::CertificateDer::from(cert_der)], rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()))
    };

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    
    server_config.alpn_protocols = vec![b"h3".to_vec(), b"hysteria2".to_vec()];

    let quinn_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)?;
    let mut quinn_config = quinn::ServerConfig::with_crypto(Arc::new(quinn_crypto));
    
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65536));
    quinn_config.transport_config(Arc::new(transport));

    Ok(quinn_config)
}

async fn read_tcp_request(
    recv_stream: &mut quinn::RecvStream,
    buf: &mut bytes::BytesMut,
) -> Option<crate::transport::hysteria_proto::TCPRequest> {
    let mut temp = [0u8; 1024];
    loop {
        let mut cursor = Cursor::new(buf.as_ref());
        if let Some(req) = crate::transport::hysteria_proto::TCPRequest::parse(&mut cursor) {
            let consumed = cursor.position() as usize;
            buf.advance(consumed);
            return Some(req);
        }
        let n = recv_stream.read(&mut temp).await.ok()??;
        if n == 0 {
            return None;
        }
        buf.put_slice(&temp[..n]);
    }
}

async fn handle_hysteria_connection(
    incoming: quinn::Incoming,
    inbound_tag: String,
    engine_state: Arc<EngineState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let quic_conn = incoming.await?;
    let quic_conn_clone = quic_conn.clone();
    
    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> = h3::server::builder().build(h3_quinn::Connection::new(quic_conn)).await?;
    let (req, mut stream) = match h3_conn.accept().await? {
        Some(resolver) => resolver.resolve_request().await?,
        None => return Err("No request received".into()),
    };

    if req.method() != http::Method::POST || req.uri().path() != "/auth" {
        return Err("Invalid HTTP/3 auth path or method".into());
    }

    let auth_header = req.headers().get("Hysteria-Auth")
        .and_then(|v| v.to_str().ok())
        .ok_or("Missing Hysteria-Auth header")?;

    let auth_uuid = uuid::Uuid::parse_str(auth_header)?;
    if !engine_state.is_user_allowed(auth_uuid.as_bytes()) {
        warn!("Unauthorized client credentials rejected");
        return Err("Authentication failed".into());
    }

    let email = {
        let config_guard = engine_state.config.read();
        config_guard.inbounds.iter()
            .find(|i| i.tag == inbound_tag)
            .and_then(|i| {
                i.settings.clients.as_ref().and_then(|clients| {
                    clients.iter().find(|c| c.id == auth_header).and_then(|c| c.email.clone())
                })
            })
    };

    info!(email = ?email, "Client authenticated successfully via Hysteria 2");

    let response = http::Response::builder()
        .status(233)
        .header("Hysteria-UDP", "true")
        .header("Hysteria-CC-RX", "auto")
        .header("Hysteria-Padding", "a".repeat(16))
        .body(())?;
    stream.send_response(response).await?;
    stream.finish().await?;

    // authenticated successfully! Now split TCP stream accepting and UDP datagram forwarding.
    let quic_conn_tcp = quic_conn_clone.clone();
    let engine_state_tcp = Arc::clone(&engine_state);
    let email_tcp = email.clone();
    
    let conn_id = uuid::Uuid::new_v4();
    let rx_counter = Arc::new(AtomicU64::new(0));
    let tx_counter = Arc::new(AtomicU64::new(0));

    let conn_info = crate::state::ConnectionInfo {
        id: conn_id,
        inbound_tag: inbound_tag.clone(),
        client_ip: quic_conn_clone.remote_address().to_string(),
        dest_address: "hysteria-multiplexed".to_string(),
        sni: None,
        outbound_tag: "freedom".to_string(),
        rx: Arc::clone(&rx_counter),
        tx: Arc::clone(&tx_counter),
        start_time: std::time::Instant::now(),
    };
    engine_state.register_connection(conn_info);

    let rx_c_tcp = Arc::clone(&rx_counter);
    let tx_c_tcp = Arc::clone(&tx_counter);

    tokio::spawn(async move {
        let mut req_buf = BytesMut::with_capacity(1024);
        while let Ok((mut send_stream, mut recv_stream)) = quic_conn_tcp.accept_bi().await {
            req_buf.clear();
            let req = match read_tcp_request(&mut recv_stream, &mut req_buf).await {
                Some(r) => r,
                None => {
                    let _ = send_stream.write_all(&[0x01, 0]).await;
                    continue;
                }
            };

            let parts: Vec<&str> = req.address.split(':').collect();
            if parts.len() != 2 {
                let _ = send_stream.write_all(&[0x01, 0]).await;
                continue;
            }
            let dest_addr = parts[0].to_string();
            let dest_port = match parts[1].parse::<u16>() {
                Ok(p) => p,
                Err(_) => {
                    let _ = send_stream.write_all(&[0x01, 0]).await;
                    continue;
                }
            };

            let target_tcp = match TcpStream::connect(format!("{}:{}", dest_addr, dest_port)).await {
                Ok(s) => s,
                Err(_) => {
                    let _ = send_stream.write_all(&[0x01, 0]).await;
                    continue;
                }
            };
            let _ = target_tcp.set_nodelay(true);

            if send_stream.write_all(&[0x00]).await.is_err() {
                continue;
            }

            let engine = Arc::clone(&engine_state_tcp);
            let rx_c = Arc::clone(&rx_c_tcp);
            let tx_c = Arc::clone(&tx_c_tcp);
            let email_record = email_tcp.clone();

            tokio::spawn(async move {
                let (mut target_read, mut target_write) = tokio::io::split(target_tcp);
                let upstream = tokio::io::copy(&mut recv_stream, &mut target_write);
                let downstream = tokio::io::copy(&mut target_read, &mut send_stream);
                
                let (upstream_res, downstream_res) = tokio::join!(upstream, downstream);
                if let (Ok(tx_bytes), Ok(rx_bytes)) = (upstream_res, downstream_res) {
                    rx_c.fetch_add(rx_bytes, Ordering::Relaxed);
                    tx_c.fetch_add(tx_bytes, Ordering::Relaxed);
                    if let Some(stats) = engine.get_user_stats(&email_record) {
                        stats.rx.fetch_add(rx_bytes, Ordering::Relaxed);
                        stats.tx.fetch_add(tx_bytes, Ordering::Relaxed);
                    }
                }
            });
        }
        engine_state_tcp.deregister_connection(&conn_id);
    });

    let quic_conn_udp = quic_conn_clone.clone();
    let engine_state_udp = Arc::clone(&engine_state);
    let email_udp = email.clone();
    let rx_c_udp = Arc::clone(&rx_counter);
    let tx_c_udp = Arc::clone(&tx_counter);

    tokio::spawn(async move {
        let mut sockets: HashMap<u32, Arc<UdpSocket>> = HashMap::new();
        loop {
            let datagram = match quic_conn_udp.read_datagram().await {
                Ok(d) => d,
                Err(_) => break,
            };

            let msg = match crate::transport::hysteria_proto::UDPMessage::parse(datagram) {
                Some(m) => m,
                None => continue,
            };

            let session_id = msg.session_id;
            let packet_id = msg.packet_id;
            let target_addr = msg.address.clone();

            let dest_socket_addr = match tokio::net::lookup_host(&target_addr).await {
                Ok(mut a) => match a.next() {
                    Some(sa) => sa,
                    None => continue,
                },
                Err(_) => continue,
            };

            let socket = match sockets.get(&session_id) {
                Some(s) => Arc::clone(s),
                None => {
                    let bind_addr = if dest_socket_addr.is_ipv4() {
                        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                    } else {
                        SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
                    };
                    let std_socket = match std::net::UdpSocket::bind(bind_addr) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let _ = std_socket.set_nonblocking(true);
                    let tokio_socket = match UdpSocket::from_std(std_socket) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let arc_socket = Arc::new(tokio_socket);

                    let socket_clone = Arc::clone(&arc_socket);
                    let quic_conn_reply = quic_conn_udp.clone();
                    let rx_c = Arc::clone(&rx_c_udp);
                    let email_record = email_udp.clone();
                    let engine = Arc::clone(&engine_state_udp);

                    tokio::spawn(async move {
                        let mut buf = [0u8; 65535];
                        loop {
                            match socket_clone.recv_from(&mut buf).await {
                                Ok((n, remote_addr)) => {
                                    let reply_msg = crate::transport::hysteria_proto::UDPMessage {
                                        session_id,
                                        packet_id,
                                        fragment_id: 0,
                                        fragment_count: 1,
                                        address: remote_addr.to_string(),
                                        payload: Bytes::copy_from_slice(&buf[..n]),
                                    };
                                    let serialized = reply_msg.serialize();
                                    if quic_conn_reply.send_datagram(serialized).is_err() {
                                        break;
                                    }
                                    rx_c.fetch_add(n as u64, Ordering::Relaxed);
                                    if let Some(stats) = engine.get_user_stats(&email_record) {
                                        stats.rx.fetch_add(n as u64, Ordering::Relaxed);
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });

                    sockets.insert(session_id, Arc::clone(&arc_socket));
                    arc_socket
                }
            };

            if socket.send_to(&msg.payload, dest_socket_addr).await.is_ok() {
                tx_c_udp.fetch_add(msg.payload.len() as u64, Ordering::Relaxed);
                if let Some(stats) = engine_state_udp.get_user_stats(&email_udp) {
                    stats.tx.fetch_add(msg.payload.len() as u64, Ordering::Relaxed);
                }
            }
        }
    });

    Ok(())
}

#[async_trait]
impl InboundListener for HysteriaInbound {
    async fn start(self: Arc<Self>, engine_state: Arc<EngineState>) -> Result<(), std::io::Error> {
        let (cert, key) = if let Some(ref ss) = self.config.stream_settings {
            if let Some(ref tls) = ss.tls_settings {
                (tls.certificate_file.as_deref(), tls.key_file.as_deref())
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let quinn_config = match create_quinn_server_config(cert, key) {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "Failed to initialize server QUIC config");
                return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
            }
        };

        let addr = SocketAddr::new(self.config.listen, self.config.port);
        let endpoint = quinn::Endpoint::server(quinn_config, addr)?;
        info!(tag = %self.config.tag, address = %addr, "Hysteria 2 Inbound Listener bound");

        while let Some(incoming) = endpoint.accept().await {
            let engine = Arc::clone(&engine_state);
            let inbound_tag = self.config.tag.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_hysteria_connection(incoming, inbound_tag, engine).await {
                    warn!(error = %e, "Hysteria connection handling error");
                }
            });
        }

        Ok(())
    }
}
