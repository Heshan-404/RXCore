use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::io::Cursor;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tracing::warn;
use uuid::Uuid;

use crate::inbound::InboundTransportStream;
use crate::config::{Hysteria2ClientConfig, TlsClientSettings};
use crate::outbound::OutboundHandler;
use crate::state::EngineState;

pub struct Hysteria2ClientOutbound {
    pub config: Hysteria2ClientConfig,
    pub connection: parking_lot::Mutex<Option<quinn::Connection>>,
}

impl Hysteria2ClientOutbound {
    pub fn new(config: Hysteria2ClientConfig) -> Self {
        Self {
            config,
            connection: parking_lot::Mutex::new(None),
        }
    }

    async fn get_connection(&self) -> Result<quinn::Connection, Box<dyn std::error::Error + Send + Sync>> {
        {
            let guard = self.connection.lock();
            if let Some(ref conn) = *guard {
                if conn.close_reason().is_none() {
                    return Ok(conn.clone());
                }
            }
        }

        let conn = connect_and_auth(&self.config).await?;
        {
            let mut guard = self.connection.lock();
            if let Some(ref existing) = *guard {
                if existing.close_reason().is_none() {
                    return Ok(existing.clone());
                }
            }
            *guard = Some(conn.clone());
        }
        Ok(conn)
    }
}

fn create_quinn_client_config(
    _tls_settings: Option<&TlsClientSettings>,
) -> Result<quinn::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut root_store = rustls::RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    if !native_certs.errors.is_empty() {
        for err in &native_certs.errors {
            warn!(error = %err, "Failed to load native root cert");
        }
    }
    for cert in native_certs.certs {
        let _ = root_store.add(cert);
    }

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    client_config.alpn_protocols = vec![b"h3".to_vec(), b"hysteria2".to_vec()];

    #[derive(Debug)]
    struct SkipServerVerification;
    impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }
    
    client_config.dangerous().set_certificate_verifier(Arc::new(SkipServerVerification));

    let quinn_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_config)?;
    let mut quinn_config = quinn::ClientConfig::new(Arc::new(quinn_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65536));
    quinn_config.transport_config(Arc::new(transport));

    Ok(quinn_config)
}

async fn connect_and_auth(
    config: &Hysteria2ClientConfig,
) -> Result<quinn::Connection, Box<dyn std::error::Error + Send + Sync>> {
    let client_config = create_quinn_client_config(config.tls.as_ref())?;
    let bind_addr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    let server_addr = format!("{}:{}", config.server, config.port);
    let socket_addrs = tokio::net::lookup_host(&server_addr).await?
        .next()
        .ok_or("Failed to resolve server hostname")?;

    let server_name = config.tls.as_ref().map(|t| t.server_name.clone()).unwrap_or_else(|| "hysteria".to_string());
    
    let connecting = endpoint.connect(socket_addrs, &server_name)?;
    let quic_conn = connecting.await?;

    let quic_conn_clone = quic_conn.clone();
    let (mut h3_driver, mut h3_send) = h3::client::new(h3_quinn::Connection::new(quic_conn)).await?;
    
    tokio::spawn(async move {
        let _ = futures_util::future::poll_fn(|cx| h3_driver.poll_close(cx)).await;
    });

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/auth")
        .header("Hysteria-Auth", &config.auth)
        .header("Hysteria-CC-RX", &config.down_mbps.unwrap_or(0).to_string())
        .header("Hysteria-Padding", "a".repeat(16))
        .body(())?;

    let mut stream = h3_send.send_request(request).await?;
    let response = stream.recv_response().await?;

    if response.status().as_u16() != 233 {
        return Err(format!("Auth failed with status code {}", response.status()).into());
    }

    Ok(quic_conn_clone)
}

async fn read_tcp_response(
    recv_stream: &mut quinn::RecvStream,
    buf: &mut bytes::BytesMut,
) -> Option<crate::transport::hysteria_proto::TCPResponse> {
    let mut temp = [0u8; 1024];
    loop {
        let mut cursor = Cursor::new(buf.as_ref());
        if let Some(resp) = crate::transport::hysteria_proto::TCPResponse::parse(&mut cursor) {
            let consumed = cursor.position() as usize;
            buf.advance(consumed);
            return Some(resp);
        }
        let n = recv_stream.read(&mut temp).await.ok()??;
        if n == 0 {
            return None;
        }
        buf.put_slice(&temp[..n]);
    }
}

#[async_trait]
impl OutboundHandler for Hysteria2ClientOutbound {
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
        let quic_conn = self.get_connection().await?;

        if dest_addr == "0.0.0.0" && dest_port == 0 {
            // UDP multiplexed mode
            self.handle_multiplexed(inbound_stream, quic_conn, rx_counter, tx_counter, engine_state, client_email).await
        } else {
            // Standard TCP mode
            self.handle_standard(inbound_stream, quic_conn, dest_addr, dest_port, rx_counter, tx_counter, engine_state, client_email).await
        }
    }
}

impl Hysteria2ClientOutbound {
    async fn handle_standard(
        &self,
        inbound_stream: InboundTransportStream,
        quic_conn: quinn::Connection,
        dest_addr: &str,
        dest_port: u16,
        rx_counter: Arc<AtomicU64>,
        tx_counter: Arc<AtomicU64>,
        engine_state: &Arc<EngineState>,
        client_email: &Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let user_stats = engine_state.get_user_stats(client_email);

        let (mut send_stream, mut recv_stream) = quic_conn.open_bi().await?;

        let req = crate::transport::hysteria_proto::TCPRequest {
            address: format!("{}:{}", dest_addr, dest_port),
        };
        send_stream.write_all(&req.serialize()).await?;

        let mut resp_buf = BytesMut::with_capacity(256);
        let resp = read_tcp_response(&mut recv_stream, &mut resp_buf).await
            .ok_or("Failed to parse TCPResponse from server")?;

        if resp.status != 0 {
            return Err(format!("TCP proxy connection rejected: {:?}", resp.error_message).into());
        }

        let (mut read_half, mut write_half) = tokio::io::split(inbound_stream);
        let upstream = tokio::io::copy(&mut read_half, &mut send_stream);
        let downstream = tokio::io::copy(&mut recv_stream, &mut write_half);

        let (upstream_res, downstream_res) = tokio::join!(upstream, downstream);
        if let (Ok(tx_bytes), Ok(rx_bytes)) = (upstream_res, downstream_res) {
            rx_counter.fetch_add(rx_bytes, Ordering::Relaxed);
            tx_counter.fetch_add(tx_bytes, Ordering::Relaxed);
            if let Some(ref stats) = user_stats {
                stats.rx.fetch_add(rx_bytes, Ordering::Relaxed);
                stats.tx.fetch_add(tx_bytes, Ordering::Relaxed);
            }
        }

        Ok(())
    }

    async fn handle_multiplexed(
        &self,
        inbound_stream: InboundTransportStream,
        quic_conn: quinn::Connection,
        rx_counter: Arc<AtomicU64>,
        tx_counter: Arc<AtomicU64>,
        engine_state: &Arc<EngineState>,
        client_email: &Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let user_stats = engine_state.get_user_stats(client_email);

        let (in_reader, mut in_writer) = tokio::io::split(inbound_stream);
        let mut buf_reader = BufReader::with_capacity(65536, in_reader);

        let (downlink_tx, mut downlink_rx) = tokio::sync::mpsc::channel::<Bytes>(128);

        tokio::spawn(async move {
            while let Some(buf) = downlink_rx.recv().await {
                if in_writer.write_all(&buf).await.is_err() {
                    break;
                }
            }
        });

        // Datagram read task (receives target replies from Hysteria server)
        let quic_conn_rx = quic_conn.clone();
        let downlink_tx_clone = downlink_tx.clone();
        let rx_counter_clone = rx_counter.clone();
        let user_stats_clone = user_stats.clone();

        tokio::spawn(async move {
            loop {
                let datagram = match quic_conn_rx.read_datagram().await {
                    Ok(d) => d,
                    Err(_) => break,
                };

                let msg = match crate::transport::hysteria_proto::UDPMessage::parse(datagram) {
                    Some(m) => m,
                    None => continue,
                };

                // We must reply back to the inbound socks5 socket using the client's expected framing.
                // SOCKS5 UDP Downlink Packet format:
                // [Total Length (u16)][Assoc ID (u16)][Address Type & Port & Payload]
                // Total Length = (2 bytes of Assoc ID + ATYP + Address + Port + Payload)
                // Let's resolve the address type to build the header
                let atyp = if let Ok(ip) = msg.address.split(':').next().unwrap_or("").parse::<std::net::IpAddr>() {
                    match ip {
                        std::net::IpAddr::V4(_) => 1u8,
                        std::net::IpAddr::V6(_) => 4u8,
                    }
                } else {
                    3u8
                };

                let mut header = BytesMut::with_capacity(30);
                // Association ID (We can map msg.session_id back to Assoc ID. For simplicity, since the client session mapping uses session_id == assoc_id)
                let assoc_id = msg.session_id as u16;
                header.put_u16(assoc_id);

                let parts: Vec<&str> = msg.address.split(':').collect();
                if parts.len() != 2 {
                    continue;
                }
                let port: u16 = parts[1].parse().unwrap_or(0);

                match atyp {
                    1 => {
                        header.put_u8(1);
                        let ip: std::net::Ipv4Addr = parts[0].parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
                        header.put_slice(&ip.octets());
                    }
                    4 => {
                        header.put_u8(4);
                        let ip: std::net::Ipv6Addr = parts[0].parse().unwrap_or(std::net::Ipv6Addr::UNSPECIFIED);
                        header.put_slice(&ip.octets());
                    }
                    _ => {
                        header.put_u8(3);
                        header.put_u8(parts[0].len() as u8);
                        header.put_slice(parts[0].as_bytes());
                    }
                }
                header.put_u16(port);

                let total_len = header.len() + msg.payload.len();
                let mut reply_buf = BytesMut::with_capacity(2 + total_len);
                reply_buf.put_u16(total_len as u16);
                reply_buf.put_slice(&header);
                reply_buf.put_slice(&msg.payload);

                if downlink_tx_clone.try_send(reply_buf.freeze()).is_err() {
                    if downlink_tx_clone.is_closed() {
                        break;
                    }
                }
                rx_counter_clone.fetch_add(msg.payload.len() as u64, Ordering::Relaxed);
                if let Some(ref stats) = user_stats_clone {
                    stats.rx.fetch_add(msg.payload.len() as u64, Ordering::Relaxed);
                }
            }
        });

        // Read tasks from inbound SOCKS5 socket and forward as QUIC datagrams
        let mut header_buf = [0u8; 4];
        let mut payload_buf = [0u8; 65535];

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
                1 => {
                    if frame_len < offset + 4 + 2 { continue; }
                    let mut ip = [0u8; 4];
                    ip.copy_from_slice(&payload_buf[offset..offset+4]);
                    offset += 4;
                    let port = u16::from_be_bytes([payload_buf[offset], payload_buf[offset+1]]);
                    offset += 2;
                    format!("{}:{}", std::net::Ipv4Addr::from(ip), port)
                }
                4 => {
                    if frame_len < offset + 16 + 2 { continue; }
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(&payload_buf[offset..offset+16]);
                    offset += 16;
                    let port = u16::from_be_bytes([payload_buf[offset], payload_buf[offset+1]]);
                    offset += 2;
                    format!("{}:{}", std::net::Ipv6Addr::from(ip), port)
                }
                3 => {
                    if frame_len < offset + 1 { continue; }
                    let len = payload_buf[offset] as usize;
                    offset += 1;
                    if frame_len < offset + len + 2 { continue; }
                    let domain_str = match std::str::from_utf8(&payload_buf[offset..offset+len]) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    offset += len;
                    let port = u16::from_be_bytes([payload_buf[offset], payload_buf[offset+1]]);
                    offset += 2;
                    format!("{}:{}", domain_str, port)
                }
                _ => continue,
            };

            if offset > frame_len {
                continue;
            }

            let payload = &payload_buf[offset..frame_len];

            // Pack into UDPMessage
            let msg = crate::transport::hysteria_proto::UDPMessage {
                session_id: assoc_id as u32,
                packet_id: 0,
                fragment_id: 0,
                fragment_count: 1,
                address: target_addr,
                payload: Bytes::copy_from_slice(payload),
            };

            if quic_conn.send_datagram(msg.serialize()).is_ok() {
                tx_counter.fetch_add(payload.len() as u64, Ordering::Relaxed);
                if let Some(ref stats) = user_stats {
                    stats.tx.fetch_add(payload.len() as u64, Ordering::Relaxed);
                }
            }
        }

        Ok(())
    }
}
