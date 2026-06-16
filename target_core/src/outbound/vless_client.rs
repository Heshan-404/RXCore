use async_trait::async_trait;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use rustls::pki_types::ServerName;
use uuid::Uuid;

use crate::inbound::InboundTransportStream;
use crate::config::VlessClientConfig;
use crate::outbound::OutboundHandler;
use crate::state::EngineState;
use crate::transport::tls::tls_helper::create_client_config;

pub struct VlessClientOutbound {
    pub config: VlessClientConfig,
}

impl VlessClientOutbound {
    pub fn new(config: VlessClientConfig) -> Self {
        Self { config }
    }
}

enum ClientTransportStream {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl AsyncRead for ClientTransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(ref mut s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ClientTransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(ref mut s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => Pin::new(s).poll_flush(cx),
            Self::Tls(ref mut s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(ref mut s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[async_trait]
impl OutboundHandler for VlessClientOutbound {
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
        // 1. Establish low-latency TCP connection to the VLESS server
        let server_addr = format!("{}:{}", self.config.server, self.config.port);
        let dial_fut = TcpStream::connect(&server_addr);
        let server_tcp = match timeout(std::time::Duration::from_secs(10), dial_fut).await {
            Ok(conn_res) => conn_res?,
            Err(_) => return Err("Dial VLESS server timed out".into()),
        };

        // TCP Optimization: Disable Nagle's algorithm for minimum jitter
        server_tcp.set_nodelay(true)?;

        // 2. Perform TLS Handshake if TLS is enabled
        let mut server_stream = if let Some(ref tls_settings) = self.config.tls {
            let connector = create_client_config(&tls_settings.server_name)?;
            let server_name = ServerName::try_from(tls_settings.server_name.clone())?;
            let tls_stream = connector.connect(server_name, server_tcp).await?;
            ClientTransportStream::Tls(tls_stream)
        } else {
            ClientTransportStream::Plain(server_tcp)
        };

        // 3. Encapsulate VLESS v0 request header
        // Request format:
        // 1 byte: Version (0)
        // 16 bytes: User UUID
        // 1 byte: Addons length (0)
        // 1 byte: Command (1 = TCP)
        // 2 bytes: Port (Big Endian)
        // 1 byte: Address Type (1 = IPv4, 2 = Domain, 3 = IPv6)
        // N bytes: Address
        let uuid = Uuid::parse_str(&self.config.uuid)?;
        let mut header = Vec::with_capacity(30);
        header.push(0u8); // Version
        header.extend_from_slice(uuid.as_bytes()); // UUID
        header.push(0u8); // Addons len
        header.push(1u8); // Command TCP CONNECT
        header.extend_from_slice(&dest_port.to_be_bytes()); // Port

        if let Ok(ip_addr) = dest_addr.parse::<std::net::IpAddr>() {
            match ip_addr {
                std::net::IpAddr::V4(ipv4) => {
                    header.push(1u8); // ATYP IPv4
                    header.extend_from_slice(&ipv4.octets());
                }
                std::net::IpAddr::V6(ipv6) => {
                    header.push(3u8); // ATYP IPv6
                    header.extend_from_slice(&ipv6.octets());
                }
            }
        } else {
            header.push(2u8); // ATYP Domain
            header.push(dest_addr.len() as u8); // Domain length
            header.extend_from_slice(dest_addr.as_bytes()); // Domain name bytes
        }

        server_stream.write_all(&header).await?;

        // 4. Read VLESS connection response header (version 0, 0 addons)
        let mut response = [0u8; 2];
        server_stream.read_exact(&mut response).await?;
        if response[0] != 0 {
            return Err("Invalid response protocol version from server".into());
        }

        let user_stats = engine_state.get_user_stats(client_email);
        let mut inbound_mut = inbound_stream;
        let mut outbound_mut = server_stream;
        if let Ok((tx_bytes, rx_bytes)) = tokio::io::copy_bidirectional(&mut inbound_mut, &mut outbound_mut).await {
            rx_counter.fetch_add(rx_bytes, std::sync::atomic::Ordering::Relaxed);
            tx_counter.fetch_add(tx_bytes, std::sync::atomic::Ordering::Relaxed);
            if let Some(ref stats) = user_stats {
                stats.rx.fetch_add(rx_bytes, std::sync::atomic::Ordering::Relaxed);
                stats.tx.fetch_add(tx_bytes, std::sync::atomic::Ordering::Relaxed);
            }
        }
        Ok(())
    }
}
