use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use crate::config::InboundConfig;
use crate::dispatcher::dispatch_connection;
use crate::state::EngineState;

pub mod vless;
pub mod socks5;

#[async_trait]
pub trait InboundListener: Send + Sync {
    async fn start(self: Arc<Self>, engine_state: Arc<EngineState>) -> Result<(), std::io::Error>;
}

pub fn create_inbound_listener(config: InboundConfig) -> Result<Arc<dyn InboundListener>, Box<dyn std::error::Error + Send + Sync>> {
    match config.protocol.as_str() {
        "vless" => Ok(Arc::new(TcpInbound::new(config))),
        "socks" => Ok(Arc::new(socks5::Socks5Inbound::new(config))),
        _ => Err(format!("Unsupported inbound protocol: {}", config.protocol).into()),
    }
}

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub enum InboundTransportStream {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl AsyncRead for InboundTransportStream {
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

impl AsyncWrite for InboundTransportStream {
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

pub struct TcpInbound {
    pub config: InboundConfig,
}

impl TcpInbound {
    pub fn new(config: InboundConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl InboundListener for TcpInbound {
    async fn start(self: Arc<Self>, engine_state: Arc<EngineState>) -> Result<(), std::io::Error> {
        let addr = SocketAddr::new(self.config.listen, self.config.port);
        let listener = TcpListener::bind(addr).await?;
        info!(tag = %self.config.tag, address = %addr, "Inbound TCP Listener bound");

        let tag = self.config.tag.clone();
        let protocol = self.config.protocol.clone();

        // Optional server-side TLS Acceptor setup
        let tls_acceptor = if let Some(ref ss) = self.config.stream_settings {
            if ss.security == "tls" {
                let (cert, key) = if let Some(ref tls) = ss.tls_settings {
                    (tls.certificate_file.as_deref(), tls.key_file.as_deref())
                } else {
                    (None, None)
                };
                match crate::transport::tls::tls_helper::create_server_config(cert, key) {
                    Ok(acc) => Some(acc),
                    Err(e) => {
                        error!(error = %e, "Failed to initialize server TLS acceptor");
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        loop {
            match listener.accept().await {
                Ok((socket, client_addr)) => {
                    let _ = socket.set_nodelay(true);

                    let engine = Arc::clone(&engine_state);
                    let inbound_tag = tag.clone();
                    let inbound_proto = protocol.clone();
                    let acceptor = tls_acceptor.clone();

                    tokio::spawn(async move {
                        let stream = if let Some(acc) = acceptor {
                            match acc.accept(socket).await {
                                Ok(s) => InboundTransportStream::Tls(s),
                                Err(e) => {
                                    error!(error = %e, client = %client_addr, "TLS handshake negotiation failed");
                                    return;
                                }
                            }
                        } else {
                            InboundTransportStream::Plain(socket)
                        };

                        if let Err(e) = handle_inbound_stream(stream, client_addr, inbound_tag, inbound_proto, engine).await {
                            error!(error = %e, client = %client_addr, "Error handling inbound connection");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Failed to accept connection on listener");
                }
            }
        }
    }
}

async fn handle_inbound_stream(
    mut stream: InboundTransportStream,
    client_addr: SocketAddr,
    inbound_tag: String,
    protocol: String,
    engine_state: Arc<EngineState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if protocol == "vless" {
        // Run VLESS protocol parser to validate UUID and read routing info
        let (target_addr, target_port, user_uuid) = vless::parse_vless_inbound(&mut stream, &engine_state).await?;
        dispatch_connection(stream, client_addr, target_addr, target_port, inbound_tag, user_uuid, engine_state).await?;
    } else {
        return Err("Unsupported inbound protocol".into());
    }
    Ok(())
}

