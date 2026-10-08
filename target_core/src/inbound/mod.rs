use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use crate::config::InboundConfig;
use crate::dispatcher::dispatch_connection;
use crate::state::EngineState;

pub mod socks5;
pub mod vless;

#[async_trait]
pub trait InboundListener: Send + Sync {
    async fn start(self: Arc<Self>, engine_state: Arc<EngineState>) -> Result<(), std::io::Error>;
}

pub fn create_inbound_listener(
    config: InboundConfig,
) -> Result<Arc<dyn InboundListener>, Box<dyn std::error::Error + Send + Sync>> {
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
    Reality(tokio_rustls::server::TlsStream<crate::transport::reality::PrefixedStream<TcpStream>>),
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
            Self::Reality(ref mut s) => Pin::new(s).poll_read(cx, buf),
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
            Self::Reality(ref mut s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => Pin::new(s).poll_flush(cx),
            Self::Tls(ref mut s) => Pin::new(s).poll_flush(cx),
            Self::Reality(ref mut s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(ref mut s) => Pin::new(s).poll_shutdown(cx),
            Self::Reality(ref mut s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub type RealityTlsStream = tokio_rustls::server::TlsStream<
    crate::transport::reality::PrefixedStream<tokio::net::TcpStream>,
>;
pub type RealityAcceptError = Box<dyn std::error::Error + Send + Sync>;

pub async fn accept_reality_bounded(
    engine: Arc<EngineState>,
    server: Arc<crate::transport::reality::RealityServerRustls>,
    socket: TcpStream,
    client_addr: SocketAddr,
) -> Result<RealityTlsStream, RealityAcceptError> {
    let mut ip = client_addr.ip();
    if let std::net::IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4() {
            ip = std::net::IpAddr::V4(v4);
        }
    }

    let global_permit = match engine.handshake_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return Err(Box::from(
                "Rejecting connection: Global handshake semaphore limit exceeded",
            ));
        }
    };

    {
        let mut map = engine.active_handshakes_per_ip.lock();
        let current_cnt = map.get(&ip).cloned().unwrap_or(0);
        if current_cnt >= 2 {
            return Err(Box::from(
                "Rejecting connection: IP active handshake limit exceeded",
            ));
        }
        if map.len() >= 1000 && current_cnt == 0 {
            return Err(Box::from("Rejecting connection: IP tracking map is full"));
        }
        map.insert(ip, current_cnt + 1);
    }

    struct HandshakeGuard {
        ip: std::net::IpAddr,
        map: Arc<parking_lot::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
        _permit: tokio::sync::OwnedSemaphorePermit,
    }
    impl Drop for HandshakeGuard {
        fn drop(&mut self) {
            let mut map = self.map.lock();
            if let Some(cnt) = map.get_mut(&self.ip) {
                if *cnt > 1 {
                    *cnt -= 1;
                } else {
                    map.remove(&self.ip);
                }
            }
        }
    }

    let _guard = HandshakeGuard {
        ip,
        map: Arc::clone(&engine.active_handshakes_per_ip),
        _permit: global_permit,
    };

    match tokio::time::timeout(std::time::Duration::from_secs(3), server.accept(socket)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Box::from("Reality handshake timed out")),
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

        // Resolve or register the Reality runtime swap pointer
        let runtime_opt = {
            let runtimes_guard = engine_state.reality_runtimes.load();
            runtimes_guard
                .values()
                .find(|r| r.profile.inbound_tag == self.config.tag)
                .cloned()
        };

        let runtime_swap = Arc::new(arc_swap::ArcSwapOption::new(runtime_opt));
        {
            let mut listeners = engine_state.active_listeners.write();
            let (tx, _) = tokio::sync::oneshot::channel();
            listeners.insert(self.config.port, (tx, Arc::clone(&runtime_swap)));
        }

        loop {
            match listener.accept().await {
                Ok((socket, client_addr)) => {
                    if let Err(e) = socket.set_nodelay(true) {
                        tracing::debug!(error = %e, "Failed to enable TCP_NODELAY");
                    }

                    #[cfg(target_os = "linux")]
                    {
                        use std::os::fd::AsRawFd;
                        let raw_fd = socket.as_raw_fd();
                        let optval: libc::c_int = 1380;
                        unsafe {
                            libc::setsockopt(
                                raw_fd,
                                libc::IPPROTO_TCP,
                                libc::TCP_MAXSEG,
                                &optval as *const _ as *const libc::c_void,
                                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                            );
                        }
                    }

                    let engine = Arc::clone(&engine_state);
                    let inbound_tag = tag.clone();
                    let inbound_proto = protocol.clone();
                    let acceptor = tls_acceptor.clone();
                    let runtime_guard = runtime_swap.load();
                    let r_server = runtime_guard.as_ref().map(|r| Arc::clone(&r.server));

                    tokio::spawn(async move {
                        info!(tag = %inbound_tag, client = %client_addr, "New TCP connection accepted");
                        let stream = if let Some(rs) = r_server {
                            match accept_reality_bounded(
                                Arc::clone(&engine),
                                rs,
                                socket,
                                client_addr,
                            )
                            .await
                            {
                                Ok(s) => {
                                    tracing::debug!(tag = %inbound_tag, client = %client_addr, "Reality handshake completed successfully");
                                    InboundTransportStream::Reality(s)
                                }
                                Err(e) => {
                                    tracing::debug!(tag = %inbound_tag, client = %client_addr, error = %e, "Reality accept failed or rejected");
                                    return;
                                }
                            }
                        } else if let Some(acc) = acceptor {
                            match acc.accept(socket).await {
                                Ok(s) => InboundTransportStream::Tls(s),
                                Err(e) => {
                                    tracing::debug!(error = %e, client = %client_addr, "TLS handshake negotiation failed");
                                    return;
                                }
                            }
                        } else {
                            InboundTransportStream::Plain(socket)
                        };

                        if let Err(e) = handle_inbound_stream(
                            stream,
                            client_addr,
                            inbound_tag,
                            inbound_proto,
                            engine,
                        )
                        .await
                        {
                            error!(error = %e, client = %client_addr, "Error handling inbound connection");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Failed to accept connection on listener");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}

pub async fn handle_inbound_stream(
    mut stream: InboundTransportStream,
    client_addr: SocketAddr,
    inbound_tag: String,
    protocol: String,
    engine_state: Arc<EngineState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if protocol == "vless" {
        let (target_addr, target_port, user_uuid, cmd) =
            vless::parse_vless_inbound(&mut stream, &engine_state).await?;
        dispatch_connection(
            stream,
            client_addr,
            target_addr,
            target_port,
            inbound_tag,
            user_uuid,
            cmd,
            engine_state,
        )
        .await?;
    } else {
        return Err("Unsupported inbound protocol".into());
    }
    Ok(())
}
