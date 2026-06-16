use std::net::SocketAddr;
use std::sync::Arc;
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
                    // TCP Optimization: Disable Nagle's algorithm for instant packet flushes
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

async fn handle_socks5_connection(
    mut socket: TcpStream,
    client_addr: SocketAddr,
    inbound_tag: String,
    engine_state: Arc<EngineState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Negotiation Phase
    let mut header = [0u8; 2];
    socket.read_exact(&mut header).await?;

    let version = header[0];
    let nmethods = header[1] as usize;

    if version != 0x05 {
        return Err("Unsupported SOCKS version".into());
    }

    let mut methods = vec![0u8; nmethods];
    socket.read_exact(&mut methods).await?;

    // Check if No Auth Method (0x00) is supported
    if !methods.contains(&0x00) {
        socket.write_all(&[0x05, 0xff]).await?; // No acceptable methods
        return Err("No acceptable auth methods supported by client".into());
    }

    // Acknowledge NO AUTH
    socket.write_all(&[0x05, 0x00]).await?;

    // 2. Request Phase
    let mut request_header = [0u8; 4];
    socket.read_exact(&mut request_header).await?;

    let version = request_header[0];
    let cmd = request_header[1]; // 0x01 = CONNECT
    let atyp = request_header[3]; // 0x01 = IPv4, 0x03 = Domain, 0x04 = IPv6

    if version != 0x05 {
        return Err("Invalid SOCKS request version".into());
    }

    if cmd != 0x01 {
        // Command not supported status 0x07
        socket.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err("Unsupported SOCKS command".into());
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
            // Address type not supported 0x08
            socket.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err("Unsupported address type".into());
        }
    };

    let mut port_buf = [0u8; 2];
    socket.read_exact(&mut port_buf).await?;
    let dest_port = u16::from_be_bytes(port_buf);

    // Respond success
    // SOCKS5 success reply format: Version (0x05), Success (0x00), Reserved (0x00), ATYP (0x01 IPv4), BND.ADDR (4 bytes 0), BND.PORT (2 bytes 0)
    socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    // Hand over the SOCKS5 TcpStream connection and target destination to the dispatcher
    // Client-side VLESS outbounds will wrap this in VLESS protocol
    // For local client SOCKS5 connection, the user UUID can be mock / dummy or retrieved from client configuration
    let dummy_uuid = [0u8; 16]; 
    
    dispatch_connection(crate::inbound::InboundTransportStream::Plain(socket), client_addr, dest_addr, dest_port, inbound_tag, dummy_uuid, engine_state).await?;
    
    Ok(())
}
