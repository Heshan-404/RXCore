use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use uuid::Uuid;

use crate::inbound::InboundTransportStream;
use crate::outbound::OutboundHandler;
use crate::state::EngineState;

pub struct UdpOutbound;

impl UdpOutbound {
    pub fn new() -> Self {
        Self
    }
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
        let user_stats = engine_state.get_user_stats(client_email);
        
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // Resolve target address and connect the UDP socket for maximum throughput
        let target_addrs = tokio::net::lookup_host(format!("{}:{}", dest_addr, dest_port)).await?;
        let target_addr = target_addrs.into_iter().next().ok_or("Failed to resolve target address")?;
        socket.connect(target_addr).await?;

        let (mut in_reader, mut in_writer) = tokio::io::split(inbound_stream);

        let upload_tx = tx_counter.clone();
        let download_rx = rx_counter.clone();
        let upload_user = user_stats.clone();
        let download_user = user_stats.clone();
        
        let socket_arc = Arc::new(socket);
        let socket_tx = Arc::clone(&socket_arc);
        let socket_rx = Arc::clone(&socket_arc);

        let upload_task = async move {
            let mut buf = [0u8; 65535];
            let mut total_tx = 0u64;
            let mut len_bytes = [0u8; 2];
            loop {
                if in_reader.read_exact(&mut len_bytes).await.is_err() {
                    break;
                }
                let len = u16::from_be_bytes(len_bytes) as usize;
                if len == 0 || len > buf.len() {
                    break;
                }
                if in_reader.read_exact(&mut buf[..len]).await.is_err() {
                    break;
                }
                if socket_tx.send(&buf[..len]).await.is_err() {
                    break;
                }
                total_tx += len as u64;
            }
            upload_tx.fetch_add(total_tx, Ordering::Relaxed);
            if let Some(ref stats) = upload_user {
                stats.tx.fetch_add(total_tx, Ordering::Relaxed);
            }
        };

        let download_task = async move {
            let mut buf = [0u8; 2 + 65535];
            let mut total_rx = 0u64;
            loop {
                match socket_rx.recv(&mut buf[2..]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let len_bytes = (n as u16).to_be_bytes();
                        buf[0..2].copy_from_slice(&len_bytes);
                        if in_writer.write_all(&buf[..2 + n]).await.is_err() {
                            break;
                        }
                        total_rx += n as u64;
                    }
                }
            }
            download_rx.fetch_add(total_rx, Ordering::Relaxed);
            if let Some(ref stats) = download_user {
                stats.rx.fetch_add(total_rx, Ordering::Relaxed);
            }
        };

        tokio::select! {
            _ = upload_task => {}
            _ = download_task => {}
        }
        Ok(())
    }
}
