use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::net::TcpStream;
use tokio::time::timeout;
use uuid::Uuid;

use crate::inbound::InboundTransportStream;
use crate::outbound::OutboundHandler;
use crate::state::EngineState;

pub struct FreedomOutbound;

impl FreedomOutbound {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl OutboundHandler for FreedomOutbound {
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
        // Resolve host and establish connection
        let resolve_addr = format!("{}:{}", dest_addr, dest_port);
        let dial_fut = TcpStream::connect(&resolve_addr);
        let outbound_stream = match timeout(std::time::Duration::from_secs(10), dial_fut).await {
            Ok(conn_res) => conn_res?,
            Err(_) => return Err("Dial destination timed out".into()),
        };

        let _ = outbound_stream.set_nodelay(true);

        let user_stats = engine_state.get_user_stats(client_email);
        let mut inbound_mut = inbound_stream;
        let mut outbound_mut = outbound_stream;
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
