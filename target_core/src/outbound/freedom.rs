use crate::transport::dial_tcp;
use async_trait::async_trait;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use uuid::Uuid;

use crate::inbound::InboundTransportStream;
use crate::outbound::OutboundHandler;
use crate::state::EngineState;

pub struct FreedomOutbound {
    outbound_proxy: Option<String>,
    bind_address: Option<String>,
}

impl FreedomOutbound {
    pub fn new(outbound_proxy: Option<String>, bind_address: Option<String>) -> Self {
        Self {
            outbound_proxy,
            bind_address,
        }
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
        _client_email: &Option<String>,
        _conn_id: &Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(proxy = ?self.outbound_proxy, dest = %dest_addr, port = dest_port, "Freedom dialing TCP");

        let outbound_stream = dial_tcp(
            dest_addr,
            dest_port,
            &self.bind_address,
            &self.outbound_proxy,
        )
        .await?;

        let _ = outbound_stream.set_nodelay(true);

        let user_uuid = {
            let conns = engine_state.active_connections.read();
            conns.get(_conn_id).and_then(|c| c.user_uuid)
        };
        let speed_limit = user_uuid.and_then(|uuid| engine_state.get_user_speed_limit(&uuid));

        let (inbound_read, inbound_write) = tokio::io::split(inbound_stream);
        let (outbound_read, outbound_write) = tokio::io::split(outbound_stream);

        let copy_res = crate::transport::copy_bidirectional_with_rate_limit(
            inbound_read,
            inbound_write,
            outbound_read,
            outbound_write,
            speed_limit,
            rx_counter,
            tx_counter,
            user_uuid,
            Arc::clone(engine_state),
        )
        .await;

        if let Err(e) = copy_res {
            tracing::debug!(error = %e, "Outbound TCP copy finished");
        }
        Ok(())
    }
}
