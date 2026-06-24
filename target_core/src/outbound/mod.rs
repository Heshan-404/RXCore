use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use uuid::Uuid;

use crate::config::OutboundConfig;
use crate::state::EngineState;

pub mod fragment;
pub mod freedom;
pub mod vless_client;
pub mod udp;
pub mod hysteria_outbound;

use crate::inbound::InboundTransportStream;

#[async_trait]
pub trait OutboundHandler: Send + Sync {
    async fn handle(
        &self,
        inbound_stream: InboundTransportStream,
        dest_addr: &str,
        dest_port: u16,
        rx_counter: Arc<AtomicU64>,
        tx_counter: Arc<AtomicU64>,
        engine_state: &Arc<EngineState>,
        client_email: &Option<String>,
        conn_id: &Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

pub fn get_outbound_handler(config: Option<&OutboundConfig>, is_udp: bool) -> Result<Box<dyn OutboundHandler>, Box<dyn std::error::Error + Send + Sync>> {
    match config {
        Some(c) => match c.protocol.as_str() {
            "freedom" => Ok(Box::new(freedom::FreedomOutbound::new(c.outbound_proxy.clone(), c.bind_address.clone()))),
            "fragment" => {
                let settings = c.settings.as_ref().and_then(|s| s.fragment.clone());
                Ok(Box::new(fragment::FragmentOutbound::new(settings)))
            }
            "vless" => {
                let settings = c.settings.as_ref().and_then(|s| s.vless.clone())
                    .ok_or_else(|| Box::<dyn std::error::Error + Send + Sync>::from("VLESS client outbound configuration missing"))?;
                Ok(Box::new(vless_client::VlessClientOutbound::new(settings, is_udp, c.outbound_proxy.clone(), c.bind_address.clone())))
            }
            "hysteria2" => {
                let settings = c.settings.as_ref().and_then(|s| s.hysteria2.clone())
                    .ok_or_else(|| Box::<dyn std::error::Error + Send + Sync>::from("Hysteria 2 client outbound configuration missing"))?;
                Ok(Box::new(hysteria_outbound::Hysteria2ClientOutbound::new(settings)))
            }
            "blackhole" => Ok(Box::new(BlackholeOutbound::new())),
            _ => Ok(Box::new(freedom::FreedomOutbound::new(None, None))),
        },
        None => Ok(Box::new(freedom::FreedomOutbound::new(None, None))),
    }
}

pub struct BlackholeOutbound;

impl BlackholeOutbound {
    pub fn new() -> Self {
        Self
    }
}


#[async_trait]
impl OutboundHandler for BlackholeOutbound {
    async fn handle(
        &self,
        _inbound_stream: InboundTransportStream,
        _dest_addr: &str,
        _dest_port: u16,
        _rx_counter: Arc<AtomicU64>,
        _tx_counter: Arc<AtomicU64>,
        _engine_state: &Arc<EngineState>,
        _client_email: &Option<String>,
        _conn_id: &Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Drop/discard connection
        Ok(())
    }
}
