use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;
use crate::inbound::InboundTransportStream;
use crate::dispatcher::sniffer::sniff_sni;
use crate::outbound::get_outbound_handler;
use crate::router::Router;
use crate::state::{ConnectionInfo, EngineState};

pub mod sniffer;

pub async fn dispatch_connection(
    inbound_stream: InboundTransportStream,
    client_addr: SocketAddr,
    dest_addr: String,
    dest_port: u16,
    inbound_tag: String,
    user_uuid: [u8; 16],
    cmd: u8,
    engine_state: Arc<EngineState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match inbound_stream {
        InboundTransportStream::Plain(ref socket) => {
            let _ = socket.set_nodelay(true);
        }
        InboundTransportStream::Tls(ref stream) => {
            let _ = stream.get_ref().0.set_nodelay(true);
        }
    }
    let sni = sniff_sni(&inbound_stream).await;
    if let Some(ref parsed_sni) = sni {
        info!(sni = %parsed_sni, "Parsed SNI successfully from connection");
    }

    let (client_email, outbound_tag, outbound_config) = {
        let config_guard = engine_state.config.read();
        let email = config_guard
            .inbounds
            .iter()
            .find(|i| i.tag == inbound_tag)
            .and_then(|i| {
                i.settings.clients.as_ref().and_then(|clients| {
                    clients.iter().find(|c| {
                        if let Ok(parsed_uuid) = Uuid::parse_str(&c.id) {
                            *parsed_uuid.as_bytes() == user_uuid
                        } else {
                            false
                        }
                    })
                })
            })
            .and_then(|c| c.email.clone());

        let router = Router::new();
        let tag = router.route(&inbound_tag, &dest_addr, dest_port, &sni, &config_guard);
        let config = config_guard.outbounds.iter().find(|o| o.tag == tag).cloned();
        (email, tag, config)
    };

    info!(
        inbound = %inbound_tag,
        outbound = %outbound_tag,
        destination = %format!("{}:{}", dest_addr, dest_port),
        "Routing connection resolved"
    );

    let is_udp = cmd == 2;
    let outbound_handler: Box<dyn crate::outbound::OutboundHandler> = match outbound_config.as_ref().map(|c| c.protocol.as_str()) {
        Some("vless") => get_outbound_handler(outbound_config.as_ref(), is_udp)?,
        _ => {
            if is_udp {
                Box::new(crate::outbound::udp::UdpOutbound::new())
            } else {
                get_outbound_handler(outbound_config.as_ref(), false)?
            }
        }
    };

    // Register active connection
    let conn_id = Uuid::new_v4();
    let rx_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let tx_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let conn_info = ConnectionInfo {
        id: conn_id,
        inbound_tag: inbound_tag.clone(),
        client_ip: client_addr.to_string(),
        dest_address: format!("{}:{}", dest_addr, dest_port),
        sni: sni.clone(),
        outbound_tag: outbound_tag.clone(),
        rx: Arc::clone(&rx_counter),
        tx: Arc::clone(&tx_counter),
        start_time: std::time::Instant::now(),
    };

    engine_state.register_connection(conn_info);

    // Launch outbound task
    let engine = Arc::clone(&engine_state);
    let email_record = client_email.clone();
    tokio::spawn(async move {
        let res = outbound_handler.handle(inbound_stream, &dest_addr, dest_port, rx_counter, tx_counter, &engine, &email_record, &conn_id).await;
        if let Err(e) = res {
            error!(error = %e, "Outbound execution failure");
        }
        engine.deregister_connection(&conn_id);
    });

    Ok(())
}
