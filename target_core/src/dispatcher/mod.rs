use crate::dispatcher::sniffer::sniff_sni;
use crate::inbound::InboundTransportStream;
use crate::outbound::get_outbound_handler;
use crate::router::Router;
use crate::state::{ConnectionInfo, EngineState};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;

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
    let ipv4_only = crate::config::is_ipv4_only();
    if ipv4_only {
        if let Ok(ip) = dest_addr.parse::<std::net::IpAddr>() {
            if ip.is_ipv6() {
                static LAST_LOG: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let last = LAST_LOG.load(std::sync::atomic::Ordering::Relaxed);
                if now >= last + 2
                    && LAST_LOG
                        .compare_exchange(
                            last,
                            now,
                            std::sync::atomic::Ordering::Relaxed,
                            std::sync::atomic::Ordering::Relaxed,
                        )
                        .is_ok()
                {
                    tracing::debug!("IPv6 destination rejected because IPv4-only mode is enabled.");
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "IPv6 destination is rejected under IPv4-only mode",
                )
                .into());
            }
        }
    }

    match inbound_stream {
        InboundTransportStream::Plain(ref socket) => {
            let _ = socket.set_nodelay(true);
        }
        InboundTransportStream::Tls(ref stream) => {
            let _ = stream.get_ref().0.set_nodelay(true);
        }
        InboundTransportStream::Reality(ref stream) => {
            let _ = stream.get_ref().0.inner.set_nodelay(true);
        }
    }

    let sni = sniff_sni(&inbound_stream).await;
    if let Some(ref parsed_sni) = sni {
        info!(sni = %parsed_sni, "Parsed SNI successfully from connection");
    }

    let (client_email, outbound_tag, outbound_config) = {
        let (email, mode) = {
            let users_guard = engine_state.users.read();
            if let Some((user, mode)) = users_guard.get(&user_uuid) {
                (user.email.read().clone(), *mode)
            } else {
                (None, crate::config::ClientRouteMode::Smart)
            }
        };

        let config_guard = engine_state.config.read();
        let router = Router::new();
        let tables = engine_state.routing_tables.load();
        let tag = router.resolve_route(mode, &dest_addr, dest_port, &inbound_tag, &sni, &tables);

        let mut config = config_guard
            .outbounds
            .iter()
            .find(|o| o.tag == tag)
            .cloned();

        if tag == "warp" {
            if !engine_state.is_warp_allowed() {
                tracing::warn!("WARP health check is down, falling closed (dropping connection)");
                return Ok(());
            }
            if config.is_none() {
                config = Some(crate::config::OutboundConfig {
                    tag: "warp".to_string(),
                    protocol: "freedom".to_string(),
                    settings: None,
                    outbound_proxy: Some("127.0.0.1:40000".to_string()),
                    bind_address: None,
                });
            }
        }

        (email, tag, config)
    };

    let is_udp = cmd == 2;
    if is_udp {
        let proxy = outbound_config.as_ref().and_then(|c| {
            if c.protocol == "freedom" {
                None
            } else {
                c.outbound_proxy.clone()
            }
        });
        if let Some(ref proxy_addr) = proxy {
            info!(
                inbound = %inbound_tag,
                outbound = %outbound_tag,
                destination = %format!("{}:{}", dest_addr, dest_port),
                proxy = %proxy_addr,
                "Routing connection resolved: UDP proxy"
            );
        } else {
            info!(
                inbound = %inbound_tag,
                outbound = %outbound_tag,
                destination = %format!("{}:{}", dest_addr, dest_port),
                "Routing connection resolved: UDP direct"
            );
        }
    } else {
        info!(
            inbound = %inbound_tag,
            outbound = %outbound_tag,
            destination = %format!("{}:{}", dest_addr, dest_port),
            "Routing connection resolved: TCP"
        );
    }

    let outbound_handler: Box<dyn crate::outbound::OutboundHandler> =
        match outbound_config.as_ref().map(|c| c.protocol.as_str()) {
            Some("vless") => get_outbound_handler(outbound_config.as_ref(), is_udp)?,
            _ => {
                if is_udp {
                    let proxy = outbound_config.as_ref().and_then(|c| {
                        if c.protocol == "freedom" {
                            None
                        } else {
                            c.outbound_proxy.clone()
                        }
                    });
                    let bind_ip = outbound_config
                        .as_ref()
                        .and_then(|c| c.bind_address.clone());
                    Box::new(crate::outbound::udp::UdpOutbound::new(proxy, bind_ip))
                } else {
                    get_outbound_handler(outbound_config.as_ref(), false)?
                }
            }
        };

    // Register active connection
    let conn_id = Uuid::new_v4();
    let rx_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let tx_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

    let account_id_bytes = {
        let users_guard = engine_state.users.read();
        users_guard
            .get(&user_uuid)
            .and_then(|(user, _)| Uuid::parse_str(&user.id).ok().map(|u| u.into_bytes()))
    };

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
        user_uuid: account_id_bytes,
        shutdown_tx: Some(Arc::new(parking_lot::Mutex::new(Some(shutdown_tx)))),
    };

    engine_state.register_connection(conn_info);

    // Launch outbound task
    let engine = Arc::clone(&engine_state);
    let email_record = client_email.clone();
    tokio::spawn(async move {
        let outbound_fut = outbound_handler.handle(
            inbound_stream,
            &dest_addr,
            dest_port,
            rx_counter,
            tx_counter,
            &engine,
            &email_record,
            &conn_id,
        );

        tokio::select! {
            res = outbound_fut => {
                if let Err(e) = res {
                    error!(error = %e, dest = %dest_addr, port = dest_port, "Outbound execution failure");
                }
            }
            _ = &mut shutdown_rx => {
                tracing::debug!(conn_id = %conn_id, "Connection forcibly closed by policy update");
            }
        }
        engine.deregister_connection(&conn_id);
    });

    Ok(())
}
