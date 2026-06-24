use std::sync::Arc;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod api;
pub mod config;
pub mod dispatcher;
pub mod inbound;
pub mod outbound;
pub mod router;
pub mod state;
pub mod transport;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Initializing Next-Generation Rust Tunnel Engine...");

    // Default basic configurations when no outer parameters are specified
    let default_config_json = r#"
    {
        "inbounds": [
            {
                "tag": "vless-inbound",
                "listen": "0.0.0.0",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": "ad60c2b2-cc0c-492a-89aa-c92330a10cc9",
                            "email": "test_user@example.com"
                        }
                    ]
                },
                "stream_settings": {
                    "security": "tls",
                    "tls_settings": {
                        "server_name": "www.tiktok.com",
                        "certificate_file": null,
                        "key_file": null
                    }
                }
            },
            {
                "tag": "hysteria2-inbound",
                "listen": "0.0.0.0",
                "port": 443,
                "protocol": "hysteria2",
                "settings": {
                    "clients": [
                        {
                            "id": "ad60c2b2-cc0c-492a-89aa-c92330a10cc9",
                            "email": "test_user@example.com"
                        }
                    ]
                },
                "stream_settings": {
                    "security": "tls",
                    "tls_settings": {
                        "server_name": "www.tiktok.com",
                        "certificate_file": null,
                        "key_file": null
                    }
                }
            }
        ],
        "outbounds": [
            {
                "tag": "bypass-sni",
                "protocol": "fragment",
                "settings": {
                    "fragment": {
                        "packets": "1-5",
                        "length": "1-10",
                        "interval": 20
                    }
                }
            },
            {
                "tag": "freedom",
                "protocol": "freedom"
            }
        ],
        "routing": {
            "rules": [
                {
                    "domain": ["tiktok.com", "byteoversea.com"],
                    "outbound_tag": "bypass-sni"
                }
            ]
        },
        "api": {
            "listen": "0.0.0.0",
            "port": 9091
        }
    }
    "#;

    let config_path = std::path::Path::new("config.json");
    let initial_config: config::Config = if config_path.exists() {
        info!("Loading configuration from config.json");
        let content = std::fs::read_to_string(config_path)?;
        serde_json::from_str(&content)?
    } else {
        info!("Using default built-in configuration");
        serde_json::from_str(default_config_json)?
    };
    let api_listen = initial_config.api.listen;
    let api_port = initial_config.api.port;

    let engine_state = Arc::new(state::EngineState::new(initial_config));

    // Boot listener thread loops
    let state_ref = Arc::clone(&engine_state);
    let inbounds = {
        let config_guard = state_ref.config.read();
        config_guard.inbounds.clone()
    };

    for inbound_config in inbounds {
        let state_inbound = Arc::clone(&engine_state);
        tokio::spawn(async move {
            match inbound::create_inbound_listener(inbound_config) {
                Ok(listener) => {
                    if let Err(e) = listener.start(state_inbound).await {
                        error!(error = %e, "Listener aborted execution");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to create inbound listener");
                }
            }
        });
    }

    // Launch Administration UI API Service
    let api_server = api::ApiServer::new(Arc::clone(&engine_state));
    api_server.start(api_listen, api_port).await?;

    Ok(())
}
