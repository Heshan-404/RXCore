use axum::{
    extract::State,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

use crate::config::Config;
use crate::state::EngineState;

const INDEX_HTML: &str = include_str!("index.html");

pub struct ApiServer {
    pub state: Arc<EngineState>,
}

impl ApiServer {
    pub fn new(state: Arc<EngineState>) -> Self {
        Self { state }
    }

    pub async fn start(self, listen: std::net::IpAddr, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app = Router::new()
            .route("/", get(serve_index))
            .route("/config", get(get_config))
            .route("/stats", get(get_stats))
            .route("/connections", get(list_connections))
            .route("/reload", post(reload_config))
            .with_state(self.state);

        let addr = SocketAddr::new(listen, port);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        info!(api_address = %addr, "Admin Dashboard REST Server started");

        axum::serve(listener, app).await?;
        Ok(())
    }
}

#[derive(Serialize)]
pub struct UserStatsResponse {
    pub email: String,
    pub rx: u64,
    pub tx: u64,
}

async fn get_stats(State(state): State<Arc<EngineState>>) -> Json<Vec<UserStatsResponse>> {
    let stats_guard = state.stats.read();
    let mut response = Vec::new();
    for (email, user_stat) in stats_guard.iter() {
        response.push(UserStatsResponse {
            email: email.clone(),
            rx: user_stat.rx.load(std::sync::atomic::Ordering::Relaxed),
            tx: user_stat.tx.load(std::sync::atomic::Ordering::Relaxed),
        });
    }
    Json(response)
}

#[derive(Serialize)]
pub struct ConnectionResponse {
    pub id: String,
    pub inbound_tag: String,
    pub client_ip: String,
    pub dest_address: String,
    pub sni: Option<String>,
    pub outbound_tag: String,
    pub rx: u64,
    pub tx: u64,
    pub uptime_secs: u64,
}

async fn list_connections(State(state): State<Arc<EngineState>>) -> Json<Vec<ConnectionResponse>> {
    let conns_guard = state.active_connections.read();
    let mut response = Vec::new();
    for conn in conns_guard.values() {
        response.push(ConnectionResponse {
            id: conn.id.to_string(),
            inbound_tag: conn.inbound_tag.clone(),
            client_ip: conn.client_ip.clone(),
            dest_address: conn.dest_address.clone(),
            sni: conn.sni.clone(),
            outbound_tag: conn.outbound_tag.clone(),
            rx: conn.rx.load(std::sync::atomic::Ordering::Relaxed),
            tx: conn.tx.load(std::sync::atomic::Ordering::Relaxed),
            uptime_secs: conn.start_time.elapsed().as_secs(),
        });
    }
    Json(response)
}

#[derive(Deserialize)]
pub struct ReloadConfigPayload {
    pub config: Config,
}

async fn reload_config(
    State(state): State<Arc<EngineState>>,
    Json(payload): Json<ReloadConfigPayload>,
) -> Json<bool> {
    info!("Triggering dynamic rule reload config in core engine");
    state.update_config(payload.config);
    Json(true)
}

async fn serve_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn get_config(State(state): State<Arc<EngineState>>) -> Json<Config> {
    let config_guard = state.config.read();
    Json(config_guard.clone())
}
