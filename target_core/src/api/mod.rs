use axum::http::HeaderMap;
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tracing::{error, info};

use crate::config::{Client, Config};
use crate::state::EngineState;

pub mod cache;

const INDEX_HTML: &str = include_str!("index.html");

const LOGIN_HTML: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ruve VPN Administration Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #07070a;
            --card-bg: rgba(18, 18, 29, 0.75);
            --border-color: rgba(255, 255, 255, 0.08);
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.4);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', sans-serif;
        }
        body {
            background-color: var(--bg-dark);
            background-image: radial-gradient(at 50% 50%, rgba(99, 102, 241, 0.15) 0px, transparent 50%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 24px;
            width: 100%;
            max-width: 420px;
            padding: 40px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
            backdrop-filter: blur(16px);
            text-align: center;
        }
        .logo-icon {
            width: 64px;
            height: 64px;
            background: linear-gradient(135deg, var(--primary), #10b981);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            box-shadow: 0 0 20px var(--primary-glow);
        }
        .logo-icon svg {
            width: 32px;
            height: 32px;
            fill: #fff;
        }
        h1 {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 10px;
        }
        p {
            color: var(--text-muted);
            font-size: 0.95rem;
            margin-bottom: 30px;
        }
        .form-group {
            text-align: left;
            margin-bottom: 20px;
        }
        label {
            display: block;
            font-size: 0.85rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        input {
            width: 100%;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 12px 16px;
            color: #fff;
            font-size: 1rem;
            outline: none;
            transition: all 0.3s;
        }
        input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 10px var(--primary-glow);
            background: rgba(255, 255, 255, 0.05);
        }
        .login-btn {
            width: 100%;
            background: var(--primary);
            color: #fff;
            border: none;
            padding: 14px;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            margin-top: 10px;
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3);
        }
        .login-btn:hover {
            background: #4f46e5;
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(99, 102, 241, 0.4);
        }
        .error-msg {
            color: #danger;
            font-size: 0.9rem;
            margin-top: 15px;
            display: none;
            color: #ef4444;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo-icon">
            <svg viewBox="0 0 24 24">
                <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
            </svg>
        </div>
        <h1>Ruve Admin Portal</h1>
        <p>Authenticate to manage VPN server</p>
        <form id="login-form">
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" required placeholder="Enter admin password">
            </div>
            <button type="submit" class="login-btn">Sign In</button>
            <div id="error" class="error-msg"></div>
        </form>
    </div>
    <script>
        document.getElementById('login-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error');
            errorDiv.style.display = 'none';
            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                if (res.ok) {
                    const data = await res.json();
                    localStorage.setItem('csrf_token', data.csrf_token);
                    window.location.href = '/';
                } else {
                    const text = await res.text();
                    errorDiv.innerText = text || 'Login failed';
                    errorDiv.style.display = 'block';
                }
            } catch (err) {
                errorDiv.innerText = 'Network error occurred';
                errorDiv.style.display = 'block';
            }
        });
    </script>
</body>
</html>
"#;

pub struct ApiServer {
    pub state: Arc<EngineState>,
}

impl ApiServer {
    pub fn new(state: Arc<EngineState>) -> Self {
        Self { state }
    }

    pub async fn start(
        self,
        listen: std::net::IpAddr,
        port: u16,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Main Admin Dashboard router on port 9091
        let protected_routes = Router::new()
            .route("/config", get(get_config))
            .route("/connections", get(list_connections))
            .route("/reload", post(reload_config))
            .route("/connections-monitor", get(serve_connections_monitor))
            .route("/api/auth/logout", post(logout_handler))
            .route("/api/auth/change-password", post(change_password_handler))
            .route("/api/auth/session", get(session_check_handler))
            .route("/api/users", get(list_users).post(create_user))
            .route("/api/users/:id", delete(delete_user))
            .route("/api/users/:id/add-quota", post(add_quota))
            .route(
                "/api/users/:id/regenerate-token",
                post(regenerate_sub_token),
            )
            .route(
                "/api/reality/profiles",
                get(list_reality_profiles).post(create_reality_profile),
            )
            .route(
                "/api/reality/generate-keypair",
                post(generate_reality_keypair),
            )
            .route(
                "/api/reality/generate-short-id",
                post(generate_reality_short_id),
            )
            .route("/api/reality/validate", post(validate_reality_profile))
            .route("/api/vpn-accounts", post(create_vpn_account))
            .route("/api/dashboard", get(get_dashboard))
            .route(
                "/api/connections-monitor/data",
                get(get_connections_monitor_data),
            )
            .route(
                "/api/routing/warp-sets",
                get(list_warp_sets).post(create_warp_set),
            )
            .route(
                "/api/routing/warp-sets/:id",
                put(update_warp_set).delete(delete_warp_set),
            )
            .route(
                "/api/routing/direct-sets",
                get(list_direct_sets).post(create_direct_set),
            )
            .route(
                "/api/routing/direct-sets/:id",
                put(update_direct_set).delete(delete_direct_set),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                Arc::clone(&self.state),
                admin_auth_middleware,
            ));

        let app = Router::new()
            .route("/", get(serve_index))
            .route("/health", get(health_check))
            .route(
                "/api/auth/login",
                post(login_handler).layer(axum::extract::DefaultBodyLimit::max(1024)),
            )
            .merge(protected_routes)
            .with_state(Arc::clone(&self.state));

        // Subscription router on port 9100
        let sub_state = Arc::clone(&self.state);
        tokio::spawn(async move {
            let sub_app = Router::new()
                .route("/sub/:id", get(serve_subscription))
                .route("/sub/:id/singbox", get(serve_singbox))
                .with_state(sub_state);
            let sub_addr = SocketAddr::new(listen, 9100);
            if let Ok(listener) = tokio::net::TcpListener::bind(sub_addr).await {
                info!(sub_address = %sub_addr, "Subscription Server started");
                if let Err(e) = axum::serve(
                    listener,
                    sub_app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                {
                    error!("Subscription Server error: {}", e);
                }
            } else {
                error!("Failed to bind Subscription Server to {}", sub_addr);
            }
        });

        let addr = SocketAddr::new(listen, port);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        info!(api_address = %addr, "Admin Dashboard REST Server started");

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
        Ok(())
    }
}

// Structs for Admin REST Responses

#[derive(Serialize, Clone)]
pub struct UserInfoResponse {
    pub id: String,
    pub email: Option<String>,
    pub limit_ip: Option<u32>,
    pub total_gb: Option<u64>,
    pub expiry_time: Option<i64>,
    pub speed_limit: Option<u64>,
    pub remaining_gb: Option<f64>,
    pub rx: u64,
    pub tx: u64,
}

#[derive(Serialize, Clone)]
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

#[derive(Deserialize)]
pub struct AddQuotaPayload {
    pub amount_gb: f64,
}

#[derive(Deserialize)]
pub struct ReloadConfigPayload {
    pub config: Config,
}

// Route Handlers

async fn serve_index(headers: HeaderMap) -> impl IntoResponse {
    let cookie_header = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut session_cookie = "";
    for cookie in cookie_header.split(';') {
        let parts: Vec<&str> = cookie.split('=').map(|s| s.trim()).collect();
        if parts.len() == 2 && parts[0] == "ruve_session" {
            session_cookie = parts[1];
            break;
        }
    }

    let mut is_authenticated = false;
    if !session_cookie.is_empty() {
        if let Ok(Some(creds)) = crate::auth::load_admin_credentials() {
            let secret_bytes = hex::decode(&creds.session_secret).unwrap_or_default();
            if let Ok(claims) =
                crate::auth::decode_and_verify_session(session_cookie, &secret_bytes)
            {
                if claims.session_epoch == creds.session_epoch {
                    is_authenticated = true;
                }
            }
        }
    }

    if is_authenticated {
        Html(INDEX_HTML).into_response()
    } else {
        Html(LOGIN_HTML).into_response()
    }
}

async fn get_config(State(state): State<Arc<EngineState>>) -> Json<Config> {
    let config_guard = state.config.read();
    Json(config_guard.clone())
}

async fn reload_config(
    State(state): State<Arc<EngineState>>,
    Json(mut payload): Json<ReloadConfigPayload>,
) -> Json<bool> {
    info!("Triggering dynamic rule reload config in core engine");
    if let Err(e) = payload.config.validate_and_normalize() {
        error!("Dynamic config reload rejected (validation failed): {}", e);
        return Json(false);
    }

    for inbound in &payload.config.inbounds {
        if inbound.protocol == "vless" {
            if let Some(ref ss) = inbound.stream_settings {
                if ss.security == "reality" {
                    if let Some(ref rs) = ss.reality_settings {
                        let dest = &rs.dest;
                        if let Some(sni) = rs.server_names.first() {
                            if let Err(e) =
                                crate::transport::reality::preflight_reality_check(dest, sni).await
                            {
                                error!("Dynamic config reload rejected (preflight failed for dest={} sni={}): {}", dest, sni, e);
                                return Json(false);
                            }
                        }
                    }
                }
            }
        }
    }

    if let Err(e) = state.update_config(payload.config) {
        error!("Dynamic config reload rejected: {}", e);
        return Json(false);
    }
    Json(true)
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
            rx: conn.rx.load(Ordering::Relaxed),
            tx: conn.tx.load(Ordering::Relaxed),
            uptime_secs: conn.start_time.elapsed().as_secs(),
        });
    }
    Json(response)
}

async fn list_users(State(state): State<Arc<EngineState>>) -> Json<Vec<UserInfoResponse>> {
    let users_guard = state.users.read();
    let mut response = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (user, _) in users_guard.values() {
        if !seen.insert(&user.id) {
            continue;
        }
        let rem_bytes = user.remaining_bytes.load(Ordering::Relaxed);
        let remaining_gb = if rem_bytes == -1 {
            None
        } else {
            Some(rem_bytes as f64 / 1_073_741_824.0)
        };

        let tot = user.total_gb.load(Ordering::Relaxed);
        let total_gb = if tot == -1 { None } else { Some(tot as u64) };

        response.push(UserInfoResponse {
            id: user.id.clone(),
            email: user.email.read().clone(),
            limit_ip: {
                let val = user.limit_ip.load(Ordering::Relaxed);
                if val > 0 {
                    Some(val)
                } else {
                    None
                }
            },
            total_gb,
            expiry_time: {
                let val = user.expiry_time.load(Ordering::Relaxed);
                if val > 0 {
                    Some(val)
                } else {
                    None
                }
            },
            speed_limit: {
                let val = user.speed_limit.load(Ordering::Relaxed);
                if val > 0 {
                    Some(val)
                } else {
                    None
                }
            },
            remaining_gb,
            rx: user.rx.load(Ordering::Relaxed),
            tx: user.tx.load(Ordering::Relaxed),
        });
    }
    Json(response)
}

async fn create_user(
    State(state): State<Arc<EngineState>>,
    Json(new_client): Json<Client>,
) -> impl IntoResponse {
    info!(
        "Adding new client dynamically to inbounds: {:?}",
        new_client.email
    );
    let mut config = state.config.read().clone();

    // Insert new client into all configured inbounds containing clients
    for inbound in &mut config.inbounds {
        if let Some(ref mut clients) = inbound.settings.clients {
            if !clients.iter().any(|c| c.id == new_client.id) {
                clients.push(new_client.clone());
            }
        }
    }

    if let Err(e) = state.update_config(config) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            format!("Failed to update config: {}", e),
        )
            .into_response();
    }
    state.persist_config_to_disk();
    Json(true).into_response()
}

async fn delete_user(
    Path(id): Path<String>,
    State(state): State<Arc<EngineState>>,
) -> impl IntoResponse {
    info!("Deleting client dynamically from inbounds: {}", id);
    let mut config = state.config.read().clone();

    for inbound in &mut config.inbounds {
        if let Some(ref mut clients) = inbound.settings.clients {
            clients.retain(|c| c.id != id);
        }
    }

    if let Err(e) = state.update_config(config) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            format!("Failed to update config: {}", e),
        )
            .into_response();
    }
    state.disconnect_user(&id);
    state.persist_config_to_disk();
    Json(true).into_response()
}

async fn add_quota(
    Path(id): Path<String>,
    State(state): State<Arc<EngineState>>,
    Json(payload): Json<AddQuotaPayload>,
) -> impl IntoResponse {
    info!(
        "Extending client quota dynamically for user ID: {}, volume: {} GB",
        id, payload.amount_gb
    );
    let users_guard = state.users.read();
    let user_stats = users_guard
        .values()
        .find(|(u, _)| u.id == id)
        .map(|(u, _)| u);

    if let Some(user) = user_stats {
        let added_bytes = (payload.amount_gb * 1_073_741_824.0) as i64;
        let prev_rem = user.remaining_bytes.load(Ordering::Relaxed);
        let new_rem = if prev_rem == -1 || prev_rem <= 0 {
            added_bytes
        } else {
            prev_rem + added_bytes
        };
        user.remaining_bytes.store(new_rem, Ordering::Relaxed);

        let prev_tot = user.total_gb.load(Ordering::Relaxed);
        let new_tot = if prev_tot == -1 {
            payload.amount_gb as i64
        } else {
            prev_tot + payload.amount_gb as i64
        };
        user.total_gb.store(new_tot, Ordering::Relaxed);

        // Trigger persistence
        state.persist_config_to_disk();
        Json(true)
    } else {
        Json(false)
    }
}

async fn regenerate_sub_token(
    Path(id): Path<String>,
    State(state): State<Arc<EngineState>>,
) -> impl IntoResponse {
    let mut config = state.config.read().clone();
    let mut found = false;

    // Generate secure random 32-byte token
    let mut token_bytes = [0u8; 32];
    rand::thread_rng().fill(&mut token_bytes);
    let raw_token_hex = hex::encode(token_bytes);

    // Compute SHA-256 hash
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(raw_token_hex.as_bytes());
    let hash_bytes = hasher.finalize();
    let hash_hex = hex::encode(hash_bytes);

    for inbound in &mut config.inbounds {
        if let Some(ref mut clients) = inbound.settings.clients {
            for client in clients {
                if client.id == id {
                    client.sub_token_hash = Some(hash_hex.clone());
                    found = true;
                }
            }
        }
    }

    if !found {
        return (axum::http::StatusCode::NOT_FOUND, "User not found").into_response();
    }

    if let Err(e) = state.update_config(config) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            format!("Failed to update configuration: {}", e),
        )
            .into_response();
    }
    state.persist_config_to_disk();

    Json(serde_json::json!({
        "sub_token": raw_token_hex
    }))
    .into_response()
}

// Subscription Serving Handler

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

static SUB_LIMITER: once_cell::sync::Lazy<Mutex<HashMap<IpAddr, Vec<Instant>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

fn check_sub_rate_limit(ip: IpAddr) -> bool {
    let now = Instant::now();
    let window = Duration::from_secs(60);
    let mut map = SUB_LIMITER.lock();

    if map.len() > 1000 {
        map.retain(|_, v| {
            v.retain(|&t| now.duration_since(t) < window);
            !v.is_empty()
        });
    }

    let entry = map.entry(ip).or_insert_with(Vec::new);
    entry.retain(|&t| now.duration_since(t) < window);

    if entry.len() >= 10 {
        return false;
    }

    entry.push(now);
    true
}

fn get_client_ip(headers: &HeaderMap, peer_addr: SocketAddr, state: &EngineState) -> IpAddr {
    let peer_ip = peer_addr.ip();
    let trusted = &state.config.read().api.trusted_proxies;
    let is_trusted = peer_ip.is_loopback() || trusted.contains(&peer_ip);
    if is_trusted {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first_ip) = xff.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    peer_ip
}

async fn serve_subscription(
    Path(id): Path<String>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    State(state): State<Arc<EngineState>>,
) -> impl IntoResponse {
    let client_ip = get_client_ip(&headers, addr, &state);
    if !check_sub_rate_limit(client_ip) {
        let mut response = Response::builder()
            .status(axum::http::StatusCode::TOO_MANY_REQUESTS)
            .body(axum::body::Body::from(
                "Too many requests. Please try again later.",
            ))
            .unwrap()
            .into_response();
        response.headers_mut().insert(
            "X-Robots-Tag",
            axum::http::HeaderValue::from_static("noindex, nofollow"),
        );
        return response;
    }
    let user_stats_opt = {
        use sha2::Digest;
        let token_bytes = id.trim().as_bytes();
        let mut hasher = sha2::Sha256::new();
        hasher.update(token_bytes);
        let hash_result = hasher.finalize();
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash_result);

        let sub_guard = state.sub_tokens.read();
        sub_guard.get(&hash_arr).cloned()
    };

    if let Some(user) = user_stats_opt {
        let email = user
            .email
            .read()
            .clone()
            .unwrap_or_else(|| "User".to_string());
        let rem_bytes = user.remaining_bytes.load(Ordering::Relaxed);

        let (total_str, rem_str, progress_percent, used_gb_str) = if rem_bytes == -1 {
            (
                "Unlimited".to_string(),
                "Unlimited".to_string(),
                0.0,
                "0.00 GB".to_string(),
            )
        } else {
            let tot_gb = user.total_gb.load(Ordering::Relaxed);
            let total_bytes = (tot_gb * 1_073_741_824) as u64;
            let computed_used_bytes = if total_bytes > rem_bytes as u64 {
                total_bytes - rem_bytes as u64
            } else {
                0
            };
            let percent = if total_bytes > 0 {
                (computed_used_bytes as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            };
            (
                format!("{:.2} GB", total_bytes as f64 / 1_073_741_824.0),
                format!("{:.2} GB", rem_bytes as f64 / 1_073_741_824.0),
                percent,
                format!("{:.2} GB", computed_used_bytes as f64 / 1_073_741_824.0),
            )
        };

        let expiry = user.expiry_time.load(Ordering::Relaxed);
        let expiry_str = if expiry > 0 {
            let datetime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(expiry as u64);
            let formatted = chrono::DateTime::<chrono::Utc>::from(datetime)
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string();
            formatted
        } else {
            "Never Expires".to_string()
        };

        let config_guard = state.config.read();

        // Determine request host name or IP address
        let host_str = config_guard
            .public_server_address
            .clone()
            .unwrap_or_else(|| {
                headers
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .map(|h| h.split(':').next().unwrap_or("172.236.150.147").to_string())
                    .unwrap_or_else(|| "172.236.150.147".to_string())
            });
        let host = &host_str;
        let (browsing_warp_uuid, low_latency_uuid, client_obj_opt) = {
            let mut b_uuid = None;
            let mut l_uuid = None;
            let mut c_obj = None;
            for inbound in &config_guard.inbounds {
                if let Some(ref clients) = inbound.settings.clients {
                    if let Some(c) = clients.iter().find(|c| c.id == user.id) {
                        b_uuid = c.browsing_warp_id.clone();
                        l_uuid = c.low_latency_id.clone();
                        c_obj = Some(c.clone());
                        break;
                    }
                }
            }
            (b_uuid, l_uuid, c_obj)
        };

        let mut smart_vless = String::new();
        let mut warp_vless = String::new();
        let mut direct_vless = String::new();

        let profile_opt = {
            let p_id_opt = *user.reality_profile_id.read();
            if let Some(p_id) = p_id_opt {
                config_guard.reality_profiles.iter().find(|p| p.id == p_id)
            } else {
                config_guard
                    .reality_profiles
                    .iter()
                    .find(|p| {
                        p.name == "Default VLESS Reality"
                            || p.inbound_tag == "vless-inbound-443"
                            || p.inbound_tag == "vless-inbound"
                    })
                    .or_else(|| config_guard.reality_profiles.first())
            }
        };

        let params_res = if let Some(profile) = profile_opt {
            let client_to_use = client_obj_opt.unwrap_or_else(|| Client {
                id: user.id.clone(),
                email: user.email.read().clone(),
                limit_ip: None,
                total_gb: None,
                expiry_time: None,
                speed_limit: None,
                remaining_gb: None,
                rx: None,
                tx: None,
                reality_profile_id: Some(profile.id),
                inbound_tag: Some(profile.inbound_tag.clone()),
                browsing_warp_id: None,
                low_latency_id: None,
                sub_token_hash: None,
                sni: user.sni.read().clone(),
            });

            Ok(crate::config::RealityClientParameters::new(
                profile,
                &client_to_use,
                host,
            ))
        } else {
            crate::config::RealityClientParameters::from_config(&config_guard, host)
        };

        if let Ok(ref params) = params_res {
            smart_vless = params.to_vless_uri(&email);

            if let Some(ref w_id) = browsing_warp_uuid {
                if let Ok(w_uuid) = uuid::Uuid::parse_str(w_id) {
                    let mut p = params.clone();
                    p.uuid = w_uuid;
                    warp_vless = p.to_vless_uri(&format!("{}-warp", email));
                }
            }

            if let Some(ref d_id) = low_latency_uuid {
                if let Ok(d_uuid) = uuid::Uuid::parse_str(d_id) {
                    let mut p = params.clone();
                    p.uuid = d_uuid;
                    direct_vless = p.to_vless_uri(&format!("{}-direct", email));
                }
            }
        }



        let html_content = format!(
            r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPN Subscription: {email}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #07070a;
            --card-bg: rgba(18, 18, 29, 0.75);
            --border-color: rgba(255, 255, 255, 0.08);
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.4);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', sans-serif;
        }}
        body {{
            background-color: var(--bg-dark);
            background-image: radial-gradient(at 50% 50%, rgba(99, 102, 241, 0.15) 0px, transparent 50%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 24px;
            width: 100%;
            max-width: 500px;
            padding: 40px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
            backdrop-filter: blur(16px);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .logo-icon {{
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, var(--primary), #10b981);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 15px;
            box-shadow: 0 0 20px var(--primary-glow);
        }}
        .logo-icon svg {{
            width: 30px;
            height: 30px;
            fill: #fff;
        }}
        h1 {{
            font-size: 1.6rem;
            font-weight: 700;
        }}
        .email {{
            color: var(--text-muted);
            font-size: 0.95rem;
            margin-top: 5px;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}
        .info-box {{
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 15px;
            text-align: center;
        }}
        .info-box h3 {{
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }}
        .info-box p {{
            font-size: 1.2rem;
            font-weight: 600;
        }}
        .progress-container {{
            margin-bottom: 30px;
        }}
        .progress-label {{
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-bottom: 8px;
        }}
        .progress-bar-bg {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 10px;
            height: 10px;
            overflow: hidden;
        }}
        .progress-bar-fill {{
            background: linear-gradient(90deg, var(--primary), #10b981);
            height: 100%;
            border-radius: 10px;
            width: {progress_percent}%;
            box-shadow: 0 0 10px rgba(99, 102, 241, 0.5);
        }}
        .links-container {{
            display: flex;
            flex-direction: column;
            gap: 15px;
        }}
        .link-row {{
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 15px;
        }}
        .link-label {{
            font-weight: 600;
            font-size: 0.95rem;
        }}
        .copy-btn {{
            background: var(--primary);
            color: #fff;
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }}
        .copy-btn:hover {{
            background: #4f46e5;
            transform: translateY(-1px);
        }}
        .tabs-container {{
            display: flex;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 25px;
            padding: 4px;
        }}
        .tab-btn {{
            flex: 1;
            background: none;
            border: none;
            color: var(--text-muted);
            padding: 10px;
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            border-radius: 8px;
            transition: all 0.3s;
        }}
        .tab-btn.active {{
            background: var(--primary);
            color: #fff;
            box-shadow: 0 0 10px var(--primary-glow);
        }}
        .tab-content {{
            display: none;
        }}
        .tab-content.active {{
            display: block;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <div class="logo-icon">
                <svg viewBox="0 0 24 24">
                    <path d="M4 15h2v3h12v-3h2v3c0 1.1-.9 2-2 2H6c-1.1 0-2-.9-2-2v-3zm16-4h-2V8H6v3H4V8c0-1.1.9-2 2-2h12c1.1 0 2 .9 2 2v3zm-5-3h-2v3h-4v2h4v3h2v-3h4v-2h-4V8z"/>
                </svg>
            </div>
            <h1>VPN Subscription Details</h1>
            <p class="email">{email}</p>
        </div>

        <div class="info-grid">
            <div class="info-box">
                <h3>Remaining Data</h3>
                <p>{rem_str}</p>
            </div>
            <div class="info-box">
                <h3>Expiry Date</h3>
                <p style="font-size: 0.95rem; padding-top: 4px;">{expiry_str}</p>
            </div>
        </div>

        <div class="progress-container">
            <div class="progress-label">
                <span>Usage: {used_gb_str} / {total_str}</span>
                <span>{progress_percent:.1}% Used</span>
            </div>
            <div class="progress-bar-bg">
                <div class="progress-bar-fill"></div>
            </div>
        </div>



        <div class="tabs-container">
            <button class="tab-btn active" onclick="switchTab(event, 'smart-tab')">Smart</button>
            <button class="tab-btn" onclick="switchTab(event, 'warp-tab')">WARP Only</button>
            <button class="tab-btn" onclick="switchTab(event, 'direct-tab')">Direct Only</button>
        </div>

        <div id="smart-tab" class="tab-content active">
            <div style="background: rgba(99,102,241,0.08); border: 1px solid rgba(99,102,241,0.2); border-radius: 10px; padding: 12px 15px; margin-bottom: 18px; font-size: 0.82rem; color: var(--text-muted); line-height: 1.5;">
                <strong style="color: #818cf8;">&#9889; Smart Mode</strong> &mdash; Best for everyday use. Most traffic goes <strong>directly through the server</strong> (fast, shows server IP). Sites that block you with a <strong>Cloudflare &ldquo;Why have I been blocked?&rdquo;</strong> page or show a <strong>Google reCAPTCHA</strong> automatically route through <strong>WARP</strong> for compatibility.
            </div>
            <div class="links-container">
                <div class="link-row">
                    <span class="link-label">VLESS Reality Config</span>
                    <button class="copy-btn" onclick="copyToClipboard('{smart_vless}', 'Smart VLESS')">Copy Link</button>
                </div>
                <div class="link-row">
                    <span class="link-label">sing-box JSON Config</span>
                    <a class="copy-btn" style="text-decoration: none; display: inline-block; text-align: center;" href="/sub/{id}/singbox?mode=smart" download="sing-box-smart.json">Download</a>
                </div>

            </div>

            <div style="margin-top: 30px; text-align: center;">
                <h3 style="font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 15px;">Smart VLESS QR Code</h3>
                <div style="background: white; padding: 15px; border-radius: 16px; display: inline-block; box-shadow: 0 4px 15px rgba(0,0,0,0.25);">
                    <canvas id="qr-smart"></canvas>
                </div>
            </div>
        </div>

        <div id="warp-tab" class="tab-content">
            <div style="background: rgba(6,182,212,0.08); border: 1px solid rgba(6,182,212,0.2); border-radius: 10px; padding: 12px 15px; margin-bottom: 18px; font-size: 0.82rem; color: var(--text-muted); line-height: 1.5;">
                <strong style="color: #22d3ee;">&#9729; WARP Only Mode</strong> &mdash; All traffic tunnels through <strong>Cloudflare WARP</strong>. Your IP will appear as a <strong>Cloudflare IP</strong>. Use this if sites are blocked on the server&apos;s IP or you specifically need a Cloudflare exit.
            </div>
            <div class="links-container">
                <div class="link-row">
                    <span class="link-label">VLESS Reality Config</span>
                    <button class="copy-btn" onclick="copyToClipboard('{warp_vless}', 'WARP VLESS')">Copy Link</button>
                </div>
                <div class="link-row">
                    <span class="link-label">sing-box JSON Config</span>
                    <a class="copy-btn" style="text-decoration: none; display: inline-block; text-align: center;" href="/sub/{id}/singbox?mode=warp" download="sing-box-warp.json">Download</a>
                </div>
            </div>

            <div style="margin-top: 30px; text-align: center;">
                <h3 style="font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 15px;">WARP VLESS QR Code</h3>
                <div style="background: white; padding: 15px; border-radius: 16px; display: inline-block; box-shadow: 0 4px 15px rgba(0,0,0,0.25);">
                    <canvas id="qr-warp"></canvas>
                </div>
            </div>
        </div>

        <div id="direct-tab" class="tab-content">
            <div style="background: rgba(34,197,94,0.08); border: 1px solid rgba(34,197,94,0.2); border-radius: 10px; padding: 12px 15px; margin-bottom: 18px; font-size: 0.82rem; color: var(--text-muted); line-height: 1.5;">
                <strong style="color: #4ade80;">&#128640; Direct Only Mode</strong> &mdash; Fastest mode. <strong>All traffic goes directly</strong> through the server, no WARP, no detours. Best for <strong>low-latency gaming, VoIP, or downloads</strong> where speed matters most.
            </div>
            <div class="links-container">
                <div class="link-row">
                    <span class="link-label">VLESS Reality Config</span>
                    <button class="copy-btn" onclick="copyToClipboard('{direct_vless}', 'Direct VLESS')">Copy Link</button>
                </div>
                <div class="link-row">
                    <span class="link-label">sing-box JSON Config</span>
                    <a class="copy-btn" style="text-decoration: none; display: inline-block; text-align: center;" href="/sub/{id}/singbox?mode=direct" download="sing-box-direct.json">Download</a>
                </div>
            </div>

            <div style="margin-top: 30px; text-align: center;">
                <h3 style="font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 15px;">Direct VLESS QR Code</h3>
                <div style="background: white; padding: 15px; border-radius: 16px; display: inline-block; box-shadow: 0 4px 15px rgba(0,0,0,0.25);">
                    <canvas id="qr-direct"></canvas>
                </div>
            </div>
        </div>

        <div style="text-align: center; margin-top: 25px; font-size: 0.75rem; color: var(--text-muted);">
            Config Version: 2.2.0 &bull; Updated: 2026-07-15 00:00:00 UTC
        </div>
    </div>

    <script>
        function switchTab(evt, tabId) {{
            const contents = document.getElementsByClassName("tab-content");
            for (let i = 0; i < contents.length; i++) {{
                contents[i].classList.remove("active");
            }}
            const buttons = document.getElementsByClassName("tab-btn");
            for (let i = 0; i < buttons.length; i++) {{
                buttons[i].classList.remove("active");
            }}
            document.getElementById(tabId).classList.add("active");
            evt.currentTarget.classList.add("active");
        }}

        function copyToClipboard(text, label) {{
            if (navigator.clipboard && navigator.clipboard.writeText) {{
                navigator.clipboard.writeText(text).then(function() {{
                    alert(label + ' link copied to clipboard!');
                }}, function() {{
                    fallbackCopy(text, label);
                }});
            }} else {{
                fallbackCopy(text, label);
            }}
        }}

        function fallbackCopy(text, label) {{
            const textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.position = "fixed";
            textArea.style.opacity = "0";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {{
                document.execCommand('copy');
                alert(label + ' link copied to clipboard!');
            }} catch (err) {{
                alert('Failed to copy ' + label + ' link.');
            }}
            document.body.removeChild(textArea);
        }}
    </script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrious/4.0.2/qrious.min.js"></script>
    <script>
        (function() {{
            new QRious({{
                element: document.getElementById('qr-smart'),
                value: '{smart_vless}',
                size: 180
            }});
            new QRious({{
                element: document.getElementById('qr-warp'),
                value: '{warp_vless}',
                size: 180
            }});
            new QRious({{
                element: document.getElementById('qr-direct'),
                value: '{direct_vless}',
                size: 180
            }});
        }})();
    </script>
</body>
</html>
        "#,
            email = email,
            smart_vless = smart_vless,
            warp_vless = warp_vless,
            direct_vless = direct_vless,
            used_gb_str = used_gb_str,
            total_str = total_str,
            progress_percent = progress_percent,
            id = id,
            expiry_str = expiry_str,
            rem_str = rem_str,
        );

        let mut response = Html(html_content).into_response();
        response.headers_mut().insert(
            "X-Robots-Tag",
            axum::http::HeaderValue::from_static("noindex, nofollow"),
        );
        response
    } else {
        Response::builder()
            .status(404)
            .body(axum::body::Body::from("<h1>Subscription Not Found</h1><p>The specified subscription ID does not exist or has expired.</p>"))
            .unwrap()
            .into_response()
    }
}

async fn serve_singbox(
    Path(id): Path<String>,
    axum::extract::Query(params_query): axum::extract::Query<HashMap<String, String>>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    State(state): State<Arc<EngineState>>,
) -> impl IntoResponse {
    let client_ip = get_client_ip(&headers, addr, &state);
    if !check_sub_rate_limit(client_ip) {
        let mut response = Response::builder()
            .status(axum::http::StatusCode::TOO_MANY_REQUESTS)
            .body(axum::body::Body::from(
                "Too many requests. Please try again later.",
            ))
            .unwrap()
            .into_response();
        response.headers_mut().insert(
            "X-Robots-Tag",
            axum::http::HeaderValue::from_static("noindex, nofollow"),
        );
        return response;
    }

    let user_stats_opt = {
        use sha2::Digest;
        let token_bytes = id.trim().as_bytes();
        let mut hasher = sha2::Sha256::new();
        hasher.update(token_bytes);
        let hash_result = hasher.finalize();
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash_result);

        let sub_guard = state.sub_tokens.read();
        sub_guard.get(&hash_arr).cloned()
    };

    if let Some(user) = user_stats_opt {
        let config_guard = state.config.read();
        let host_str = config_guard
            .public_server_address
            .clone()
            .unwrap_or_else(|| {
                headers
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .map(|h| h.split(':').next().unwrap_or("172.236.150.147").to_string())
                    .unwrap_or_else(|| "172.236.150.147".to_string())
            });
        let host = &host_str;

        let profile_opt = {
            let p_id_opt = *user.reality_profile_id.read();
            if let Some(p_id) = p_id_opt {
                config_guard.reality_profiles.iter().find(|p| p.id == p_id)
            } else {
                config_guard
                    .reality_profiles
                    .iter()
                    .find(|p| {
                        p.name == "Default VLESS Reality"
                            || p.inbound_tag == "vless-inbound-443"
                            || p.inbound_tag == "vless-inbound"
                    })
                    .or_else(|| config_guard.reality_profiles.first())
            }
        };

        let mut matched_client = None;
        for inbound in &config_guard.inbounds {
            if let Some(ref clients) = inbound.settings.clients {
                if let Some(c) = clients.iter().find(|c| c.id == user.id) {
                    matched_client = Some(c.clone());
                    break;
                }
            }
        }

        let client_to_use = matched_client.unwrap_or_else(|| Client {
            id: user.id.clone(),
            email: user.email.read().clone(),
            limit_ip: None,
            total_gb: None,
            expiry_time: None,
            speed_limit: None,
            remaining_gb: None,
            rx: None,
            tx: None,
            reality_profile_id: profile_opt.map(|p| p.id),
            inbound_tag: profile_opt.map(|p| p.inbound_tag.clone()),
            browsing_warp_id: None,
            low_latency_id: None,
            sub_token_hash: None,
            sni: user.sni.read().clone(),
        });

        let mut params_res = if let Some(profile) = profile_opt {
            Ok(crate::config::RealityClientParameters::new(
                profile,
                &client_to_use,
                host,
            ))
        } else {
            crate::config::RealityClientParameters::from_config(&config_guard, host)
        };

        if let Ok(ref mut params) = params_res {
            let mode = params_query
                .get("mode")
                .map(|s| s.as_str())
                .unwrap_or("smart");
            if mode == "warp" {
                if let Some(ref w_id) = client_to_use.browsing_warp_id {
                    if let Ok(w_uuid) = uuid::Uuid::parse_str(w_id) {
                        params.uuid = w_uuid;
                    }
                }
            } else if mode == "direct" {
                if let Some(ref d_id) = client_to_use.low_latency_id {
                    if let Ok(d_uuid) = uuid::Uuid::parse_str(d_id) {
                        params.uuid = d_uuid;
                    }
                }
            }
        }

        match params_res {
            Ok(params) => {
                let json_content = params.to_singbox_json();
                let mut response = Response::builder()
                    .header("Content-Type", "application/json")
                    .header(
                        "Content-Disposition",
                        "attachment; filename=\"sing-box.json\"",
                    )
                    .body(axum::body::Body::from(json_content))
                    .unwrap()
                    .into_response();
                response.headers_mut().insert(
                    "X-Robots-Tag",
                    axum::http::HeaderValue::from_static("noindex, nofollow"),
                );
                response
            }
            Err(e) => {
                let mut response = Response::builder()
                    .status(500)
                    .body(axum::body::Body::from(format!(
                        "Failed to generate sing-box configuration: {}",
                        e
                    )))
                    .unwrap()
                    .into_response();
                response.headers_mut().insert(
                    "X-Robots-Tag",
                    axum::http::HeaderValue::from_static("noindex, nofollow"),
                );
                response
            }
        }
    } else {
        let mut response = Response::builder()
            .status(404)
            .body(axum::body::Body::from("Subscription Not Found"))
            .unwrap()
            .into_response();
        response.headers_mut().insert(
            "X-Robots-Tag",
            axum::http::HeaderValue::from_static("noindex, nofollow"),
        );
        response
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct CreateVpnAccountPayload {
    pub email: String,
    pub id: String,
    pub total_gb: Option<u64>,
    pub speed_limit: Option<u64>,
    pub expiry_time: Option<i64>,
    pub connection_mode: String,
    pub reality_profile_id: Option<uuid::Uuid>,
    pub custom_reality_profile: Option<CustomRealityProfilePayload>,
    pub sni: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CustomRealityProfilePayload {
    pub name: String,
    pub inbound_tag: String,
    pub listen: String,
    pub port: u16,
    pub dest: String,
    pub server_names: Vec<String>,
    pub private_key: String,
    pub short_ids: Vec<String>,
    pub fingerprint: String,
}

async fn list_reality_profiles(
    State(state): State<Arc<EngineState>>,
) -> Json<Vec<crate::config::RealityProfilePublic>> {
    let config = state.config.read();
    let publics = config
        .reality_profiles
        .iter()
        .map(|p| p.to_public())
        .collect();
    Json(publics)
}

#[derive(Serialize)]
pub struct KeyPairResponse {
    pub private_key: String,
    pub public_key: String,
}

async fn generate_reality_keypair() -> impl IntoResponse {
    let _permit = crate::state::CONTROL_PLANE_CPU.acquire().await;
    use rand::RngCore;
    let mut private_key_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut private_key_bytes);
    let secret = x25519_dalek::StaticSecret::from(private_key_bytes);
    let public = x25519_dalek::PublicKey::from(&secret);

    let private_key = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, private_key_bytes);
    let public_key =
        base64::Engine::encode(&base64::prelude::BASE64_URL_SAFE_NO_PAD, public.as_bytes());

    Json(KeyPairResponse {
        private_key,
        public_key,
    })
}

#[derive(Deserialize)]
pub struct GenerateShortIdPayload {
    pub bytes: Option<usize>,
}

#[derive(Serialize)]
pub struct GenerateShortIdResponse {
    pub short_id: String,
}

async fn generate_reality_short_id(
    Json(payload): Json<GenerateShortIdPayload>,
) -> impl IntoResponse {
    use rand::RngCore;
    let num_bytes = payload.bytes.unwrap_or(8);
    if num_bytes < 1 || num_bytes > 8 {
        return Response::builder()
            .status(axum::http::StatusCode::BAD_REQUEST)
            .body(axum::body::Body::from(
                "Bytes count must be between 1 and 8",
            ))
            .unwrap()
            .into_response();
    }
    let mut r_bytes = vec![0u8; num_bytes];
    rand::rngs::OsRng.fill_bytes(&mut r_bytes);
    let short_id = hex::encode(r_bytes);

    Json(GenerateShortIdResponse { short_id }).into_response()
}

#[derive(Deserialize)]
pub struct ValidateRealityProfilePayload {
    pub dest: String,
    pub server_names: Vec<String>,
    pub private_key: String,
    pub short_ids: Vec<String>,
    pub port: u16,
}

async fn validate_reality_profile(
    Json(payload): Json<ValidateRealityProfilePayload>,
) -> impl IntoResponse {
    match crate::transport::reality::validate_reality_target(
        &payload.dest,
        &payload.server_names,
        &payload.private_key,
        &payload.short_ids,
        payload.port,
    )
    .await
    {
        Ok(result) => Json(result).into_response(),
        Err(e) => {
            let res = crate::transport::reality::ValidationResult {
                valid: false,
                public_key: "".to_string(),
                certificate_names: vec![],
                connect_latency_ms: 0,
                warnings: vec![],
                error: Some(e),
            };
            Json(res).into_response()
        }
    }
}

async fn create_reality_profile(
    State(state): State<Arc<EngineState>>,
    Json(payload): Json<CustomRealityProfilePayload>,
) -> impl IntoResponse {
    let profile = crate::config::RealityProfile {
        id: uuid::Uuid::new_v4(),
        name: payload.name,
        inbound_tag: payload.inbound_tag,
        listen: payload.listen,
        port: payload.port,
        dest: payload.dest,
        server_names: payload.server_names,
        private_key: payload.private_key,
        public_key: "".to_string(),
        short_ids: payload.short_ids,
        fingerprint: payload.fingerprint,
        created_at: chrono::Utc::now().timestamp(),
        updated_at: chrono::Utc::now().timestamp(),
    };

    match state.create_reality_profile_and_listener(profile).await {
        Ok(runtime) => Json(runtime.profile.to_public()).into_response(),
        Err(e) => Response::builder()
            .status(axum::http::StatusCode::BAD_REQUEST)
            .body(axum::body::Body::from(format!(
                "Failed to create reality profile listener: {}",
                e
            )))
            .unwrap()
            .into_response(),
    }
}

async fn create_vpn_account(
    State(state): State<Arc<EngineState>>,
    Json(payload): Json<CreateVpnAccountPayload>,
) -> impl IntoResponse {
    // Check duplicates of user UUID or email in config
    {
        let config = state.config.read();
        for inbound in &config.inbounds {
            if let Some(ref clients) = inbound.settings.clients {
                for client in clients {
                    if client.id == payload.id {
                        return Response::builder()
                            .status(axum::http::StatusCode::CONFLICT)
                            .body(axum::body::Body::from("CONFLICT: User UUID already exists"))
                            .unwrap()
                            .into_response();
                    }
                    if client.email.as_ref() == Some(&payload.email) {
                        return Response::builder()
                            .status(axum::http::StatusCode::CONFLICT)
                            .body(axum::body::Body::from(
                                "CONFLICT: User email already exists",
                            ))
                            .unwrap()
                            .into_response();
                    }
                }
            }
        }
    }

    let (profile_id, inbound_tag) = if payload.connection_mode == "existing_profile" {
        let p_id = match payload.reality_profile_id {
            Some(id) => id,
            None => {
                return Response::builder()
                    .status(axum::http::StatusCode::BAD_REQUEST)
                    .body(axum::body::Body::from(
                        "reality_profile_id is required for existing_profile mode",
                    ))
                    .unwrap()
                    .into_response();
            }
        };

        let config = state.config.read();
        let profile = match config.reality_profiles.iter().find(|p| p.id == p_id) {
            Some(p) => p,
            None => {
                return Response::builder()
                    .status(axum::http::StatusCode::BAD_REQUEST)
                    .body(axum::body::Body::from("Selected reality profile not found"))
                    .unwrap()
                    .into_response();
            }
        };
        (Some(profile.id), Some(profile.inbound_tag.clone()))
    } else if payload.connection_mode == "custom_profile" {
        let custom = match payload.custom_reality_profile {
            Some(ref c) => c,
            None => {
                return Response::builder()
                    .status(axum::http::StatusCode::BAD_REQUEST)
                    .body(axum::body::Body::from(
                        "custom_reality_profile parameters are required for custom_profile mode",
                    ))
                    .unwrap()
                    .into_response();
            }
        };

        // Check duplicate name, tag, or port across profiles and inbounds
        {
            let config = state.config.read();
            for p in &config.reality_profiles {
                if p.name == custom.name
                    || p.port == custom.port
                    || p.inbound_tag == custom.inbound_tag
                {
                    return Response::builder()
                        .status(axum::http::StatusCode::CONFLICT)
                        .body(axum::body::Body::from(
                            "CONFLICT: Duplicate profile name, port, or tag already exists",
                        ))
                        .unwrap()
                        .into_response();
                }
            }
            for inbound in &config.inbounds {
                if inbound.tag == custom.inbound_tag || inbound.port == custom.port {
                    return Response::builder()
                        .status(axum::http::StatusCode::CONFLICT)
                        .body(axum::body::Body::from(
                            "CONFLICT: Duplicate inbound tag or port already exists",
                        ))
                        .unwrap()
                        .into_response();
                }
            }
        }

        // Create new profile
        let profile = crate::config::RealityProfile {
            id: uuid::Uuid::new_v4(),
            name: custom.name.clone(),
            inbound_tag: custom.inbound_tag.clone(),
            listen: custom.listen.clone(),
            port: custom.port,
            dest: custom.dest.clone(),
            server_names: custom.server_names.clone(),
            private_key: custom.private_key.clone(),
            public_key: "".to_string(),
            short_ids: custom.short_ids.clone(),
            fingerprint: custom.fingerprint.clone(),
            created_at: chrono::Utc::now().timestamp(),
            updated_at: chrono::Utc::now().timestamp(),
        };

        let pid_val = profile.id;
        let itag_val = profile.inbound_tag.clone();

        if let Err(e) = state.create_reality_profile_and_listener(profile).await {
            let status = if e.to_string().contains("CONFLICT") {
                axum::http::StatusCode::CONFLICT
            } else {
                axum::http::StatusCode::BAD_REQUEST
            };
            return Response::builder()
                .status(status)
                .body(axum::body::Body::from(format!(
                    "Failed to initialize custom profile: {}",
                    e
                )))
                .unwrap()
                .into_response();
        }
        (Some(pid_val), Some(itag_val))
    } else {
        (None, Some("vless-inbound-443".to_string()))
    };

    let target_tag = inbound_tag
        .clone()
        .unwrap_or_else(|| "vless-inbound-443".to_string());

    // Generate secure random 32-byte token
    let mut token_bytes = [0u8; 32];
    rand::thread_rng().fill(&mut token_bytes);
    let raw_token_hex = hex::encode(token_bytes);

    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(raw_token_hex.as_bytes());
    let hash_bytes = hasher.finalize();
    let hash_hex = hex::encode(hash_bytes);

    // Insert user into config
    let mut config = state.config.read().clone();
    let new_client = Client {
        id: payload.id,
        email: Some(payload.email),
        limit_ip: None,
        total_gb: payload.total_gb,
        expiry_time: payload.expiry_time,
        speed_limit: payload.speed_limit,
        remaining_gb: payload.total_gb.map(|t| t as f64),
        rx: None,
        tx: None,
        reality_profile_id: profile_id,
        inbound_tag: inbound_tag.clone(),
        browsing_warp_id: Some(uuid::Uuid::new_v4().to_string()),
        low_latency_id: Some(uuid::Uuid::new_v4().to_string()),
        sub_token_hash: Some(hash_hex),
        sni: payload.sni,
    };

    let mut added = false;
    for inbound in &mut config.inbounds {
        if inbound.tag == target_tag {
            if let Some(ref mut clients) = inbound.settings.clients {
                if !clients.iter().any(|c| c.id == new_client.id) {
                    clients.push(new_client.clone());
                    added = true;
                }
            } else {
                inbound.settings.clients = Some(vec![new_client.clone()]);
                added = true;
            }
        }
    }

    if !added {
        return Response::builder()
            .status(axum::http::StatusCode::BAD_REQUEST)
            .body(axum::body::Body::from(format!(
                "Target inbound tag '{}' not found in config",
                target_tag
            )))
            .unwrap()
            .into_response();
    }

    if let Err(e) = state.update_config(config) {
        return Response::builder()
            .status(axum::http::StatusCode::BAD_REQUEST)
            .body(axum::body::Body::from(format!(
                "Failed to update config: {}",
                e
            )))
            .unwrap()
            .into_response();
    }
    state.disconnect_user(&new_client.id);
    state.persist_config_to_disk();

    Json(serde_json::json!({
        "success": true,
        "sub_token": raw_token_hex
    }))
    .into_response()
}

// System stats reporting
#[derive(serde::Serialize)]
pub struct SystemStats {
    pub cpu_percent: f64,
    pub system_load: f64,
    pub ram_used_gb: f64,
    pub ram_total_gb: f64,
    pub ram_percent: f64,
    pub uptime_secs: u64,
}

pub fn get_system_stats(state: Option<&crate::state::EngineState>) -> SystemStats {
    let uptime_str = std::fs::read_to_string("/proc/uptime").unwrap_or_else(|_| "0 0".to_string());
    let uptime_secs = uptime_str
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0) as u64;

    let mut mem_total = 0.0;
    let mut mem_avail = 0.0;
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                if let Some(val) = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<f64>().ok())
                {
                    mem_total = val * 1024.0;
                }
            } else if line.starts_with("MemAvailable:") {
                if let Some(val) = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<f64>().ok())
                {
                    mem_avail = val * 1024.0;
                }
            }
        }
    }
    if mem_avail == 0.0 {
        mem_avail = mem_total * 0.5;
    }
    let ram_used = mem_total - mem_avail;
    let ram_percent = if mem_total > 0.0 {
        (ram_used / mem_total) * 100.0
    } else {
        0.0
    };

    let (cpu_percent, _, _) = if let Ok(stat_str) = std::fs::read_to_string("/proc/stat") {
        if let Some(first_line) = stat_str.lines().next() {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 5 && parts[0] == "cpu" {
                let user: u64 = parts[1].parse().unwrap_or(0);
                let nice: u64 = parts[2].parse().unwrap_or(0);
                let system: u64 = parts[3].parse().unwrap_or(0);
                let idle: u64 = parts[4].parse().unwrap_or(0);
                let iowait: u64 = parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);
                let irq: u64 = parts.get(6).and_then(|s| s.parse().ok()).unwrap_or(0);
                let softirq: u64 = parts.get(7).and_then(|s| s.parse().ok()).unwrap_or(0);
                let steal: u64 = parts.get(8).and_then(|s| s.parse().ok()).unwrap_or(0);

                let total = user + nice + system + idle + iowait + irq + softirq + steal;
                let idle_all = idle + iowait;

                if let Some(s) = state {
                    let prev_total = s.last_cpu_total_ticks.load(Ordering::Relaxed);
                    let prev_idle = s.last_cpu_idle_ticks.load(Ordering::Relaxed);

                    s.last_cpu_total_ticks.store(total, Ordering::Relaxed);
                    s.last_cpu_idle_ticks.store(idle_all, Ordering::Relaxed);

                    if prev_total > 0 && total > prev_total {
                        let total_diff = total - prev_total;
                        let idle_diff = idle_all - prev_idle;
                        let cpu_val = 100.0 * (1.0 - (idle_diff as f64 / total_diff as f64));
                        (cpu_val.clamp(0.0, 100.0), total, idle_all)
                    } else {
                        (0.0, total, idle_all)
                    }
                } else {
                    (0.0, total, idle_all)
                }
            } else {
                (0.0, 0, 0)
            }
        } else {
            (0.0, 0, 0)
        }
    } else {
        (0.0, 0, 0)
    };

    let loadavg = std::fs::read_to_string("/proc/loadavg").unwrap_or_else(|_| "0.0".to_string());
    let system_load = loadavg
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);

    SystemStats {
        cpu_percent,
        system_load,
        ram_used_gb: ram_used / 1_073_741_824.0,
        ram_total_gb: mem_total / 1_073_741_824.0,
        ram_percent,
        uptime_secs,
    }
}

pub async fn get_dashboard(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<EngineState>>,
) -> Response {
    let cached = state.cached_dashboard.load();

    if let Some(if_none_match) = headers.get(axum::http::header::IF_NONE_MATCH) {
        if if_none_match.to_str().unwrap_or("") == cached.etag.as_ref() {
            return Response::builder()
                .status(axum::http::StatusCode::NOT_MODIFIED)
                .header(axum::http::header::ETAG, cached.etag.as_ref())
                .header("X-Dashboard-Generation", cached.generation.to_string())
                .header(
                    "X-Dashboard-Age-Ms",
                    cached.generated_at.elapsed().as_millis().to_string(),
                )
                .body(axum::body::Body::empty())
                .unwrap();
        }
    }

    let is_stale = cached.generated_at.elapsed().as_secs() > 30;

    let mut builder = Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(
            axum::http::header::CACHE_CONTROL,
            "private, no-cache, must-revalidate",
        )
        .header(axum::http::header::ETAG, cached.etag.as_ref())
        .header("X-Dashboard-Generation", cached.generation.to_string())
        .header(
            "X-Dashboard-Age-Ms",
            cached.generated_at.elapsed().as_millis().to_string(),
        );

    if is_stale {
        builder = builder.header("X-Dashboard-Stale", "true");
    }

    builder
        .body(axum::body::Body::from(cached.body.clone()))
        .unwrap()
}

pub async fn get_connections_monitor_data(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<EngineState>>,
) -> Response {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    state
        .connections_monitor_last_request_ms
        .store(now, std::sync::atomic::Ordering::Relaxed);

    let cached = state.cached_connections.load();

    if let Some(if_none_match) = headers.get(axum::http::header::IF_NONE_MATCH) {
        if if_none_match.to_str().unwrap_or("") == cached.etag.as_ref() {
            return Response::builder()
                .status(axum::http::StatusCode::NOT_MODIFIED)
                .header(axum::http::header::ETAG, cached.etag.as_ref())
                .header("X-Dashboard-Generation", cached.generation.to_string())
                .header(
                    "X-Dashboard-Age-Ms",
                    cached.generated_at.elapsed().as_millis().to_string(),
                )
                .body(axum::body::Body::empty())
                .unwrap();
        }
    }

    let is_stale = cached.generated_at.elapsed().as_secs() > 30;

    let mut builder = Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(
            axum::http::header::CACHE_CONTROL,
            "private, no-cache, must-revalidate",
        )
        .header(axum::http::header::ETAG, cached.etag.as_ref())
        .header("X-Dashboard-Generation", cached.generation.to_string())
        .header(
            "X-Dashboard-Age-Ms",
            cached.generated_at.elapsed().as_millis().to_string(),
        );

    if is_stale {
        builder = builder.header("X-Dashboard-Stale", "true");
    }

    builder
        .body(axum::body::Body::from(cached.body.clone()))
        .unwrap()
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn serve_connections_monitor() -> impl IntoResponse {
    Html(CONNECTIONS_MONITOR_HTML)
}

static CONNECTIONS_MONITOR_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rust Tunnel: Connection Monitor</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #07070a;
            --card-bg: rgba(18, 18, 29, 0.75);
            --border-color: rgba(255, 255, 255, 0.08);
            --primary: #6366f1;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --success: #10b981;
            --secondary: #3b82f6;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Outfit', sans-serif; }
        body {
            background: var(--bg-dark);
            color: var(--text-main);
            padding: 40px 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        h1 { font-size: 1.8rem; font-weight: 700; }
        .btn {
            background: var(--primary);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 10px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
        }
        .btn:hover { background: #4f46e5; transform: translateY(-1px); }
        .btn-secondary { background: rgba(255,255,255,0.05); border: 1px solid var(--border-color); color: var(--text-main); }
        .btn-secondary:hover { background: rgba(255,255,255,0.1); }
        .panel-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            backdrop-filter: blur(12px);
            border-radius: 16px;
            padding: 1.75rem;
        }
        .table-container { width: 100%; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
        th {
            color: var(--text-muted);
            font-weight: 500;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.5px;
        }
        td { padding: 1rem; border-bottom: 1px solid var(--border-color); color: var(--text-muted); }
        tr:last-child td { border-bottom: none; }
        .dest-highlight { color: #f3f4f6; font-weight: 500; }
        .sni-badge {
            background: rgba(99, 102, 241, 0.1);
            color: #a5b4fc;
            padding: 2px 8px;
            border-radius: 6px;
            font-size: 0.8rem;
            border: 1px solid rgba(99, 102, 241, 0.2);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Live Connection Monitoring</h1>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 5px;">Active network tunnels connected to this core</p>
            </div>
            <div style="display: flex; gap: 15px;">
                <a href="/" class="btn">Back to Dashboard</a>
            </div>
        </header>
        <div class="panel-card">
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Client IP</th>
                            <th>Destination Address</th>
                            <th>Sniffed SNI</th>
                            <th>Outbound Route</th>
                            <th>Usage</th>
                            <th>Uptime</th>
                        </tr>
                    </thead>
                    <tbody id="connections-table-body">
                        <tr>
                            <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 3rem 0;">No active connections running</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <script>
        function formatBytes(bytes, decimals = 2) {
            if (bytes === 0) return '0.00 B';
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
        }

        function formatDuration(seconds) {
            if (seconds < 60) return `${seconds}s`;
            const minutes = Math.floor(seconds / 60);
            if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
            const hours = Math.floor(minutes / 60);
            return `${hours}h ${minutes % 60}m`;
        }

        let inFlight = false;
        let controller = null;
        let timerId = null;
        let lastEtag = "";

        async function updateConnections() {
            if (inFlight || document.hidden) return;
            inFlight = true;

            if (controller) controller.abort();
            controller = new AbortController();

            try {
                const headers = {};
                if (lastEtag) {
                    headers['If-None-Match'] = lastEtag;
                }
                const connsRes = await fetch('/api/connections-monitor/data', {
                    signal: controller.signal,
                    headers: headers
                });

                if (connsRes.status === 304) {
                    inFlight = false;
                    scheduleNext();
                    return;
                }

                if (!connsRes.ok) {
                    throw new Error("Failed to fetch connections data");
                }

                const etagVal = connsRes.headers.get('ETag');
                if (etagVal) lastEtag = etagVal;

                const data = await connsRes.json();
                const conns = data.connections || [];
                const connsBody = document.getElementById('connections-table-body');
                if (conns.length === 0) {
                    connsBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 3rem 0;">No active connections running</td></tr>`;
                } else {
                    connsBody.innerHTML = conns.map(c => `
                        <tr>
                            <td>${c.client_ip}</td>
                            <td class="dest-highlight">${c.dest_address}</td>
                            <td>${c.sni ? `<span class="sni-badge">${c.sni}</span>` : '-'}</td>
                            <td><span style="font-weight: 600; color: #a5b4fc;">${c.outbound_tag}</span></td>
                            <td>
                                <div>Rx: <span style="color: var(--success)">${formatBytes(c.rx)}</span></div>
                                <div>Tx: <span style="color: var(--secondary)">${formatBytes(c.tx)}</span></div>
                            </td>
                            <td>${formatDuration(c.uptime_secs)}</td>
                        </tr>
                    `).join('');
                }
            } catch (e) {
                if (e.name !== 'AbortError') {
                    console.error("Failed to update connections:", e);
                }
            } finally {
                inFlight = false;
                scheduleNext();
            }
        }

        function scheduleNext() {
            if (timerId) clearTimeout(timerId);
            if (!document.hidden) {
                timerId = setTimeout(updateConnections, 5000);
            }
        }

        document.addEventListener("visibilitychange", () => {
            if (document.hidden) {
                if (timerId) clearTimeout(timerId);
                if (controller) controller.abort();
                inFlight = false;
            } else {
                updateConnections();
            }
        });

        updateConnections();
    </script>
</body>
</html>
"#;

// --- Admin Portal Auth and Routing CRUD Handlers ---

use rand::Rng;

#[derive(Deserialize)]
struct LoginPayload {
    password: String,
}

static LOGIN_LIMITER: once_cell::sync::Lazy<crate::auth::LoginRateLimiter> =
    once_cell::sync::Lazy::new(|| crate::auth::LoginRateLimiter::new());

async fn login_handler(
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    State(state): State<Arc<EngineState>>,
    Json(payload): Json<LoginPayload>,
) -> impl IntoResponse {
    let client_ip = get_client_ip(&headers, addr, &state);



    if !LOGIN_LIMITER.is_allowed(client_ip) {
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "Too many failed attempts. Please try again in 5 minutes.",
        )
            .into_response();
    }

    let auth_cached = match state.admin_auth.load().as_ref() {
        Some(a) => Arc::clone(a),
        None => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Admin credentials not initialized.",
            )
                .into_response();
        }
    };

    let _permit = match crate::auth::ADMIN_AUTH_CPU.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            return (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "Server busy, please try again shortly.",
            )
                .into_response();
        }
    };

    let hash_clone = auth_cached.password_hash.clone();
    let pass_clone = payload.password;
    let is_valid = match tokio::task::spawn_blocking(move || {
        crate::auth::verify_password(&hash_clone, &pass_clone)
    })
    .await
    {
        Ok(Ok(ok)) => ok,
        _ => false,
    };

    if !is_valid {
        LOGIN_LIMITER.record_failure(client_ip);
        return (axum::http::StatusCode::UNAUTHORIZED, "Invalid password.").into_response();
    }

    LOGIN_LIMITER.record_success(client_ip);

    let mut csrf_bytes = [0u8; 32];
    rand::thread_rng().fill(&mut csrf_bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let claims = crate::auth::AdminSessionClaims {
        version: 1,
        issued_at: now,
        expires_at: now + 3600 * 24,
        session_epoch: auth_cached.session_epoch,
        csrf_token: csrf_bytes,
    };

    let cookie_val = match crate::auth::encode_session_cookie(&claims, &auth_cached.session_secret)
    {
        Ok(val) => val,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate session cookie.",
            )
                .into_response();
        }
    };

    let is_loopback = client_ip.is_loopback();
    let is_https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("https"))
        .unwrap_or(false);
    let secure_flag = if is_loopback || !is_https {
        ""
    } else {
        "; Secure"
    };
    let cookie_header = format!(
        "ruve_session={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}{}",
        cookie_val,
        3600 * 24,
        secure_flag
    );

    let csrf_hex = hex::encode(csrf_bytes);

    Response::builder()
        .header(axum::http::header::SET_COOKIE, cookie_header)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(format!(
            "{{\"csrf_token\":\"{}\"}}",
            csrf_hex
        )))
        .unwrap()
        .into_response()
}

async fn logout_handler(
    State(state): State<Arc<EngineState>>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let client_ip = get_client_ip(&headers, addr, &state);
    let is_loopback = client_ip.is_loopback();
    let is_https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("https"))
        .unwrap_or(false);
    let cookie_header = if is_loopback || !is_https {
        "ruve_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
    } else {
        "ruve_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
    };
    Response::builder()
        .header(axum::http::header::SET_COOKIE, cookie_header)
        .body(axum::body::Body::from("Logged out"))
        .unwrap()
        .into_response()
}

#[derive(Deserialize)]
struct ChangePasswordPayload {
    current_password: String,
    new_password: String,
}

async fn change_password_handler(
    State(state): State<Arc<EngineState>>,
    Json(payload): Json<ChangePasswordPayload>,
) -> impl IntoResponse {
    let auth_cached = match state.admin_auth.load().as_ref() {
        Some(a) => Arc::clone(a),
        None => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Credentials not initialized",
            )
                .into_response()
        }
    };

    let hash_clone = auth_cached.password_hash.clone();
    let cur_pass = payload.current_password;
    let is_valid = match tokio::task::spawn_blocking(move || {
        crate::auth::verify_password(&hash_clone, &cur_pass)
    })
    .await
    {
        Ok(Ok(ok)) => ok,
        _ => false,
    };

    if !is_valid {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            "Incorrect current password.",
        )
            .into_response();
    }

    if let Err(err_msg) = crate::auth::validate_password_rules(&payload.new_password) {
        return (axum::http::StatusCode::BAD_REQUEST, err_msg).into_response();
    }

    let _permit = match crate::auth::ADMIN_AUTH_CPU.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            return (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "Server busy, please try again shortly.",
            )
                .into_response();
        }
    };

    let new_pass = payload.new_password;
    let hashed_res =
        tokio::task::spawn_blocking(move || crate::auth::hash_password(&new_pass)).await;

    let new_hash = match hashed_res {
        Ok(Ok(h)) => h,
        _ => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to hash new password",
            )
                .into_response()
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let new_creds = crate::auth::AdminCredentials {
        password_hash: new_hash,
        session_secret: crate::auth::generate_random_secret(),
        session_epoch: auth_cached.session_epoch + 1,
        created_at: now,
        updated_at: now,
        version: 1,
    };

    if let Err(e) = crate::auth::save_admin_credentials(&new_creds) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save credentials: {}", e),
        )
            .into_response();
    }

    let runtime = crate::auth::AdminAuthRuntime {
        password_hash: Arc::from(new_creds.password_hash),
        session_secret: Arc::from(hex::decode(&new_creds.session_secret).unwrap_or_default()),
        session_epoch: new_creds.session_epoch,
    };

    state.admin_auth.store(Some(Arc::new(runtime)));

    (
        axum::http::StatusCode::OK,
        "Password updated successfully. All sessions invalidated.",
    )
        .into_response()
}

async fn session_check_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "authenticated": true }))
}

async fn admin_auth_middleware(
    State(state): State<Arc<EngineState>>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<Response, Response> {
    let cookie_header = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut session_cookie = "";
    for cookie in cookie_header.split(';') {
        let parts: Vec<&str> = cookie.split('=').map(|s| s.trim()).collect();
        if parts.len() == 2 && parts[0] == "ruve_session" {
            session_cookie = parts[1];
            break;
        }
    }

    if session_cookie.is_empty() {
        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            "Unauthorized: Session cookie missing",
        )
            .into_response());
    }

    let auth_cached = match state.admin_auth.load().as_ref() {
        Some(a) => Arc::clone(a),
        None => {
            return Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Credentials not initialized",
            )
                .into_response())
        }
    };

    let claims =
        match crate::auth::decode_and_verify_session(session_cookie, &auth_cached.session_secret) {
            Ok(c) => c,
            Err(_) => {
                return Err((
                    axum::http::StatusCode::UNAUTHORIZED,
                    "Unauthorized: Invalid session token",
                )
                    .into_response())
            }
        };

    if claims.session_epoch != auth_cached.session_epoch {
        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            "Unauthorized: Session epoch invalidated",
        )
            .into_response());
    }

    let method = req.method();
    if method == axum::http::Method::POST
        || method == axum::http::Method::PUT
        || method == axum::http::Method::DELETE
    {
        let csrf_header = headers
            .get("X-CSRF-Token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let expected_csrf = hex::encode(claims.csrf_token);
        if csrf_header != expected_csrf {
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                "Forbidden: CSRF validation failed",
            )
                .into_response());
        }
    }

    Ok(next.run(req).await)
}

#[derive(Deserialize)]
pub struct RoutingSetPayload {
    pub name: String,
    pub description: String,
    pub exact_domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub enabled: bool,
    pub priority: i32,
}

// Warp Domain Sets CRUD handlers
async fn list_warp_sets(State(state): State<Arc<EngineState>>) -> impl IntoResponse {
    let config = state.config.read();
    Json(config.warp_domain_sets.clone()).into_response()
}

async fn create_warp_set(
    State(state): State<Arc<EngineState>>,
    Json(payload): Json<RoutingSetPayload>,
) -> impl IntoResponse {
    let mut config = state.config.read().clone();
    let new_set = crate::config::WarpDomainSet {
        id: uuid::Uuid::new_v4(),
        name: payload.name,
        description: payload.description,
        exact_domains: payload.exact_domains,
        domain_suffixes: payload.domain_suffixes,
        enabled: payload.enabled,
        priority: payload.priority,
        scope: crate::config::DomainRuleScope::Global,
        created_at: chrono::Utc::now().timestamp(),
        updated_at: chrono::Utc::now().timestamp(),
    };
    config.warp_domain_sets.push(new_set.clone());
    state.apply_routing_update(config);
    Json(new_set).into_response()
}

async fn update_warp_set(
    Path(id): Path<uuid::Uuid>,
    State(state): State<Arc<EngineState>>,
    Json(payload): Json<RoutingSetPayload>,
) -> impl IntoResponse {
    let mut config = state.config.read().clone();
    if let Some(set) = config.warp_domain_sets.iter_mut().find(|s| s.id == id) {
        set.name = payload.name;
        set.description = payload.description;
        set.exact_domains = payload.exact_domains;
        set.domain_suffixes = payload.domain_suffixes;
        set.enabled = payload.enabled;
        set.priority = payload.priority;
        set.updated_at = chrono::Utc::now().timestamp();
        let updated = set.clone();
        state.apply_routing_update(config);
        Json(updated).into_response()
    } else {
        (axum::http::StatusCode::NOT_FOUND, "Routing set not found").into_response()
    }
}

async fn delete_warp_set(
    Path(id): Path<uuid::Uuid>,
    State(state): State<Arc<EngineState>>,
) -> impl IntoResponse {
    let mut config = state.config.read().clone();
    let initial_len = config.warp_domain_sets.len();
    config.warp_domain_sets.retain(|s| s.id != id);
    if config.warp_domain_sets.len() < initial_len {
        state.apply_routing_update(config);
        Json(true).into_response()
    } else {
        (axum::http::StatusCode::NOT_FOUND, "Routing set not found").into_response()
    }
}

// Direct Exception Sets CRUD handlers
async fn list_direct_sets(State(state): State<Arc<EngineState>>) -> impl IntoResponse {
    let config = state.config.read();
    Json(config.direct_exception_sets.clone()).into_response()
}

async fn create_direct_set(
    State(state): State<Arc<EngineState>>,
    Json(payload): Json<RoutingSetPayload>,
) -> impl IntoResponse {
    let mut config = state.config.read().clone();
    let new_set = crate::config::DirectExceptionSet {
        id: uuid::Uuid::new_v4(),
        name: payload.name,
        description: payload.description,
        exact_domains: payload.exact_domains,
        domain_suffixes: payload.domain_suffixes,
        enabled: payload.enabled,
        priority: payload.priority,
        scope: crate::config::DomainRuleScope::Global,
        created_at: chrono::Utc::now().timestamp(),
        updated_at: chrono::Utc::now().timestamp(),
    };
    config.direct_exception_sets.push(new_set.clone());
    state.apply_routing_update(config);
    Json(new_set).into_response()
}

async fn update_direct_set(
    Path(id): Path<uuid::Uuid>,
    State(state): State<Arc<EngineState>>,
    Json(payload): Json<RoutingSetPayload>,
) -> impl IntoResponse {
    let mut config = state.config.read().clone();
    if let Some(set) = config.direct_exception_sets.iter_mut().find(|s| s.id == id) {
        set.name = payload.name;
        set.description = payload.description;
        set.exact_domains = payload.exact_domains;
        set.domain_suffixes = payload.domain_suffixes;
        set.enabled = payload.enabled;
        set.priority = payload.priority;
        set.updated_at = chrono::Utc::now().timestamp();
        let updated = set.clone();
        state.apply_routing_update(config);
        Json(updated).into_response()
    } else {
        (axum::http::StatusCode::NOT_FOUND, "Routing set not found").into_response()
    }
}

async fn delete_direct_set(
    Path(id): Path<uuid::Uuid>,
    State(state): State<Arc<EngineState>>,
) -> impl IntoResponse {
    let mut config = state.config.read().clone();
    let initial_len = config.direct_exception_sets.len();
    config.direct_exception_sets.retain(|s| s.id != id);
    if config.direct_exception_sets.len() < initial_len {
        state.apply_routing_update(config);
        Json(true).into_response()
    } else {
        (axum::http::StatusCode::NOT_FOUND, "Routing set not found").into_response()
    }
}
