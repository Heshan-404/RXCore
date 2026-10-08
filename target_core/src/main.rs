use std::sync::Arc;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub use target_core::{api, config, inbound, state, transport};

struct UserTempStats {
    id: String,
    email: Option<String>,
    limit_ip: u32,
    total_gb: i64,
    expiry_time: i64,
    speed_limit: u64,
    remaining_bytes: i64,
    rx: u64,
    tx: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().collect();
    if target_core::auth::handle_admin_cli(&args)? {
        return Ok(());
    }

    let creds_opt = target_core::auth::load_admin_credentials()?;
    if creds_opt.is_none() {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            println!("Ruve VPN Administrator Setup");
            println!("Create a password for the administration dashboard.\n");
            let password = target_core::auth::prompt_password_interactive()?;
            let hash = target_core::auth::hash_password(&password)?;
            let secret = target_core::auth::generate_random_secret();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let new_creds = target_core::auth::AdminCredentials {
                password_hash: hash,
                session_secret: secret,
                session_epoch: 1,
                created_at: now,
                updated_at: now,
                version: 1,
            };
            target_core::auth::save_admin_credentials(&new_creds)?;
            println!("Administrator credentials initialized successfully!");
        } else {
            let hash = target_core::auth::hash_password("admin")?;
            let secret = target_core::auth::generate_random_secret();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let new_creds = target_core::auth::AdminCredentials {
                password_hash: hash,
                session_secret: secret,
                session_epoch: 1,
                created_at: now,
                updated_at: now,
                version: 1,
            };
            target_core::auth::save_admin_credentials(&new_creds)?;
            println!("Administrator credentials auto-initialized with default password 'admin'.");
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(4)
        .thread_keep_alive(std::time::Duration::from_secs(10))
        .enable_all()
        .build()?;

    runtime.block_on(async {
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
                        "server_name": "aks.ms",
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
            "listen": "127.0.0.1",
            "port": 9091
        }
    }
    "#;

        let config_path = std::path::Path::new("config.json");
        let mut initial_config: config::Config = if config_path.exists() {
            info!("Loading configuration from config.json");
            let content = std::fs::read_to_string(config_path)?;
            serde_json::from_str(&content)?
        } else {
            info!("Using default built-in configuration");
            serde_json::from_str(default_config_json)?
        };

        let migrated = initial_config.migrate_if_needed();

        initial_config
            .validate_and_normalize()
            .map_err(|e| format!("Configuration validation failed: {}", e))?;

        for profile in &initial_config.reality_profiles {
            let dest = &profile.dest;
            let sni = profile.server_names.first().ok_or_else(|| {
                Box::<dyn std::error::Error + Send + Sync>::from(
                    "Reality profile server_names cannot be empty",
                )
            })?;
            info!("Performing TLS preflight check to {} for SNI {}", dest, sni);
            crate::transport::reality::preflight_reality_check(dest, sni).await?;
            info!("Preflight check to {} for SNI {} succeeded", dest, sni);
        }

        let api_listen = initial_config.api.listen;
        let api_port = initial_config.api.port;

        let (engine, rx) = state::EngineState::new(initial_config);
        let engine_state = Arc::new(engine);
        state::start_persistence_worker(Arc::clone(&engine_state), rx);

        if migrated {
            engine_state.persist_config_to_disk();
        }

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

        // Optional event loop lag monitor recording wake-up delays
        let engine_lag = Arc::clone(&engine_state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(50));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_tick = tokio::time::Instant::now();
            let mut last_report = tokio::time::Instant::now();
            let mut last_warn_log = tokio::time::Instant::now();
            let mut last_critical_log = tokio::time::Instant::now();

            loop {
                interval.tick().await;
                let now = tokio::time::Instant::now();
                let elapsed = now.duration_since(last_tick);
                last_tick = now;

                if elapsed > std::time::Duration::from_millis(50) {
                    let lag = elapsed - std::time::Duration::from_millis(50);
                    let lag_ms = lag.as_millis();

                    let mut current_max = engine_lag
                        .maximum_lag_ms
                        .load(std::sync::atomic::Ordering::Relaxed);
                    while lag_ms as u64 > current_max {
                        match engine_lag.maximum_lag_ms.compare_exchange_weak(
                            current_max,
                            lag_ms as u64,
                            std::sync::atomic::Ordering::Relaxed,
                            std::sync::atomic::Ordering::Relaxed,
                        ) {
                            Ok(_) => break,
                            Err(actual) => current_max = actual,
                        }
                    }

                    if lag_ms >= 50 {
                        engine_lag.recent_event_loop_lag_ms.store(lag_ms as u64, std::sync::atomic::Ordering::Relaxed);
                        let epoch = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        engine_lag.last_lag_event_epoch_ms.store(epoch, std::sync::atomic::Ordering::Relaxed);
                    }

                    if lag_ms >= 250 {
                        engine_lag
                            .lag_250ms_count
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if now.duration_since(last_critical_log) >= std::time::Duration::from_secs(10) {
                            tracing::warn!("Event loop lag: {} ms (CRITICAL)", lag_ms);
                            last_critical_log = now;
                        }
                    } else if lag_ms >= 100 {
                        engine_lag
                            .lag_100ms_count
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if now.duration_since(last_warn_log) >= std::time::Duration::from_secs(10) {
                            tracing::warn!("Event loop lag: {} ms (HIGH)", lag_ms);
                            last_warn_log = now;
                        }
                    } else if lag_ms >= 50 {
                        engine_lag
                            .lag_50ms_count
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    } else if lag_ms >= 10 {
                        engine_lag
                            .lag_10ms_count
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }

                if now.duration_since(last_report) >= std::time::Duration::from_secs(60) {
                    let c10 = engine_lag.lag_10ms_count.swap(0, std::sync::atomic::Ordering::Relaxed);
                    let c50 = engine_lag.lag_50ms_count.swap(0, std::sync::atomic::Ordering::Relaxed);
                    let c100 = engine_lag.lag_100ms_count.swap(0, std::sync::atomic::Ordering::Relaxed);
                    let c250 = engine_lag.lag_250ms_count.swap(0, std::sync::atomic::Ordering::Relaxed);
                    let max_l = engine_lag.maximum_lag_ms.swap(0, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!(
                        "Event-loop report: 10ms={}, 50ms={}, 100ms={}, 250ms={}, max={}ms",
                        c10, c50, c100, c250, max_l
                    );
                    last_report = now;
                }
            }
        });

        // Spawn background config persistence task
        let state_persist = Arc::clone(&engine_state);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                if state_persist
                    .dirty
                    .swap(false, std::sync::atomic::Ordering::Relaxed)
                {
                    state_persist.persist_config_to_disk();
                }
            }
        });

        // Spawn background dashboard snapshot task (every 5 seconds)
        let state_dash = Arc::clone(&engine_state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut generation = 0u64;

            loop {
                interval.tick().await;

                // 1. Check event-loop pressure (last 10 seconds)
                let now_epoch = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let last_lag_epoch = state_dash.last_lag_event_epoch_ms.load(std::sync::atomic::Ordering::Relaxed);
                let last_lag_val = state_dash.recent_event_loop_lag_ms.load(std::sync::atomic::Ordering::Relaxed);
                let current_lag = if now_epoch.saturating_sub(last_lag_epoch) < 10_000 {
                    last_lag_val
                } else {
                    0
                };
                if current_lag >= 50 {
                    state_dash.dashboard_build_skipped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                }

                // 2. Check connection monitor visibility (last 30 seconds)
                let last_conn_req = state_dash.connections_monitor_last_request_ms.load(std::sync::atomic::Ordering::Relaxed);
                let has_never_generated = state_dash.cached_connections.load().generation == 0;
                let needs_connections = has_never_generated || (now_epoch.saturating_sub(last_conn_req) < 30_000);

                // 3. Try to acquire DASHBOARD_BUILD semaphore permit
                let permit = match state_dash.dashboard_build_semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        state_dash.dashboard_build_skipped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                };

                let start_time = std::time::Instant::now();

                // 4. Collect state with try_read() separately in an optimized manner
                let users_data_res = match state_dash.users.try_read() {
                    Some(users_guard) => {
                        let mut unique_users = std::collections::HashMap::new();
                        for user in users_guard.values() {
                            unique_users.insert(user.0.id.clone(), Arc::clone(&user.0));
                        }
                        let total_users_count = unique_users.len();
                        let mut users_raw = Vec::with_capacity(total_users_count);
                        for user in unique_users.values() {
                            users_raw.push(UserTempStats {
                                id: user.id.clone(),
                                email: user.email.read().clone(),
                                limit_ip: user.limit_ip.load(std::sync::atomic::Ordering::Relaxed),
                                total_gb: user.total_gb.load(std::sync::atomic::Ordering::Relaxed),
                                expiry_time: user.expiry_time.load(std::sync::atomic::Ordering::Relaxed),
                                speed_limit: user.speed_limit.load(std::sync::atomic::Ordering::Relaxed),
                                remaining_bytes: user.remaining_bytes.load(std::sync::atomic::Ordering::Relaxed),
                                rx: user.rx.load(std::sync::atomic::Ordering::Relaxed),
                                tx: user.tx.load(std::sync::atomic::Ordering::Relaxed),
                            });
                        }
                        Some((users_raw, total_users_count))
                    }
                    None => {
                        state_dash.dashboard_build_skipped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                };
                let (users_raw, total_users_count) = match users_data_res {
                    Some(val) => val,
                    None => continue,
                };

                let (total_active_connections, visible_connections_monitor) = match state_dash.active_connections.try_read() {
                    Some(conns_guard) => {
                        let total = conns_guard.len();
                        let mut list_monitor = Vec::new();
                        if needs_connections {
                            list_monitor.reserve(total.min(200));
                            for conn in conns_guard.values().take(200) {
                                list_monitor.push(crate::api::ConnectionResponse {
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
                        }
                        (total, list_monitor)
                    }
                    None => {
                        state_dash.dashboard_build_skipped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                };

                let lag_10 = state_dash.lag_10ms_count.load(std::sync::atomic::Ordering::Relaxed);
                let lag_50 = state_dash.lag_50ms_count.load(std::sync::atomic::Ordering::Relaxed);
                let lag_100 = state_dash.lag_100ms_count.load(std::sync::atomic::Ordering::Relaxed);
                let lag_250 = state_dash.lag_250ms_count.load(std::sync::atomic::Ordering::Relaxed);
                let max_lag = state_dash.maximum_lag_ms.load(std::sync::atomic::Ordering::Relaxed);

                generation += 1;
                let current_gen = generation;
                let state_dash_blocking = Arc::clone(&state_dash);

                // 5. Run in one blocking task
                let res = tokio::task::spawn_blocking(move || {
                    state_dash_blocking.active_blocking_tasks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let _guard = crate::state::BlockingTaskGuard(&state_dash_blocking.active_blocking_tasks);
                    let sys = crate::api::get_system_stats(Some(&state_dash_blocking));
                    let timestamp = chrono::Utc::now().timestamp() as u64;

                    // Compute stats, sort and truncate inside blocking task
                    let mut sum_rx = 0;
                    let mut sum_tx = 0;
                    let mut users_all = users_raw;
                    users_all.sort_by(|a, b| {
                        a.email.cmp(&b.email)
                    });

                    let mut list = Vec::with_capacity(users_all.len().min(100));
                    for user in users_all {
                        sum_rx += user.rx;
                        sum_tx += user.tx;

                        if list.len() < 100 {
                            let remaining_gb = if user.remaining_bytes == -1 {
                                None
                            } else {
                                Some(user.remaining_bytes as f64 / 1_073_741_824.0)
                            };
                            let total_gb = if user.total_gb == -1 { None } else { Some(user.total_gb as u64) };

                            list.push(crate::api::UserInfoResponse {
                                id: user.id,
                                email: user.email,
                                limit_ip: if user.limit_ip > 0 { Some(user.limit_ip) } else { None },
                                total_gb,
                                expiry_time: if user.expiry_time > 0 { Some(user.expiry_time) } else { None },
                                speed_limit: if user.speed_limit > 0 { Some(user.speed_limit) } else { None },
                                remaining_gb,
                                rx: user.rx,
                                tx: user.tx,
                            });
                        }
                    }

                    let dash_snapshot = crate::state::DashboardSnapshot {
                        cpu_percent: sys.cpu_percent,
                        ram_used_gb: sys.ram_used_gb,
                        ram_total_gb: sys.ram_total_gb,
                        ram_percent: sys.ram_percent,
                        uptime_secs: sys.uptime_secs,
                        active_connections: total_active_connections,
                        total_users: total_users_count,
                        total_rx: sum_rx,
                        total_tx: sum_tx,
                        lag_10ms_count: lag_10,
                        lag_50ms_count: lag_50,
                        lag_100ms_count: lag_100,
                        lag_250ms_count: lag_250,
                        maximum_lag_ms: max_lag,
                        users: list,
                        timestamp,
                        event_loop_lag_ms: current_lag,
                        dashboard_build_duration_ms: state_dash_blocking.dashboard_build_duration_ms.load(std::sync::atomic::Ordering::Relaxed),
                        dashboard_build_skipped: state_dash_blocking.dashboard_build_skipped.load(std::sync::atomic::Ordering::Relaxed),
                        dashboard_build_errors: state_dash_blocking.dashboard_build_errors.load(std::sync::atomic::Ordering::Relaxed),
                        active_blocking_operations: state_dash_blocking.active_blocking_tasks.load(std::sync::atomic::Ordering::Relaxed),
                    };

                    let dash_json = serde_json::to_vec(&dash_snapshot)?;
                    let dash_etag = format!("\"dash-{}-{}\"", current_gen, timestamp);

                    let monitor_update = if needs_connections {
                        let monitor_snapshot = crate::state::ConnectionsMonitorSnapshot {
                            connections: visible_connections_monitor,
                            total_connections: total_active_connections,
                            timestamp,
                        };
                        let monitor_json = serde_json::to_vec(&monitor_snapshot)?;
                        let monitor_etag = format!("\"conns-{}-{}\"", current_gen, timestamp);
                        Some((monitor_json, monitor_etag))
                    } else {
                        None
                    };

                    Ok::<_, serde_json::Error>((dash_json, dash_etag, monitor_update))
                })
                .await;

                drop(permit);

                match res {
                    Ok(Ok((dash_json, dash_etag, monitor_update))) => {
                        let duration_ms = start_time.elapsed().as_millis() as u64;
                        state_dash.dashboard_build_duration_ms.store(duration_ms, std::sync::atomic::Ordering::Relaxed);

                        let new_dash = crate::state::CachedJsonResponse {
                            body: bytes::Bytes::from(dash_json),
                            etag: Arc::from(dash_etag),
                            generated_at: std::time::Instant::now(),
                            generation: current_gen,
                        };
                        state_dash.cached_dashboard.store(Arc::new(new_dash));

                        if let Some((monitor_json, monitor_etag)) = monitor_update {
                            let new_conns = crate::state::CachedJsonResponse {
                                body: bytes::Bytes::from(monitor_json),
                                etag: Arc::from(monitor_etag),
                                generated_at: std::time::Instant::now(),
                                generation: current_gen,
                            };
                            state_dash.cached_connections.store(Arc::new(new_conns));
                        }
                    }
                    _ => {
                        state_dash.dashboard_build_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        static LAST_WARN_ERR: once_cell::sync::Lazy<parking_lot::Mutex<Option<std::time::Instant>>> =
                            once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(None));
                        let mut last = LAST_WARN_ERR.lock();
                        let should_warn = match *last {
                            Some(t) => t.elapsed().as_secs() >= 30,
                            None => true,
                        };
                        if should_warn {
                            tracing::warn!("Failed to rebuild dashboard cache");
                            *last = Some(std::time::Instant::now());
                        }
                    }
                }
            }
        });

        // Launch SOCKS5 WARP control-plane health checks
        let engine_state_warp = Arc::clone(&engine_state);
        tokio::spawn(async move {
            let mut consecutive_failures = 0;
            let mut last_warn = std::time::Instant::now() - std::time::Duration::from_secs(60);

            loop {
                let current_state = engine_state_warp.warp_health.load(std::sync::atomic::Ordering::Relaxed);
                let check_timeout = std::time::Duration::from_secs(2);
                let handshake_res = tokio::time::timeout(
                    check_timeout,
                    tokio::net::TcpStream::connect("127.0.0.1:40000")
                ).await;

                let success = match handshake_res {
                    Ok(Ok(_stream)) => true,
                    _ => false,
                };

                let new_state = match current_state {
                    0 => { // Unknown
                        if success {
                            consecutive_failures = 0;
                            1 // Healthy
                        } else {
                            consecutive_failures = 1;
                            2 // Degraded
                        }
                    }
                    1 => { // Healthy
                        if success {
                            consecutive_failures = 0;
                            1 // Healthy
                        } else {
                            consecutive_failures = 1;
                            2 // Degraded
                        }
                    }
                    2 => { // Degraded
                        if success {
                            consecutive_failures = 0;
                            1 // Healthy
                        } else {
                            consecutive_failures += 1;
                            if consecutive_failures >= 3 {
                                3 // Down
                            } else {
                                2 // Degraded
                            }
                        }
                    }
                    3 => { // Down
                        if success {
                            consecutive_failures = 0;
                            1 // Healthy
                        } else {
                            consecutive_failures += 1;
                            if consecutive_failures >= 5 {
                                4 // CircuitOpen
                            } else {
                                3 // Down
                            }
                        }
                    }
                    4 => { // CircuitOpen
                        if success {
                            consecutive_failures = 0;
                            1 // Healthy
                        } else {
                            4 // CircuitOpen
                        }
                    }
                    _ => 0, // Fallback to Unknown
                };

                if new_state != current_state {
                    let state_name = match new_state {
                        1 => "Healthy",
                        2 => "Degraded (unstable connectivity)",
                        3 => "Down (proxy unreachable)",
                        4 => "CircuitOpen (cooldown active)",
                        _ => "Unknown",
                    };
                    tracing::info!("WARP health state changed: from {} to {}", 
                        match current_state {
                            0 => "Unknown",
                            1 => "Healthy",
                            2 => "Degraded",
                            3 => "Down",
                            4 => "CircuitOpen",
                            _ => "?",
                        },
                        state_name
                    );
                    engine_state_warp.warp_health.store(new_state, std::sync::atomic::Ordering::Relaxed);
                }

                if new_state == 3 || new_state == 4 {
                    if last_warn.elapsed().as_secs() >= 60 {
                        tracing::warn!("WARP SOCKS5 health check failing. State is Down/CircuitOpen. Please verify WARP service.");
                        last_warn = std::time::Instant::now();
                    }
                }

                let sleep_duration = if new_state == 4 {
                    std::time::Duration::from_secs(30)
                } else {
                    std::time::Duration::from_secs(10)
                };
                tokio::time::sleep(sleep_duration).await;
            }
        });

        // Launch Administration UI API Service
        let api_server = api::ApiServer::new(Arc::clone(&engine_state));
        api_server.start(api_listen, api_port).await?;

        Ok(())
    })
}
