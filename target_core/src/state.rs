use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use uuid::Uuid;

use crate::config::Config;
use crate::transport::reality::RealityRuntime;

pub static CONTROL_PLANE_CPU: once_cell::sync::Lazy<tokio::sync::Semaphore> =
    once_cell::sync::Lazy::new(|| tokio::sync::Semaphore::new(1));

pub static REALITY_VALIDATION: once_cell::sync::Lazy<tokio::sync::Semaphore> =
    once_cell::sync::Lazy::new(|| tokio::sync::Semaphore::new(1));

#[derive(Debug)]
pub struct UserStats {
    pub id: String, // UUID
    pub email: RwLock<Option<String>>,
    pub limit_ip: AtomicU32,
    pub total_gb: AtomicI64,
    pub expiry_time: AtomicI64,
    pub speed_limit: AtomicU64,
    pub remaining_bytes: AtomicI64, // -1 for unlimited, or remaining bytes
    pub rx: AtomicU64,
    pub tx: AtomicU64,
    pub reality_profile_id: RwLock<Option<Uuid>>,
    pub inbound_tag: RwLock<Option<String>>,
    pub sni: RwLock<Option<String>>,
}

pub struct ConnectionInfo {
    pub id: Uuid,
    pub inbound_tag: String,
    pub client_ip: String,
    pub dest_address: String,
    pub sni: Option<String>,
    pub outbound_tag: String,
    pub rx: Arc<AtomicU64>,
    pub tx: Arc<AtomicU64>,
    pub start_time: std::time::Instant,
    pub user_uuid: Option<[u8; 16]>,
    pub shutdown_tx: Option<Arc<parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>>,
}

impl Clone for ConnectionInfo {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            inbound_tag: self.inbound_tag.clone(),
            client_ip: self.client_ip.clone(),
            dest_address: self.dest_address.clone(),
            sni: self.sni.clone(),
            outbound_tag: self.outbound_tag.clone(),
            rx: Arc::clone(&self.rx),
            tx: Arc::clone(&self.tx),
            start_time: self.start_time,
            user_uuid: self.user_uuid,
            shutdown_tx: self.shutdown_tx.clone(),
        }
    }
}

impl std::fmt::Debug for ConnectionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionInfo")
            .field("id", &self.id)
            .field("inbound_tag", &self.inbound_tag)
            .field("client_ip", &self.client_ip)
            .field("dest_address", &self.dest_address)
            .field("sni", &self.sni)
            .field("outbound_tag", &self.outbound_tag)
            .field("rx", &self.rx)
            .field("tx", &self.tx)
            .field("start_time", &self.start_time)
            .field("user_uuid", &self.user_uuid)
            .finish()
    }
}

pub struct PersistRequest {
    pub generation: u64,
    pub config: Config,
    pub user_snapshots: HashMap<String, (i64, i64, u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarpHealth {
    Unknown,
    Healthy,
    Degraded,
    Down,
    CircuitOpen,
}

pub struct EngineState {
    pub config: RwLock<Config>,
    pub routing_tables: arc_swap::ArcSwap<crate::router::RouteModeTables>,
    // Mapping from Client UUID bytes to UserStats and its Route Mode
    pub users: RwLock<HashMap<[u8; 16], (Arc<UserStats>, crate::config::ClientRouteMode)>>,
    // Mapping from Email string to UserStats
    pub stats: RwLock<HashMap<String, Arc<UserStats>>>,
    // Mapping from hashed subscription token to UserStats
    pub sub_tokens: RwLock<HashMap<[u8; 32], Arc<UserStats>>>,
    // Immutable cached admin runtime auth
    pub admin_auth: arc_swap::ArcSwapOption<crate::auth::AdminAuthRuntime>,
    // Inbound tag -> active count
    pub active_connections: RwLock<HashMap<Uuid, ConnectionInfo>>,
    pub warp_health: std::sync::atomic::AtomicU8,
    pub dirty: std::sync::atomic::AtomicBool,
    pub persist_tx: tokio::sync::mpsc::Sender<PersistRequest>,
    pub persist_gen: std::sync::atomic::AtomicU64,
    pub lag_10ms_count: std::sync::atomic::AtomicU64,
    pub lag_50ms_count: std::sync::atomic::AtomicU64,
    pub lag_100ms_count: std::sync::atomic::AtomicU64,
    pub lag_250ms_count: std::sync::atomic::AtomicU64,
    pub maximum_lag_ms: std::sync::atomic::AtomicU64,
    pub reality_runtimes: arc_swap::ArcSwap<HashMap<Uuid, Arc<RealityRuntime>>>,
    pub active_listeners: RwLock<
        HashMap<
            u16,
            (
                tokio::sync::oneshot::Sender<()>,
                Arc<arc_swap::ArcSwapOption<RealityRuntime>>,
            ),
        >,
    >,
    pub cached_dashboard: arc_swap::ArcSwap<CachedJsonResponse>,
    pub cached_connections: arc_swap::ArcSwap<CachedJsonResponse>,
    pub handshake_semaphore: Arc<tokio::sync::Semaphore>,
    pub active_handshakes_per_ip: Arc<parking_lot::Mutex<HashMap<std::net::IpAddr, usize>>>,
    pub recent_event_loop_lag_ms: std::sync::atomic::AtomicU64,
    pub last_lag_event_epoch_ms: std::sync::atomic::AtomicU64,
    pub dashboard_build_errors: std::sync::atomic::AtomicU64,
    pub dashboard_build_skipped: std::sync::atomic::AtomicU64,
    pub dashboard_build_duration_ms: std::sync::atomic::AtomicU64,
    pub active_blocking_tasks: std::sync::atomic::AtomicU64,
    pub connections_monitor_last_request_ms: std::sync::atomic::AtomicU64,
    pub last_cpu_total_ticks: std::sync::atomic::AtomicU64,
    pub last_cpu_idle_ticks: std::sync::atomic::AtomicU64,
    pub dashboard_build_semaphore: Arc<tokio::sync::Semaphore>,
    pub network_runtime: Arc<crate::config::NetworkRuntime>,
}

impl EngineState {
    pub fn new(mut config: Config) -> (Self, tokio::sync::mpsc::Receiver<PersistRequest>) {
        let _ = config.migrate_if_needed();
        crate::config::set_ipv4_only(config.network.ipv4_only);
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let mut users = HashMap::new();
        let mut stats = HashMap::new();
        let mut sub_tokens = HashMap::new();

        // Map to keep track of already instantiated UserStats to prevent duplicate stat mappings across inbounds
        let mut stats_map: HashMap<String, Arc<UserStats>> = HashMap::new();

        for inbound in &config.inbounds {
            if let Some(ref clients) = inbound.settings.clients {
                for client in clients {
                    if let Ok(uuid) = Uuid::parse_str(&client.id) {
                        let user_stat = stats_map.entry(client.id.clone()).or_insert_with(|| {
                            let remaining_bytes = if let Some(rem_gb) = client.remaining_gb {
                                if rem_gb >= 0.0 {
                                    (rem_gb * 1_073_741_824.0) as i64
                                } else {
                                    -1
                                }
                            } else {
                                -1
                            };

                            let total_gb_val = client.total_gb.map(|t| t as i64).unwrap_or(-1);

                            Arc::new(UserStats {
                                id: client.id.clone(),
                                email: RwLock::new(client.email.clone()),
                                limit_ip: AtomicU32::new(client.limit_ip.unwrap_or(0)),
                                total_gb: AtomicI64::new(total_gb_val),
                                expiry_time: AtomicI64::new(client.expiry_time.unwrap_or(0)),
                                speed_limit: AtomicU64::new(client.speed_limit.unwrap_or(0)),
                                remaining_bytes: AtomicI64::new(remaining_bytes),
                                rx: AtomicU64::new(client.rx.unwrap_or(0)),
                                tx: AtomicU64::new(client.tx.unwrap_or(0)),
                                reality_profile_id: RwLock::new(client.reality_profile_id),
                                inbound_tag: RwLock::new(client.inbound_tag.clone()),
                                sni: RwLock::new(client.sni.clone()),
                            })
                        });

                        users.insert(
                            *uuid.as_bytes(),
                            (Arc::clone(user_stat), crate::config::ClientRouteMode::Smart),
                        );

                        if let Some(ref b_id) = client.browsing_warp_id {
                            if let Ok(b_uuid) = Uuid::parse_str(b_id) {
                                users.insert(
                                    *b_uuid.as_bytes(),
                                    (
                                        Arc::clone(user_stat),
                                        crate::config::ClientRouteMode::BrowsingWarp,
                                    ),
                                );
                            }
                        }

                        if let Some(ref l_id) = client.low_latency_id {
                            if let Ok(l_uuid) = Uuid::parse_str(l_id) {
                                users.insert(
                                    *l_uuid.as_bytes(),
                                    (
                                        Arc::clone(user_stat),
                                        crate::config::ClientRouteMode::LowLatencyDirect,
                                    ),
                                );
                            }
                        }

                        if let Some(ref email) = client.email {
                            stats.insert(email.clone(), Arc::clone(user_stat));
                        }

                        if let Some(ref token_hash_hex) = client.sub_token_hash {
                            if let Ok(hash_bytes) = hex::decode(token_hash_hex) {
                                if hash_bytes.len() == 32 {
                                    let mut hash_arr = [0u8; 32];
                                    hash_arr.copy_from_slice(&hash_bytes);
                                    sub_tokens.insert(hash_arr, Arc::clone(user_stat));
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut runtimes = HashMap::new();
        for profile in &config.reality_profiles {
            if let Ok(runtime) = RealityRuntime::new(profile.clone()) {
                runtimes.insert(profile.id, Arc::new(runtime));
            }
        }

        let initial_dash = CachedJsonResponse {
            body: bytes::Bytes::from("{\"cpu_percent\":0.0,\"ram_used_gb\":0.0,\"ram_total_gb\":0.0,\"ram_percent\":0.0,\"uptime_secs\":0,\"active_connections\":0,\"total_users\":0,\"total_rx\":0,\"total_tx\":0,\"lag_10ms_count\":0,\"lag_50ms_count\":0,\"lag_100ms_count\":0,\"lag_250ms_count\":0,\"maximum_lag_ms\":0,\"users\":[],\"timestamp\":0,\"event_loop_lag_ms\":0,\"dashboard_build_duration_ms\":0,\"dashboard_build_skipped\":0,\"dashboard_build_errors\":0,\"active_blocking_operations\":0}"),
            etag: Arc::from("\"dash-0-0\""),
            generated_at: std::time::Instant::now(),
            generation: 0,
        };
        let initial_conns = CachedJsonResponse {
            body: bytes::Bytes::from(
                "{\"connections\":[],\"total_connections\":0,\"timestamp\":0}",
            ),
            etag: Arc::from("\"conns-0-0\""),
            generated_at: std::time::Instant::now(),
            generation: 0,
        };

        let routing_tables = crate::router::RouteModeTables::compile(&config);

        let admin_auth_val = crate::auth::load_admin_credentials()
            .ok()
            .flatten()
            .map(|c| {
                Arc::new(crate::auth::AdminAuthRuntime {
                    password_hash: Arc::from(c.password_hash),
                    session_secret: Arc::from(hex::decode(&c.session_secret).unwrap_or_default()),
                    session_epoch: c.session_epoch,
                })
            });

        let ipv4_only = config.network.ipv4_only;
        let state = Self {
            config: RwLock::new(config),
            routing_tables: arc_swap::ArcSwap::new(Arc::new(routing_tables)),
            users: RwLock::new(users),
            stats: RwLock::new(stats),
            sub_tokens: RwLock::new(sub_tokens),
            admin_auth: arc_swap::ArcSwapOption::new(admin_auth_val),
            active_connections: RwLock::new(HashMap::new()),
            warp_health: std::sync::atomic::AtomicU8::new(0), // unknown SOCKS5 state
            dirty: std::sync::atomic::AtomicBool::new(false),
            persist_tx: tx,
            persist_gen: std::sync::atomic::AtomicU64::new(0),
            lag_10ms_count: std::sync::atomic::AtomicU64::new(0),
            lag_50ms_count: std::sync::atomic::AtomicU64::new(0),
            lag_100ms_count: std::sync::atomic::AtomicU64::new(0),
            lag_250ms_count: std::sync::atomic::AtomicU64::new(0),
            maximum_lag_ms: std::sync::atomic::AtomicU64::new(0),
            reality_runtimes: arc_swap::ArcSwap::new(Arc::new(runtimes)),
            active_listeners: RwLock::new(HashMap::new()),
            cached_dashboard: arc_swap::ArcSwap::new(Arc::new(initial_dash)),
            cached_connections: arc_swap::ArcSwap::new(Arc::new(initial_conns)),
            handshake_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            active_handshakes_per_ip: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            recent_event_loop_lag_ms: std::sync::atomic::AtomicU64::new(0),
            last_lag_event_epoch_ms: std::sync::atomic::AtomicU64::new(0),
            dashboard_build_errors: std::sync::atomic::AtomicU64::new(0),
            dashboard_build_skipped: std::sync::atomic::AtomicU64::new(0),
            dashboard_build_duration_ms: std::sync::atomic::AtomicU64::new(0),
            active_blocking_tasks: std::sync::atomic::AtomicU64::new(0),
            connections_monitor_last_request_ms: std::sync::atomic::AtomicU64::new(0),
            last_cpu_total_ticks: std::sync::atomic::AtomicU64::new(0),
            last_cpu_idle_ticks: std::sync::atomic::AtomicU64::new(0),
            dashboard_build_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
            network_runtime: Arc::new(crate::config::NetworkRuntime { ipv4_only }),
        };
        (state, rx)
    }

    pub fn authenticate_client(
        &self,
        id: &[u8; 16],
    ) -> Option<(Arc<UserStats>, crate::config::ClientRouteMode)> {
        let users_guard = self.users.read();
        if let Some((user, mode)) = users_guard.get(id) {
            let expiry = user.expiry_time.load(Ordering::Relaxed);
            if expiry > 0 {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                if now > expiry {
                    return None;
                }
            }

            let remaining = user.remaining_bytes.load(Ordering::Relaxed);
            if remaining != -1 && remaining <= 0 {
                return None;
            }

            Some((Arc::clone(user), *mode))
        } else {
            None
        }
    }

    pub fn is_user_allowed(&self, id: &[u8; 16]) -> bool {
        self.authenticate_client(id).is_some()
    }

    pub fn get_user_speed_limit(&self, id: &[u8; 16]) -> Option<u64> {
        let users_guard = self.users.read();
        users_guard.get(id).and_then(|(u, _)| {
            let limit = u.speed_limit.load(Ordering::Relaxed);
            if limit > 0 {
                Some(limit * 1_000_000 / 8)
            } else {
                None
            }
        })
    }

    pub fn build_all_runtimes(
        config: &Config,
    ) -> Result<HashMap<Uuid, Arc<RealityRuntime>>, Box<dyn std::error::Error + Send + Sync>> {
        let mut runtimes = HashMap::new();
        for profile in &config.reality_profiles {
            let runtime = RealityRuntime::new(profile.clone())?;
            runtimes.insert(profile.id, Arc::new(runtime));
        }
        Ok(runtimes)
    }

    pub fn update_config(
        &self,
        new_config: Config,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if new_config.network.ipv4_only != self.config.read().network.ipv4_only {
            return Err("restart_required".into());
        }
        // 1. Build and validate all runtimes first to ensure they all succeed
        let new_runtimes = Self::build_all_runtimes(&new_config)?;

        let mut config_lock = self.config.write();
        let mut users_lock = self.users.write();
        let mut stats_lock = self.stats.write();
        let mut sub_tokens_lock = self.sub_tokens.write();

        let mut new_users = HashMap::new();
        let mut new_stats = HashMap::new();
        let mut new_sub_tokens = HashMap::new();

        // Keep a mapping of already resolved/created UserStats to prevent duplicate stat mappings across inbounds
        let mut local_stats_map: HashMap<String, Arc<UserStats>> = HashMap::new();

        for inbound in &new_config.inbounds {
            if let Some(ref clients) = inbound.settings.clients {
                for client in clients {
                    if let Ok(uuid) = Uuid::parse_str(&client.id) {
                        let uuid_bytes = *uuid.as_bytes();

                        let user_stat = if let Some(existing_local) =
                            local_stats_map.get(&client.id)
                        {
                            Arc::clone(existing_local)
                        } else if let Some((existing_user, _)) = users_lock.get(&uuid_bytes) {
                            // Keep the existing Arc reference and update only what has changed or is mutable.
                            *existing_user.email.write() = client.email.clone();
                            existing_user
                                .limit_ip
                                .store(client.limit_ip.unwrap_or(0), Ordering::Relaxed);
                            existing_user
                                .expiry_time
                                .store(client.expiry_time.unwrap_or(0), Ordering::Relaxed);
                            existing_user
                                .speed_limit
                                .store(client.speed_limit.unwrap_or(0), Ordering::Relaxed);

                            *existing_user.reality_profile_id.write() = client.reality_profile_id;
                            *existing_user.inbound_tag.write() = client.inbound_tag.clone();
                            *existing_user.sni.write() = client.sni.clone();

                            let stats_arc = Arc::clone(existing_user);
                            local_stats_map.insert(client.id.clone(), Arc::clone(&stats_arc));
                            stats_arc
                        } else {
                            // Create a brand new UserStats for new user
                            let remaining_bytes = if let Some(rem_gb) = client.remaining_gb {
                                if rem_gb >= 0.0 {
                                    (rem_gb * 1_073_741_824.0) as i64
                                } else {
                                    -1
                                }
                            } else {
                                -1
                            };

                            let total_gb_val = client.total_gb.map(|t| t as i64).unwrap_or(-1);

                            let stats_arc = Arc::new(UserStats {
                                id: client.id.clone(),
                                email: RwLock::new(client.email.clone()),
                                limit_ip: AtomicU32::new(client.limit_ip.unwrap_or(0)),
                                total_gb: AtomicI64::new(total_gb_val),
                                expiry_time: AtomicI64::new(client.expiry_time.unwrap_or(0)),
                                speed_limit: AtomicU64::new(client.speed_limit.unwrap_or(0)),
                                remaining_bytes: AtomicI64::new(remaining_bytes),
                                rx: AtomicU64::new(client.rx.unwrap_or(0)),
                                tx: AtomicU64::new(client.tx.unwrap_or(0)),
                                reality_profile_id: RwLock::new(client.reality_profile_id),
                                inbound_tag: RwLock::new(client.inbound_tag.clone()),
                                sni: RwLock::new(client.sni.clone()),
                            });
                            local_stats_map.insert(client.id.clone(), Arc::clone(&stats_arc));
                            stats_arc
                        };

                        new_users.insert(
                            uuid_bytes,
                            (
                                Arc::clone(&user_stat),
                                crate::config::ClientRouteMode::Smart,
                            ),
                        );

                        if let Some(ref b_id) = client.browsing_warp_id {
                            if let Ok(b_uuid) = Uuid::parse_str(b_id) {
                                new_users.insert(
                                    *b_uuid.as_bytes(),
                                    (
                                        Arc::clone(&user_stat),
                                        crate::config::ClientRouteMode::BrowsingWarp,
                                    ),
                                );
                            }
                        }

                        if let Some(ref l_id) = client.low_latency_id {
                            if let Ok(l_uuid) = Uuid::parse_str(l_id) {
                                new_users.insert(
                                    *l_uuid.as_bytes(),
                                    (
                                        Arc::clone(&user_stat),
                                        crate::config::ClientRouteMode::LowLatencyDirect,
                                    ),
                                );
                            }
                        }

                        let email_opt = user_stat.email.read().clone();
                        if let Some(email) = email_opt {
                            new_stats.insert(email, Arc::clone(&user_stat));
                        }

                        if let Some(ref token_hash_hex) = client.sub_token_hash {
                            if let Ok(hash_bytes) = hex::decode(token_hash_hex) {
                                if hash_bytes.len() == 32 {
                                    let mut hash_arr = [0u8; 32];
                                    hash_arr.copy_from_slice(&hash_bytes);
                                    new_sub_tokens.insert(hash_arr, Arc::clone(&user_stat));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Hot-swap active Reality runtimes (using already built new_runtimes)
        self.reality_runtimes.store(Arc::new(new_runtimes.clone()));
        for (profile_id, runtime_arc) in &new_runtimes {
            if let Some(profile) = new_config
                .reality_profiles
                .iter()
                .find(|p| p.id == *profile_id)
            {
                let listeners_guard = self.active_listeners.read();
                if let Some((_, runtime_swap)) = listeners_guard.get(&profile.port) {
                    runtime_swap.store(Some(Arc::clone(runtime_arc)));
                }
            }
        }

        let new_tables = crate::router::RouteModeTables::compile(&new_config);
        self.routing_tables.store(Arc::new(new_tables));

        *users_lock = new_users;
        *stats_lock = new_stats;
        *sub_tokens_lock = new_sub_tokens;
        *config_lock = new_config;
        self.dirty.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub fn apply_routing_update(&self, new_config: Config) {
        let mut config_lock = self.config.write();
        config_lock.warp_domain_sets = new_config.warp_domain_sets;
        config_lock.direct_exception_sets = new_config.direct_exception_sets;
        let config_clone = config_lock.clone();
        drop(config_lock);

        let new_tables = crate::router::RouteModeTables::compile(&config_clone);
        self.routing_tables.store(Arc::new(new_tables));

        self.dirty.store(true, Ordering::Relaxed);
        self.persist_config_to_disk();
    }

    pub fn is_warp_allowed(&self) -> bool {
        let val = self.warp_health.load(Ordering::Relaxed);
        val != 3 && val != 4 // not Down (3) and not CircuitOpen (4)
    }

    pub fn get_user_stats(&self, email: &Option<String>) -> Option<Arc<UserStats>> {
        if let Some(ref email_str) = email {
            self.stats.read().get(email_str).cloned()
        } else {
            None
        }
    }

    pub fn register_connection(&self, conn: ConnectionInfo) {
        self.active_connections.write().insert(conn.id, conn);
    }

    pub fn deregister_connection(&self, id: &Uuid) {
        self.active_connections.write().remove(id);
    }

    pub fn disconnect_user(&self, user_id: &str) {
        if let Ok(uuid) = uuid::Uuid::parse_str(user_id) {
            let user_bytes = uuid.into_bytes();
            let conns = self.active_connections.read();
            for conn in conns.values() {
                if conn.user_uuid == Some(user_bytes) {
                    if let Some(ref tx_mutex) = conn.shutdown_tx {
                        if let Some(tx) = tx_mutex.lock().take() {
                            let _ = tx.send(());
                        }
                    }
                }
            }
        }
    }

    pub fn record_rx_stats_only(&self, conn_id: &Uuid, bytes: u64, user: Option<&Arc<UserStats>>) {
        if let Some(user_stat) = user {
            user_stat.rx.fetch_add(bytes, Ordering::Relaxed);
        }
        let conn_guard = self.active_connections.read();
        if let Some(conn) = conn_guard.get(conn_id) {
            conn.rx.fetch_add(bytes, Ordering::Relaxed);
        }
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub fn record_tx_stats_only(&self, conn_id: &Uuid, bytes: u64, user: Option<&Arc<UserStats>>) {
        if let Some(user_stat) = user {
            user_stat.tx.fetch_add(bytes, Ordering::Relaxed);
        }
        let conn_guard = self.active_connections.read();
        if let Some(conn) = conn_guard.get(conn_id) {
            conn.tx.fetch_add(bytes, Ordering::Relaxed);
        }
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub fn record_rx(&self, conn_id: &Uuid, bytes: u64, user: Option<&Arc<UserStats>>) {
        if let Some(user_stat) = user {
            user_stat.rx.fetch_add(bytes, Ordering::Relaxed);
            let remaining = user_stat.remaining_bytes.load(Ordering::Relaxed);
            if remaining != -1 {
                user_stat
                    .remaining_bytes
                    .fetch_sub(bytes as i64, Ordering::Relaxed);
            }
        }
        let conn_guard = self.active_connections.read();
        if let Some(conn) = conn_guard.get(conn_id) {
            conn.rx.fetch_add(bytes, Ordering::Relaxed);
        }
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub fn record_tx(&self, conn_id: &Uuid, bytes: u64, user: Option<&Arc<UserStats>>) {
        if let Some(user_stat) = user {
            user_stat.tx.fetch_add(bytes, Ordering::Relaxed);
            let remaining = user_stat.remaining_bytes.load(Ordering::Relaxed);
            if remaining != -1 {
                user_stat
                    .remaining_bytes
                    .fetch_sub(bytes as i64, Ordering::Relaxed);
            }
        }
        let conn_guard = self.active_connections.read();
        if let Some(conn) = conn_guard.get(conn_id) {
            conn.tx.fetch_add(bytes, Ordering::Relaxed);
        }
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub fn persist_config_to_disk(&self) {
        // Acquire a single read lock block to clone primitive values instantly
        let user_snapshots: HashMap<String, (i64, i64, u64, u64)> = {
            let guard = self.users.read();
            guard
                .values()
                .map(|user_stat| {
                    (
                        user_stat.0.id.clone(),
                        (
                            user_stat.0.remaining_bytes.load(Ordering::Relaxed),
                            user_stat.0.total_gb.load(Ordering::Relaxed),
                            user_stat.0.rx.load(Ordering::Relaxed),
                            user_stat.0.tx.load(Ordering::Relaxed),
                        ),
                    )
                })
                .collect()
        }; // Lock drops right here

        // Snapshot current config in a short read lock block
        let config = self.config.read().clone();

        let gen = self.persist_gen.fetch_add(1, Ordering::Relaxed) + 1;
        let req = PersistRequest {
            generation: gen,
            config,
            user_snapshots,
        };
        match self.persist_tx.try_send(req) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.dirty.store(true, Ordering::Release);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                tracing::error!("Persistence worker is unavailable");
                self.dirty.store(true, Ordering::Release);
            }
        }
    }

    pub async fn create_reality_profile_and_listener(
        self: &Arc<Self>,
        mut profile: crate::config::RealityProfile,
    ) -> Result<Arc<RealityRuntime>, Box<dyn std::error::Error + Send + Sync>> {
        // 1. Validate the profile
        profile.validate_and_normalize()?;

        // Check duplicate name, tag, or port across profiles and inbounds
        {
            let config = self.config.read();
            for p in &config.reality_profiles {
                if p.name == profile.name
                    || p.port == profile.port
                    || p.inbound_tag == profile.inbound_tag
                {
                    return Err(Box::from(
                        "CONFLICT: Duplicate profile name, port, or tag already exists",
                    ));
                }
            }
            for inbound in &config.inbounds {
                if inbound.tag == profile.inbound_tag || inbound.port == profile.port {
                    return Err(Box::from(
                        "CONFLICT: Duplicate inbound tag or port already exists",
                    ));
                }
            }
        }

        // Check if port is already bound in active listeners
        {
            let listeners = self.active_listeners.read();
            if listeners.contains_key(&profile.port) {
                return Err(Box::from(
                    "CONFLICT: Port is already bound in active listeners",
                ));
            }
        }

        // 2. Build the complete Reality runtime off-reactor
        let profile_clone = profile.clone();
        let permit = crate::state::CONTROL_PLANE_CPU.acquire().await?;
        let runtime_res =
            tokio::task::spawn_blocking(move || RealityRuntime::new(profile_clone)).await;
        drop(permit);

        let runtime = Arc::new(runtime_res??);

        // 3. Bind the port before modifying persisted configuration
        let addr = format!("{}:{}", profile.listen, profile.port);
        let tcp_listener = tokio::net::TcpListener::bind(&addr).await?;

        // 4. Start the listener
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let r_runtime = Arc::new(arc_swap::ArcSwapOption::new(Some(Arc::clone(&runtime))));

        let self_arc = Arc::clone(self);
        let tag = profile.inbound_tag.clone();
        let port = profile.port;
        let r_runtime_clone = Arc::clone(&r_runtime);

        tokio::spawn(async move {
            tracing::info!(tag = %tag, port = %port, "Dynamic Inbound Reality Listener started successfully");

            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        tracing::info!(tag = %tag, port = %port, "Dynamic listener shutdown signal received");
                        break;
                    }
                    res = tcp_listener.accept() => {
                        match res {
                            Ok((socket, client_addr)) => {
                                if let Err(e) = socket.set_nodelay(true) {
                                    tracing::debug!(error = %e, "Failed to enable TCP_NODELAY");
                                }

                                let engine = Arc::clone(&self_arc);
                                let inbound_tag = tag.clone();
                                let runtime_guard = r_runtime_clone.load();
                                let r_server = runtime_guard.as_ref().map(|r| Arc::clone(&r.server));

                                tokio::spawn(async move {
                                    if let Some(rs) = r_server {
                                        match crate::inbound::accept_reality_bounded(engine.clone(), rs, socket, client_addr).await {
                                            Ok(s) => {
                                                if let Err(e) = crate::inbound::handle_inbound_stream(
                                                    crate::inbound::InboundTransportStream::Reality(s),
                                                    client_addr,
                                                    inbound_tag,
                                                    "vless".to_string(),
                                                    engine,
                                                ).await {
                                                    tracing::error!(error = %e, client = %client_addr, "Error handling inbound connection");
                                                }
                                            }
                                            Err(e) => {
                                                tracing::debug!(tag = %inbound_tag, client = %client_addr, error = %e, "Reality accept failed or rejected");
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "Failed to accept connection on dynamic listener");
                            }
                        }
                    }
                }
            }
        });

        // 5. Publish it in the active listeners registry
        self.active_listeners
            .write()
            .insert(profile.port, (shutdown_tx, Arc::clone(&r_runtime)));

        // 6. Publish it in the runtimes registry
        let mut runtimes = self.reality_runtimes.load().as_ref().clone();
        runtimes.insert(profile.id, Arc::clone(&runtime));
        self.reality_runtimes.store(Arc::new(runtimes));

        // 7. Update persisted config and inbound configuration
        {
            let mut config = self.config.write();

            // Add profile to reality_profiles list
            config.reality_profiles.push(profile.clone());

            // Add inbound config to config.inbounds list
            let inbound_config = crate::config::InboundConfig {
                tag: profile.inbound_tag.clone(),
                listen: profile.listen.parse()?,
                port: profile.port,
                protocol: "vless".to_string(),
                settings: crate::config::InboundSettings {
                    clients: Some(Vec::new()),
                },
                stream_settings: Some(crate::config::StreamSettings {
                    security: "reality".to_string(),
                    tls_settings: None,
                    reality_settings: Some(crate::config::RealitySettings {
                        dest: profile.dest.clone(),
                        server_names: profile.server_names.clone(),
                        private_key: profile.private_key.clone(),
                        short_ids: profile.short_ids.clone(),
                    }),
                }),
            };
            config.inbounds.push(inbound_config);
        }

        self.persist_config_to_disk();

        Ok(runtime)
    }
}

pub fn start_persistence_worker(
    engine_state: Arc<EngineState>,
    mut rx: tokio::sync::mpsc::Receiver<PersistRequest>,
) {
    tokio::spawn(async move {
        let mut last_written_gen = 0u64;
        while let Some(req) = rx.recv().await {
            let mut latest_req = req;
            while let Ok(next_req) = rx.try_recv() {
                if next_req.generation > latest_req.generation {
                    latest_req = next_req;
                }
            }

            if latest_req.generation <= last_written_gen {
                continue;
            }

            let gen = latest_req.generation;
            let config = latest_req.config;
            let snapshots = latest_req.user_snapshots;
            let engine = Arc::clone(&engine_state);

            let res = tokio::task::spawn_blocking(move || {
                let mut config = config;
                let mut changed = false;
                for inbound in &mut config.inbounds {
                    if let Some(ref mut clients) = inbound.settings.clients {
                        for client in clients {
                            if let Some(&(rem_bytes, tot_gb, rx_val, tx_val)) =
                                snapshots.get(&client.id)
                            {
                                let current_rem_gb = if rem_bytes == -1 {
                                    None
                                } else {
                                    Some(std::ops::Div::div(rem_bytes as f64, 1_073_741_824.0))
                                };
                                if client.remaining_gb != current_rem_gb {
                                    client.remaining_gb = current_rem_gb;
                                    changed = true;
                                }

                                let current_tot_gb = if tot_gb == -1 {
                                    None
                                } else {
                                    Some(tot_gb as u64)
                                };
                                if client.total_gb != current_tot_gb {
                                    client.total_gb = current_tot_gb;
                                    changed = true;
                                }

                                if client.rx != Some(rx_val) {
                                    client.rx = Some(rx_val);
                                    changed = true;
                                }

                                if client.tx != Some(tx_val) {
                                    client.tx = Some(tx_val);
                                    changed = true;
                                }
                            }
                        }
                    }
                }

                if changed {
                    if let Ok(content) = serde_json::to_string(&config) {
                        let temp_path = "config.json.tmp";
                        let final_path = "config.json";
                        if let Err(e) = std::fs::write(temp_path, content) {
                            eprintln!("Failed to write temp config to disk: {}", e);
                            return Err(e);
                        }
                        if let Ok(file) = std::fs::File::open(temp_path) {
                            let _ = file.sync_all();
                        }
                        if let Err(e) = std::fs::rename(temp_path, final_path) {
                            eprintln!("Failed to atomically rename config: {}", e);
                            return Err(e);
                        }
                    }
                }
                Ok(changed)
            })
            .await;

            match res {
                Ok(Ok(_)) => {
                    last_written_gen = gen;
                }
                _ => {
                    engine.dirty.store(true, Ordering::Relaxed);
                }
            }
        }
    });
}

#[derive(serde::Serialize, Clone)]
pub struct DashboardSnapshot {
    pub cpu_percent: f64,
    pub ram_used_gb: f64,
    pub ram_total_gb: f64,
    pub ram_percent: f64,
    pub uptime_secs: u64,
    pub active_connections: usize,
    pub total_users: usize,
    pub total_rx: u64,
    pub total_tx: u64,
    pub lag_10ms_count: u64,
    pub lag_50ms_count: u64,
    pub lag_100ms_count: u64,
    pub lag_250ms_count: u64,
    pub maximum_lag_ms: u64,
    pub users: Vec<crate::api::UserInfoResponse>,
    pub timestamp: u64,
    pub event_loop_lag_ms: u64,
    pub dashboard_build_duration_ms: u64,
    pub dashboard_build_skipped: u64,
    pub dashboard_build_errors: u64,
    pub active_blocking_operations: u64,
}

#[derive(serde::Serialize, Clone)]
pub struct ConnectionsMonitorSnapshot {
    pub connections: Vec<crate::api::ConnectionResponse>,
    pub total_connections: usize,
    pub timestamp: u64,
}

#[derive(Clone)]
pub struct CachedJsonResponse {
    pub body: bytes::Bytes,
    pub etag: Arc<str>,
    pub generated_at: std::time::Instant,
    pub generation: u64,
}

pub struct BlockingTaskGuard<'a>(pub &'a std::sync::atomic::AtomicU64);

impl Drop for BlockingTaskGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub fn reserve_udp_datagram(remaining: &std::sync::atomic::AtomicI64, datagram_len: usize) -> bool {
    let mut current = remaining.load(std::sync::atomic::Ordering::Acquire);
    loop {
        if current == -1 {
            return true;
        }
        if current < datagram_len as i64 {
            return false;
        }
        let next = current - datagram_len as i64;
        match remaining.compare_exchange_weak(
            current,
            next,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn test_dashboard_build_semaphore_skip() {
        let (state, _) = EngineState::new(Config::default());
        // Initial state permit count is 1
        assert_eq!(state.dashboard_build_semaphore.available_permits(), 1);

        // Acquire the permit
        let permit = state
            .dashboard_build_semaphore
            .clone()
            .try_acquire_owned()
            .unwrap();
        assert_eq!(state.dashboard_build_semaphore.available_permits(), 0);

        // Try to acquire again, should fail (skip build)
        let second = state.dashboard_build_semaphore.clone().try_acquire_owned();
        assert!(second.is_err());

        // Release the permit
        drop(permit);
        assert_eq!(state.dashboard_build_semaphore.available_permits(), 1);
    }

    #[test]
    fn test_blocking_task_guard_counters() {
        let counter = AtomicU64::new(0);
        assert_eq!(counter.load(Ordering::Relaxed), 0);

        {
            counter.fetch_add(1, Ordering::Relaxed);
            let _guard = BlockingTaskGuard(&counter);
            assert_eq!(counter.load(Ordering::Relaxed), 1);
        }

        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_recent_event_loop_lag_pressure() {
        let (state, _) = EngineState::new(Config::default());

        // Initial state: no lag
        let last_lag = state.recent_event_loop_lag_ms.load(Ordering::Relaxed);
        assert_eq!(last_lag, 0);

        // Set lag to 60 ms
        state.recent_event_loop_lag_ms.store(60, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        state.last_lag_event_epoch_ms.store(now, Ordering::Relaxed);

        // Check if lag occurred recently (less than 10 seconds ago)
        let epoch_check = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let last_lag_epoch = state.last_lag_event_epoch_ms.load(Ordering::Relaxed);
        let last_lag_val = state.recent_event_loop_lag_ms.load(Ordering::Relaxed);

        assert!(last_lag_val > 50);
        assert!(epoch_check.saturating_sub(last_lag_epoch) < 10000);
    }
}
