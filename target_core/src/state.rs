use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use uuid::Uuid;

use crate::config::Config;

#[derive(Debug, Default)]
pub struct UserStats {
    pub rx: AtomicU64,
    pub tx: AtomicU64,
}

#[derive(Debug, Clone)]
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
}

pub struct EngineState {
    pub config: RwLock<Config>,
    // Set of allowed user UUIDs mapped from configured clients
    pub allowed_users: RwLock<HashSet<[u8; 16]>>,
    // Client email -> stats
    pub stats: RwLock<HashMap<String, Arc<UserStats>>>,
    // Inbound tag -> active count
    pub active_connections: RwLock<HashMap<Uuid, ConnectionInfo>>,
}

impl EngineState {
    pub fn new(config: Config) -> Self {
        let mut allowed_users = HashSet::new();
        let mut stats = HashMap::new();

        for inbound in &config.inbounds {
            if let Some(ref clients) = inbound.settings.clients {
                for client in clients {
                    if let Ok(uuid) = Uuid::parse_str(&client.id) {
                        allowed_users.insert(*uuid.as_bytes());
                        if let Some(ref email) = client.email {
                            stats.insert(email.clone(), Arc::new(UserStats::default()));
                        }
                    }
                }
            }
        }

        Self {
            config: RwLock::new(config),
            allowed_users: RwLock::new(allowed_users),
            stats: RwLock::new(stats),
            active_connections: RwLock::new(HashMap::new()),
        }
    }

    pub fn is_user_allowed(&self, id: &[u8; 16]) -> bool {
        self.allowed_users.read().contains(id)
    }

    pub fn update_config(&self, new_config: Config) {
        let mut config_lock = self.config.write();
        let mut users_lock = self.allowed_users.write();
        let mut stats_lock = self.stats.write();

        users_lock.clear();
        for inbound in &new_config.inbounds {
            if let Some(ref clients) = inbound.settings.clients {
                for client in clients {
                    if let Ok(uuid) = Uuid::parse_str(&client.id) {
                        users_lock.insert(*uuid.as_bytes());
                        if let Some(ref email) = client.email {
                            stats_lock.entry(email.clone()).or_insert_with(Arc::default);
                        }
                    }
                }
            }
        }

        *config_lock = new_config;
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

    pub fn record_rx(&self, conn_id: &Uuid, bytes: u64, email: &Option<String>) {
        if let Some(email_str) = email {
            let stats_guard = self.stats.read();
            if let Some(user_stat) = stats_guard.get(email_str) {
                user_stat.rx.fetch_add(bytes, Ordering::Relaxed);
            }
        }
        let conn_guard = self.active_connections.read();
        if let Some(conn) = conn_guard.get(conn_id) {
            conn.rx.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn record_tx(&self, conn_id: &Uuid, bytes: u64, email: &Option<String>) {
        if let Some(email_str) = email {
            let stats_guard = self.stats.read();
            if let Some(user_stat) = stats_guard.get(email_str) {
                user_stat.tx.fetch_add(bytes, Ordering::Relaxed);
            }
        }
        let conn_guard = self.active_connections.read();
        if let Some(conn) = conn_guard.get(conn_id) {
            conn.tx.fetch_add(bytes, Ordering::Relaxed);
        }
    }
}
