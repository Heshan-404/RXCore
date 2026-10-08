use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;

pub struct NetworkRuntime {
    pub ipv4_only: bool,
}

pub static NETWORK_RUNTIME: Lazy<ArcSwap<NetworkRuntime>> =
    Lazy::new(|| ArcSwap::from_pointee(NetworkRuntime { ipv4_only: true }));

pub fn is_ipv4_only() -> bool {
    NETWORK_RUNTIME.load().ipv4_only
}

pub fn set_ipv4_only(val: bool) {
    NETWORK_RUNTIME.store(Arc::new(NetworkRuntime { ipv4_only: val }));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_ipv4_only")]
    pub ipv4_only: bool,
}

fn default_ipv4_only() -> bool {
    true
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self { ipv4_only: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub routing: RoutingConfig,
    pub api: ApiConfig,
    #[serde(default = "default_subscription_config")]
    pub subscription: SubscriptionConfig,
    #[serde(default)]
    pub reality_profiles: Vec<RealityProfile>,
    #[serde(default)]
    pub warp_domain_sets: Vec<WarpDomainSet>,
    #[serde(default)]
    pub direct_exception_sets: Vec<DirectExceptionSet>,
    pub public_server_address: Option<String>,
    pub subscription_base_url: Option<String>,
    #[serde(default)]
    pub routing_schema_version: u32,
    #[serde(default)]
    pub network: NetworkConfig,
}

fn default_subscription_config() -> SubscriptionConfig {
    SubscriptionConfig {
        listen: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        port: 9100,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WarpDomainSet {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: String,
    pub exact_domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub enabled: bool,
    pub priority: i32,
    pub scope: DomainRuleScope,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DirectExceptionSet {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: String,
    pub exact_domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub enabled: bool,
    pub priority: i32,
    pub scope: DomainRuleScope,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DomainRuleScope {
    Global,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            routing: RoutingConfig { rules: Vec::new() },
            api: ApiConfig {
                listen: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port: 9091,
                trusted_proxies: Vec::new(),
            },
            subscription: default_subscription_config(),
            reality_profiles: Vec::new(),
            warp_domain_sets: Vec::new(),
            direct_exception_sets: Vec::new(),
            public_server_address: None,
            subscription_base_url: None,
            routing_schema_version: 0,
            network: NetworkConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundConfig {
    pub tag: String,
    pub listen: IpAddr,
    pub port: u16,
    pub protocol: String, // "vless" or "socks"
    pub settings: InboundSettings,
    pub stream_settings: Option<StreamSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSettings {
    pub security: String, // "none" or "tls" or "reality"
    pub tls_settings: Option<TlsSettings>,
    pub reality_settings: Option<RealitySettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    pub server_name: String,
    pub certificate_file: Option<String>,
    pub key_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealitySettings {
    pub dest: String,
    pub server_names: Vec<String>,
    pub private_key: String,
    pub short_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundSettings {
    pub clients: Option<Vec<Client>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: String, // UUID
    pub email: Option<String>,
    pub limit_ip: Option<u32>,
    pub total_gb: Option<u64>,
    pub expiry_time: Option<i64>,
    pub speed_limit: Option<u64>,
    pub remaining_gb: Option<f64>,
    pub rx: Option<u64>,
    pub tx: Option<u64>,
    pub reality_profile_id: Option<uuid::Uuid>,
    pub inbound_tag: Option<String>,
    #[serde(default)]
    pub browsing_warp_id: Option<String>,
    #[serde(default)]
    pub low_latency_id: Option<String>,
    #[serde(default)]
    pub sub_token_hash: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    pub tag: String,
    pub protocol: String, // "freedom", "fragment", "blackhole", "vless"
    pub settings: Option<OutboundSettings>,
    pub outbound_proxy: Option<String>,
    pub bind_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundSettings {
    // For fragment outbound configuration
    pub fragment: Option<FragmentSettings>,
    // For VLESS client configuration
    pub vless: Option<VlessClientConfig>,
    // For Hysteria 2 client configuration
    pub hysteria2: Option<Hysteria2ClientConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2ClientConfig {
    pub server: String,
    pub port: u16,
    pub auth: String,
    pub up_mbps: Option<u64>,
    pub down_mbps: Option<u64>,
    pub tls: Option<TlsClientSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessClientConfig {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub tls: Option<TlsClientSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsClientSettings {
    pub server_name: String,
    pub reality: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentSettings {
    pub packets: String, // e.g. "1-5" (split first packet into 1 to 5 random bytes chunks)
    pub length: String,  // e.g. "100-200" or similar rules
    pub interval: u64,   // millisecond delay between packets
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    pub domain: Option<Vec<String>>,
    pub ip: Option<Vec<String>>,
    pub port: Option<Vec<u16>>,
    pub inbound_tag: Option<Vec<String>>,
    pub outbound_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub listen: IpAddr,
    pub port: u16,
    #[serde(default)]
    pub trusted_proxies: Vec<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    pub listen: IpAddr,
    pub port: u16,
}

pub fn derive_reality_public_key(private_key_b64: &str) -> Option<String> {
    let pk_bytes = base64::Engine::decode(&base64::prelude::BASE64_STANDARD, private_key_b64)
        .or_else(|_| hex::decode(private_key_b64))
        .ok()?;
    if pk_bytes.len() == 32 {
        let private_key: [u8; 32] = pk_bytes.try_into().ok()?;
        let secret = x25519_dalek::StaticSecret::from(private_key);
        let public = x25519_dalek::PublicKey::from(&secret);
        Some(base64::Engine::encode(
            &base64::prelude::BASE64_URL_SAFE_NO_PAD,
            public.as_bytes(),
        ))
    } else {
        None
    }
}

impl RealitySettings {
    pub fn validate_and_normalize(&mut self) -> Result<(), String> {
        if self.dest.trim().is_empty() {
            return Err("Reality dest is empty".to_string());
        }
        let parts: Vec<&str> = self.dest.split(':').collect();
        if parts.len() != 2 || parts[0].trim().is_empty() || parts[1].trim().is_empty() {
            return Err(format!(
                "Reality dest must be host:port, got '{}'",
                self.dest
            ));
        }
        if parts[1].parse::<u16>().is_err() {
            return Err(format!(
                "Reality dest port must be a valid u16, got '{}'",
                parts[1]
            ));
        }

        if self.server_names.is_empty() {
            return Err("Reality server_names cannot be empty".to_string());
        }
        for name in &mut self.server_names {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err("Reality server_names contains an empty hostname".to_string());
            }
            *name = trimmed.to_lowercase();
        }

        let client_sni = self
            .server_names
            .first()
            .ok_or_else(|| "Reality server_names cannot be empty".to_string())?;
        if !self.server_names.contains(client_sni) {
            return Err("The generated client SNI is not in server_names".to_string());
        }

        if self.short_ids.is_empty() {
            return Err("Reality short_ids cannot be empty".to_string());
        }
        for sid in &self.short_ids {
            if sid.len() % 2 != 0 {
                return Err(format!(
                    "Reality short ID must have an even length, got '{}'",
                    sid
                ));
            }
            if hex::decode(sid).is_err() {
                return Err(format!(
                    "Reality short ID must be a valid hex string, got '{}'",
                    sid
                ));
            }
        }

        let pk_bytes = base64::Engine::decode(&base64::prelude::BASE64_STANDARD, &self.private_key)
            .or_else(|_| hex::decode(&self.private_key))
            .map_err(|e| format!("Invalid base64/hex Reality private key: {}", e))?;
        if pk_bytes.len() != 32 {
            return Err(format!(
                "Reality private key must be 32 bytes, got {} bytes",
                pk_bytes.len()
            ));
        }
        let private_key_arr: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| "Failed to parse private key bytes".to_string())?;
        let _secret = x25519_dalek::StaticSecret::from(private_key_arr);

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealityProfile {
    pub id: uuid::Uuid,
    pub name: String,
    pub inbound_tag: String,
    pub listen: String,
    pub port: u16,
    pub dest: String,
    pub server_names: Vec<String>,
    pub private_key: String,
    pub public_key: String,
    pub short_ids: Vec<String>,
    pub fingerprint: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealityProfilePublic {
    pub id: uuid::Uuid,
    pub name: String,
    pub inbound_tag: String,
    pub listen: String,
    pub port: u16,
    pub dest: String,
    pub server_names: Vec<String>,
    pub public_key: String,
    pub short_ids: Vec<String>,
    pub fingerprint: String,
}

impl RealityProfile {
    pub fn validate_and_normalize(&mut self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Profile name is empty".to_string());
        }
        if self.inbound_tag.trim().is_empty() {
            return Err("Inbound tag is empty".to_string());
        }
        if self.listen.trim().is_empty() {
            return Err("Listen address is empty".to_string());
        }
        if self.listen.parse::<IpAddr>().is_err() {
            return Err(format!("Invalid listen IP address: {}", self.listen));
        }
        if self.dest.trim().is_empty() {
            return Err("Reality dest is empty".to_string());
        }
        let parts: Vec<&str> = self.dest.split(':').collect();
        if parts.len() != 2 || parts[0].trim().is_empty() || parts[1].trim().is_empty() {
            return Err(format!(
                "Reality dest must be host:port, got '{}'",
                self.dest
            ));
        }
        if parts[1].parse::<u16>().is_err() {
            return Err(format!(
                "Reality dest port must be a valid u16, got '{}'",
                parts[1]
            ));
        }

        if self.server_names.is_empty() {
            return Err("Reality server_names cannot be empty".to_string());
        }
        for name in &mut self.server_names {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err("Reality server_names contains an empty hostname".to_string());
            }
            *name = trimmed.to_lowercase();
        }

        if self.short_ids.is_empty() {
            return Err("Reality short_ids cannot be empty".to_string());
        }
        for sid in &mut self.short_ids {
            let trimmed = sid.trim();
            *sid = trimmed.to_lowercase();
            if sid.len() < 2 || sid.len() > 16 || sid.len() % 2 != 0 {
                return Err(format!(
                    "Reality short ID must be even length between 2 and 16 hex characters, got '{}'",
                    sid
                ));
            }
            if hex::decode(&*sid).is_err() {
                return Err(format!(
                    "Reality short ID must be a valid hex string, got '{}'",
                    sid
                ));
            }
        }

        let pk_bytes = base64::Engine::decode(&base64::prelude::BASE64_STANDARD, &self.private_key)
            .or_else(|_| hex::decode(&self.private_key))
            .map_err(|e| format!("Invalid base64/hex Reality private key: {}", e))?;
        if pk_bytes.len() != 32 {
            return Err(format!(
                "Reality private key must be 32 bytes, got {} bytes",
                pk_bytes.len()
            ));
        }

        let derived_pbk = derive_reality_public_key(&self.private_key)
            .ok_or_else(|| "Failed to derive public key".to_string())?;
        self.public_key = derived_pbk;

        Ok(())
    }

    pub fn to_public(&self) -> RealityProfilePublic {
        RealityProfilePublic {
            id: self.id,
            name: self.name.clone(),
            inbound_tag: self.inbound_tag.clone(),
            listen: self.listen.clone(),
            port: self.port,
            dest: self.dest.clone(),
            server_names: self.server_names.clone(),
            public_key: self.public_key.clone(),
            short_ids: self.short_ids.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }
}

impl Config {
    pub fn validate_and_normalize(&mut self) -> Result<(), String> {
        if !self.network.ipv4_only {
            return Err("ipv4_only must be true in this release".to_string());
        }
        let ipv4_only = self.network.ipv4_only;
        for profile in &mut self.reality_profiles {
            profile.validate_and_normalize()?;
            if ipv4_only {
                if let Ok(ip) = profile.listen.parse::<IpAddr>() {
                    if ip.is_ipv6() {
                        if let std::net::IpAddr::V6(v6) = ip {
                            if v6.is_unspecified() {
                                profile.listen = "0.0.0.0".to_string();
                            } else if v6.is_loopback() {
                                profile.listen = "127.0.0.1".to_string();
                            } else if let Some(ipv4) = v6.to_ipv4() {
                                profile.listen = ipv4.to_string();
                            } else {
                                return Err(format!(
                                    "IPv6 listener address '{}' in Reality profile '{}' is rejected under ipv4_only mode",
                                    profile.listen, profile.name
                                ));
                            }
                        }
                    }
                }
            }
        }
        for inbound in &mut self.inbounds {
            if ipv4_only && inbound.listen.is_ipv6() {
                if let std::net::IpAddr::V6(v6) = inbound.listen {
                    if v6.is_unspecified() {
                        inbound.listen = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
                    } else if v6.is_loopback() {
                        inbound.listen = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
                    } else if let Some(ipv4) = v6.to_ipv4() {
                        inbound.listen = std::net::IpAddr::V4(ipv4);
                    } else {
                        return Err(format!(
                            "IPv6 listener address '{}' in inbound '{}' is rejected under ipv4_only mode",
                            inbound.listen, inbound.tag
                        ));
                    }
                }
            }
            if inbound.protocol == "vless" {
                if let Some(ref mut ss) = inbound.stream_settings {
                    if ss.security == "reality" {
                        if let Some(ref mut rs) = ss.reality_settings {
                            rs.validate_and_normalize()?;
                        } else {
                            return Err(
                                "reality security set but reality_settings is missing".to_string()
                            );
                        }
                    }
                }
            }
        }
        if ipv4_only && self.api.listen.is_ipv6() {
            if let std::net::IpAddr::V6(v6) = self.api.listen {
                if v6.is_unspecified() {
                    self.api.listen = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
                } else if v6.is_loopback() {
                    self.api.listen = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
                } else if let Some(ipv4) = v6.to_ipv4() {
                    self.api.listen = std::net::IpAddr::V4(ipv4);
                } else {
                    return Err(format!(
                        "IPv6 listener address '{}' in API config is rejected under ipv4_only mode",
                        self.api.listen
                    ));
                }
            }
        }
        for rule in &self.routing.rules {
            if let Some(ref ips) = rule.ip {
                for ip_str in ips {
                    if ip_str.trim().is_empty() {
                        return Err("Empty IP/CIDR entry in routing rule".to_string());
                    }
                    match ip_str.parse::<ipnet::IpNet>() {
                        Ok(ipnet::IpNet::V4(_)) => {
                            // IPv4 CIDR — always accepted
                        }
                        Ok(ipnet::IpNet::V6(_)) if ipv4_only => {
                            return Err(format!(
                                "IPv6 CIDR '{}' is rejected under ipv4_only mode",
                                ip_str
                            ));
                        }
                        Ok(ipnet::IpNet::V6(_)) => {
                            // Dual-stack mode: IPv6 CIDR accepted
                        }
                        Err(_) => {
                            // Also try parsing as a bare IP (no prefix)
                            match ip_str.parse::<IpAddr>() {
                                Ok(IpAddr::V4(_)) => {}
                                Ok(IpAddr::V6(_)) if ipv4_only => {
                                    return Err(format!(
                                        "IPv6 address '{}' in routing rule is rejected under ipv4_only mode",
                                        ip_str
                                    ));
                                }
                                Ok(IpAddr::V6(_)) => {}
                                Err(_) => {
                                    return Err(format!(
                                        "Invalid IP/CIDR '{}' in routing rule",
                                        ip_str
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn migrate_if_needed(&mut self) -> bool {
        let mut migrated = false;

        if self.reality_profiles.is_empty() {
            for inbound in &self.inbounds {
                if inbound.protocol == "vless" {
                    if let Some(ref ss) = inbound.stream_settings {
                        if ss.security == "reality" {
                            if let Some(ref rs) = ss.reality_settings {
                                let profile = RealityProfile {
                                    id: uuid::Uuid::new_v4(),
                                    name: "Default VLESS Reality".to_string(),
                                    inbound_tag: inbound.tag.clone(),
                                    listen: inbound.listen.to_string(),
                                    port: inbound.port,
                                    dest: rs.dest.clone(),
                                    server_names: rs.server_names.clone(),
                                    private_key: rs.private_key.clone(),
                                    public_key: derive_reality_public_key(&rs.private_key)
                                        .unwrap_or_default(),
                                    short_ids: rs.short_ids.clone(),
                                    fingerprint: "chrome".to_string(),
                                    created_at: chrono::Utc::now().timestamp(),
                                    updated_at: chrono::Utc::now().timestamp(),
                                };
                                self.reality_profiles.push(profile);
                                migrated = true;
                            }
                        }
                    }
                }
            }
        }

        if self.routing_schema_version == 0 {
            if self.warp_domain_sets.is_empty() {
                self.warp_domain_sets.push(WarpDomainSet {
                    id: uuid::Uuid::new_v4(),
                    name: "Online Fix Compatibility".to_string(),
                    description: "Routes Online Fix traffic through WARP".to_string(),
                    exact_domains: vec!["online-fix.me".to_string()],
                    domain_suffixes: vec!["online-fix.me".to_string()],
                    enabled: true,
                    priority: 10,
                    scope: DomainRuleScope::Global,
                    created_at: chrono::Utc::now().timestamp(),
                    updated_at: chrono::Utc::now().timestamp(),
                });

                self.warp_domain_sets.push(WarpDomainSet {
                    id: uuid::Uuid::new_v4(),
                    name: "Google Search Compatibility".to_string(),
                    description: "Routes Google Search through WARP".to_string(),
                    exact_domains: vec!["www.google.com".to_string(), "google.com".to_string()],
                    domain_suffixes: vec![],
                    enabled: false,
                    priority: 5,
                    scope: DomainRuleScope::Global,
                    created_at: chrono::Utc::now().timestamp(),
                    updated_at: chrono::Utc::now().timestamp(),
                });

                self.warp_domain_sets.push(WarpDomainSet {
                    id: uuid::Uuid::new_v4(),
                    name: "Google Account Compatibility".to_string(),
                    description: "Routes Google Account through WARP".to_string(),
                    exact_domains: vec!["accounts.google.com".to_string()],
                    domain_suffixes: vec![
                        "googleusercontent.com".to_string(),
                        "gstatic.com".to_string(),
                    ],
                    enabled: false,
                    priority: 5,
                    scope: DomainRuleScope::Global,
                    created_at: chrono::Utc::now().timestamp(),
                    updated_at: chrono::Utc::now().timestamp(),
                });
            }

            if self.direct_exception_sets.is_empty() {
                self.direct_exception_sets.push(DirectExceptionSet {
                    id: uuid::Uuid::new_v4(),
                    name: "VoIP and Gaming Direct Exceptions".to_string(),
                    description: "Low-latency VoIP and gaming services".to_string(),
                    exact_domains: vec![],
                    domain_suffixes: vec![
                        "discord.gg".to_string(),
                        "discord.com".to_string(),
                        "steampowered.com".to_string(),
                    ],
                    enabled: true,
                    priority: 10,
                    scope: DomainRuleScope::Global,
                    created_at: chrono::Utc::now().timestamp(),
                    updated_at: chrono::Utc::now().timestamp(),
                });
            }
            self.routing_schema_version = 1;
            migrated = true;
        }

        for inbound in &mut self.inbounds {
            if let Some(ref mut clients) = inbound.settings.clients {
                for client in clients {
                    if client.browsing_warp_id.is_none() {
                        client.browsing_warp_id = Some(uuid::Uuid::new_v4().to_string());
                        migrated = true;
                    }
                    if client.low_latency_id.is_none() {
                        client.low_latency_id = Some(uuid::Uuid::new_v4().to_string());
                        migrated = true;
                    }
                }
            }
        }

        migrated
    }

    pub fn get_reality_profile_for_client(&self, client: &Client) -> Option<&RealityProfile> {
        if let Some(id) = client.reality_profile_id {
            self.reality_profiles.iter().find(|p| p.id == id)
        } else {
            self.reality_profiles
                .iter()
                .find(|p| {
                    p.name == "Default VLESS Reality"
                        || p.inbound_tag == "vless-inbound-443"
                        || p.inbound_tag == "vless-inbound"
                })
                .or_else(|| self.reality_profiles.first())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityClientParameters {
    pub server_address: String,
    pub server_port: u16,
    pub server_name: String,
    pub public_key: String,
    pub short_id: String,
    pub fingerprint: String,
    pub uuid: uuid::Uuid,
    pub profile_name: String,
}

impl RealityClientParameters {
    pub fn new(profile: &RealityProfile, client: &Client, fallback_address: &str) -> Self {
        let server_name = client
            .sni
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| profile.server_names.first().cloned().unwrap_or_default());

        Self {
            server_address: fallback_address.to_string(),
            server_port: profile.port,
            server_name,
            public_key: profile.public_key.clone(),
            short_id: profile.short_ids.first().cloned().unwrap_or_default(),
            fingerprint: profile.fingerprint.clone(),
            uuid: uuid::Uuid::parse_str(&client.id).unwrap_or_default(),
            profile_name: profile.name.clone(),
        }
    }

    pub fn from_config(config: &Config, fallback_address: &str) -> Result<Self, String> {
        let vless_inbound = config
            .inbounds
            .iter()
            .find(|i| i.protocol == "vless")
            .ok_or_else(|| "No VLESS inbound configured".to_string())?;

        let ss = vless_inbound
            .stream_settings
            .as_ref()
            .ok_or_else(|| "VLESS inbound is missing stream_settings".to_string())?;

        if ss.security != "reality" {
            return Err("VLESS inbound security is not reality".to_string());
        }

        let rs = ss
            .reality_settings
            .as_ref()
            .ok_or_else(|| "Reality settings are missing".to_string())?;

        let server_name = rs
            .server_names
            .first()
            .ok_or_else(|| "Reality server_names list is empty".to_string())?
            .clone();

        let public_key = derive_reality_public_key(&rs.private_key)
            .ok_or_else(|| "Failed to derive public key from Reality private key".to_string())?;

        let short_id = rs
            .short_ids
            .first()
            .ok_or_else(|| "Reality short_ids list is empty".to_string())?
            .clone();

        let server_address = fallback_address.to_string();
        let server_port = vless_inbound.port;

        Ok(Self {
            server_address,
            server_port,
            server_name,
            public_key,
            short_id,
            fingerprint: "chrome".to_string(),
            uuid: uuid::Uuid::new_v4(),
            profile_name: "Default Profile".to_string(),
        })
    }

    pub fn to_vless_uri(&self, name_or_email: &str) -> String {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("security", "reality");
        serializer.append_pair("sni", &self.server_name);
        serializer.append_pair("fp", &self.fingerprint);
        serializer.append_pair("pbk", &self.public_key);
        serializer.append_pair("sid", &self.short_id);
        serializer.append_pair("type", "tcp");
        serializer.append_pair("encryption", "none");
        let query_str = serializer.finish();

        let encoded_email =
            url::form_urlencoded::byte_serialize(name_or_email.as_bytes()).collect::<String>();

        format!(
            "vless://{}@{}:{}?{}#{}",
            self.uuid, self.server_address, self.server_port, query_str, encoded_email
        )
    }

    pub fn to_singbox_json(&self) -> String {
        let config = serde_json::json!({
            "dns": {
                "servers": [
                    {
                        "tag": "dns_direct",
                        "address": "1.1.1.1",
                        "detour": "direct"
                    },
                    {
                        "tag": "dns_direct_backup",
                        "address": "8.8.8.8",
                        "detour": "direct"
                    }
                ],
                "strategy": "ipv4_only"
            },
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "tun0",
                    "inet4_address": "172.19.0.1/30",
                    "auto_route": true,
                    "strict_route": true,
                    "stack": "system",
                    "mtu": 1400
                }
            ],
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "proxy",
                    "server": self.server_address,
                    "server_port": self.server_port,
                    "uuid": self.uuid.to_string(),
                    "flow": "",
                    "tls": {
                        "enabled": true,
                        "server_name": self.server_name,
                        "utls": {
                            "enabled": true,
                            "fingerprint": self.fingerprint
                        },
                        "reality": {
                            "enabled": true,
                            "public_key": self.public_key,
                            "short_id": self.short_id
                        }
                    }
                },
                {
                    "type": "direct",
                    "tag": "direct"
                },
                {
                    "type": "block",
                    "tag": "block"
                },
                {
                    "type": "dns",
                    "tag": "dns-out"
                }
            ],
            "route": {
                "rules": [
                    {
                        "protocol": "dns",
                        "outbound": "dns-out"
                    },
                    {
                        "network": ["udp"],
                        "outbound": "block"
                    },
                    {
                        "ip_version": 6,
                        "outbound": "block"
                    },
                    // Bypass the VPN server itself — use ip_cidr only for IPv4 literals,
                    // domain rule for hostnames (avoids invalid "hostname/32" CIDRs).
                    (if let Ok(std::net::IpAddr::V4(ip)) = self.server_address.parse::<std::net::IpAddr>() {
                        serde_json::json!({
                            "ip_cidr": [format!("{ip}/32")],
                            "outbound": "direct"
                        })
                    } else {
                        serde_json::json!({
                            "domain": [self.server_address.clone()],
                            "outbound": "direct"
                        })
                    }),
                    {
                        "port": [
                            9091,
                            9100
                        ],
                        "outbound": "direct"
                    }
                ]
            }
        });
        serde_json::to_string_pretty(&config).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_settings_validation() {
        let mut bad_settings = RealitySettings {
            dest: "aka.ms:443".to_string(),
            server_names: vec![],
            private_key: "hZHP8YPZFBGa3Cno3nepKfop/+KWy3YmpXq5WQdfryI=".to_string(),
            short_ids: vec!["da09ebd28dc215c8".to_string()],
        };
        assert!(bad_settings.validate_and_normalize().is_err());

        bad_settings.server_names = vec!["aka.ms".to_string()];
        bad_settings.short_ids = vec![];
        assert!(bad_settings.validate_and_normalize().is_err());

        bad_settings.short_ids = vec!["da09ebd28dc215c8".to_string()];
        bad_settings.private_key = "invalid-key".to_string();
        assert!(bad_settings.validate_and_normalize().is_err());

        bad_settings.private_key = "hZHP8YPZFBGa3Cno3nepKfop/+KWy3YmpXq5WQdfryI=".to_string();
        assert!(bad_settings.validate_and_normalize().is_ok());

        bad_settings.server_names = vec!["AkA.Ms".to_string()];
        assert!(bad_settings.validate_and_normalize().is_ok());
        assert_eq!(bad_settings.server_names[0], "aka.ms");
    }

    #[test]
    fn test_reality_client_params() {
        let rs = RealitySettings {
            dest: "aka.ms:443".to_string(),
            server_names: vec!["aka.ms".to_string()],
            private_key: "hZHP8YPZFBGa3Cno3nepKfop/+KWy3YmpXq5WQdfryI=".to_string(),
            short_ids: vec!["da09ebd28dc215c8".to_string()],
        };
        let inbound = InboundConfig {
            tag: "vless-inbound".to_string(),
            listen: "0.0.0.0".parse().unwrap(),
            port: 443,
            protocol: "vless".to_string(),
            settings: InboundSettings { clients: None },
            stream_settings: Some(StreamSettings {
                security: "reality".to_string(),
                tls_settings: None,
                reality_settings: Some(rs),
            }),
        };
        let config = Config {
            inbounds: vec![inbound],
            outbounds: vec![],
            routing: RoutingConfig { rules: vec![] },
            api: ApiConfig {
                listen: "0.0.0.0".parse().unwrap(),
                port: 9091,
                trusted_proxies: vec![],
            },
            reality_profiles: vec![],
            warp_domain_sets: vec![],
            direct_exception_sets: vec![],
            ..Default::default()
        };

        let mut params = RealityClientParameters::from_config(&config, "1.2.3.4").unwrap();
        params.uuid = uuid::Uuid::parse_str("ad60c2b2-cc0c-492a-89aa-c92330a10cc9").unwrap();
        assert_eq!(params.server_address, "1.2.3.4");
        assert_eq!(params.server_port, 443);
        assert_eq!(params.server_name, "aka.ms");
        assert_eq!(params.short_id, "da09ebd28dc215c8");

        let expected_pbk =
            derive_reality_public_key("hZHP8YPZFBGa3Cno3nepKfop/+KWy3YmpXq5WQdfryI=").unwrap();
        assert_eq!(params.public_key, expected_pbk);

        let uri = params.to_vless_uri("user@test.com");
        assert!(uri.contains("vless://ad60c2b2-cc0c-492a-89aa-c92330a10cc9@1.2.3.4:443"));
        assert!(uri.contains("security=reality"));
        assert!(uri.contains("sni=aka.ms"));
        assert!(uri.contains("fp=chrome"));
        assert!(uri.contains(&format!(
            "pbk={}",
            url::form_urlencoded::byte_serialize(expected_pbk.as_bytes()).collect::<String>()
        )));
        assert!(uri.contains("sid=da09ebd28dc215c8"));
        assert!(uri.contains("type=tcp"));
        assert!(uri.contains("encryption=none"));
        assert!(uri.contains("#user%40test.com"));

        assert!(!uri.contains("9OOhOXX8lH7Vk6bB57c0M_nmHlO7O8MBxpZU-d4biDI"));
        assert!(!uri.contains("334f665b6b753216"));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClientRouteMode {
    Smart,
    BrowsingWarp,
    LowLatencyDirect,
}
