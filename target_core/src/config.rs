use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub routing: RoutingConfig,
    pub api: ApiConfig,
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
    pub security: String, // "none" or "tls"
    pub tls_settings: Option<TlsSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    pub server_name: String,
    pub certificate_file: Option<String>,
    pub key_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundSettings {
    pub clients: Option<Vec<Client>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: String, // UUID
    pub email: Option<String>,
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
}
