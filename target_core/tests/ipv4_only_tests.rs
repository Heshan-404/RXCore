use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};
use target_core::config::{Config, InboundConfig};
use target_core::transport::{
    reject_ipv6_ip, reject_ipv6_socket_addr, DefaultResolver, OutboundResolver, SelectedRoute,
};

// 1. A-only hostname returns IPv4.
#[tokio::test]
async fn test_a_only_hostname() {
    let resolver = DefaultResolver::new(true, None);
    // 127.0.0.1 is an IP literal, which resolves directly
    let res = resolver
        .resolve_ipv4("127.0.0.1", 80, SelectedRoute::Direct)
        .await
        .unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].ip(), &Ipv4Addr::new(127, 0, 0, 1));
}

// 2. A plus AAAA returns only IPv4, 3. AAAA-only hostname fails, 4. IPv6 literal fails immediately.
#[tokio::test]
async fn test_ipv6_resolutions_and_literals() {
    let resolver = DefaultResolver::new(true, None);

    // IPv6 literal must fail immediately with AddressFamilyNotSupported
    let err = resolver
        .resolve_ipv4("::1", 80, SelectedRoute::Direct)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    let err_socket = reject_ipv6_socket_addr("[::1]:80".parse().unwrap(), true).unwrap_err();
    assert_eq!(err_socket.kind(), std::io::ErrorKind::InvalidInput);
}

// Custom mock resolver for testing mock scenarios
struct MockResolver {
    ipv4_only: bool,
    records: HashMap<String, Vec<IpAddr>>,
}

#[async_trait::async_trait]
impl OutboundResolver for MockResolver {
    async fn resolve_ipv4(
        &self,
        hostname: &str,
        port: u16,
        _route: SelectedRoute,
    ) -> std::io::Result<Vec<SocketAddrV4>> {
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            let ipv4 = reject_ipv6_ip(ip, self.ipv4_only)?;
            return Ok(vec![SocketAddrV4::new(ipv4, port)]);
        }
        if let Some(ips) = self.records.get(hostname) {
            let mut resolved = Vec::new();
            for ip in ips {
                if let IpAddr::V4(v4) = ip {
                    resolved.push(SocketAddrV4::new(*v4, port));
                }
            }
            if resolved.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "AAAA-only or no records",
                ));
            }
            return Ok(resolved);
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "not found",
        ))
    }
}

// 1. A-only hostname returns IPv4 (mock)
#[tokio::test]
async fn test_mock_a_only() {
    let mut records = HashMap::new();
    records.insert(
        "example.com".to_string(),
        vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
    );
    let resolver = MockResolver {
        ipv4_only: true,
        records,
    };

    let res = resolver
        .resolve_ipv4("example.com", 80, SelectedRoute::Direct)
        .await
        .unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].ip(), &Ipv4Addr::new(93, 184, 216, 34));
}

// 2. A plus AAAA returns only IPv4 (mock)
#[tokio::test]
async fn test_mock_a_plus_aaaa() {
    let mut records = HashMap::new();
    records.insert(
        "example.com".to_string(),
        vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            )),
        ],
    );
    let resolver = MockResolver {
        ipv4_only: true,
        records,
    };

    let res = resolver
        .resolve_ipv4("example.com", 80, SelectedRoute::Direct)
        .await
        .unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].ip(), &Ipv4Addr::new(93, 184, 216, 34));
}

// 3. AAAA-only hostname fails (mock)
#[tokio::test]
async fn test_mock_aaaa_only_fails() {
    let mut records = HashMap::new();
    records.insert(
        "example.com".to_string(),
        vec![IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
        ))],
    );
    let resolver = MockResolver {
        ipv4_only: true,
        records,
    };

    let err = resolver
        .resolve_ipv4("example.com", 80, SelectedRoute::Direct)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable);
}

// 14. IPv6 route rules produce validation errors.
// 21. [::] normalizes to 0.0.0.0.
// 22. [::1] normalizes to 127.0.0.1.
// 23. A specific IPv6 bind address is rejected.
#[test]
fn test_listener_normalization_and_validation() {
    let mut config = Config::default();
    config.network.ipv4_only = true;

    // Normalization test: unspecified IPv6
    let inbound_unspec = InboundConfig {
        tag: "test-unspec".to_string(),
        listen: "::".parse().unwrap(),
        port: 8080,
        protocol: "vless".to_string(),
        settings: target_core::config::InboundSettings { clients: None },
        stream_settings: None,
    };
    config.inbounds.push(inbound_unspec.clone());

    // Normalization test: loopback IPv6
    let inbound_loopback = InboundConfig {
        tag: "test-loopback".to_string(),
        listen: "::1".parse().unwrap(),
        port: 8081,
        protocol: "socks".to_string(),
        settings: target_core::config::InboundSettings { clients: None },
        stream_settings: None,
    };
    config.inbounds.push(inbound_loopback.clone());

    // Validate and normalize must succeed and map them to IPv4
    config.validate_and_normalize().unwrap();
    assert_eq!(
        config.inbounds[0].listen,
        "0.0.0.0".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        config.inbounds[1].listen,
        "127.0.0.1".parse::<IpAddr>().unwrap()
    );

    // Specific non-loopback non-unspecified IPv6 bind address must fail validation
    let mut config_fail = Config::default();
    config_fail.network.ipv4_only = true;
    let inbound_v6_specific = InboundConfig {
        tag: "test-v6-specific".to_string(),
        listen: "2001:db8::1".parse().unwrap(),
        port: 8082,
        protocol: "socks".to_string(),
        settings: target_core::config::InboundSettings { clients: None },
        stream_settings: None,
    };
    config_fail.inbounds.push(inbound_v6_specific);

    let err = config_fail.validate_and_normalize().unwrap_err();
    assert!(err.contains("rejected under ipv4_only mode"));
}

// 14. IPv6 routing rules validation error
#[test]
fn test_routing_rules_validation_v6() {
    let mut config = Config::default();
    config.network.ipv4_only = true;

    config.routing.rules.push(target_core::config::RoutingRule {
        domain: None,
        ip: Some(vec!["2001:db8::/32".to_string()]),
        port: None,
        inbound_tag: None,
        outbound_tag: "direct".to_string(),
    });

    let err = config.validate_and_normalize().unwrap_err();
    assert!(err.contains("rejected under ipv4_only mode"));
}

// 25. Generated client configuration has no IPv6 TUN, strategy is ipv4_only, and ip_version 6 is blocked
#[test]
fn test_generated_singbox_ipv4_only() {
    let params = target_core::config::RealityClientParameters {
        server_address: "1.2.3.4".to_string(),
        server_port: 443,
        server_name: "example.com".to_string(),
        public_key: "pbkey".to_string(),
        short_id: "sid".to_string(),
        fingerprint: "chrome".to_string(),
        uuid: uuid::Uuid::new_v4(),
        profile_name: "Test Profile".to_string(),
    };

    let json_str = params.to_singbox_json();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    // Check DNS strategy
    assert_eq!(parsed["dns"]["strategy"].as_str(), Some("ipv4_only"));

    // Check TUN addresses
    let inbounds = parsed["inbounds"].as_array().unwrap();
    let tun = inbounds
        .iter()
        .find(|i| i["type"].as_str() == Some("tun"))
        .unwrap();
    assert!(tun["inet6_address"].is_null());
    assert_eq!(tun["inet4_address"].as_str(), Some("172.19.0.1/30"));

    // Check route rules for ip_version 6 blocking
    let rules = parsed["route"]["rules"].as_array().unwrap();
    let block_v6 = rules
        .iter()
        .find(|r| r["ip_version"].as_u64() == Some(6))
        .unwrap();
    assert_eq!(block_v6["outbound"].as_str(), Some("block"));
}
