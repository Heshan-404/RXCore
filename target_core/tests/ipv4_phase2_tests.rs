use std::net::Ipv4Addr;
use target_core::config::{Config, RoutingRule};
use target_core::transport::dns_cache::DIRECT_DNS_CACHE;
use target_core::transport::{
    build_dns_query, parse_dns_response, parse_endpoint, DefaultResolver,
    SelectedRoute,
};

#[test]
fn test_parse_endpoint_various_formats() {
    // 1. IP literal with port (e.g. SOCKS5 proxy)
    let (host, port) = parse_endpoint("127.0.0.1:40000", 1080).unwrap();
    assert_eq!(host, "127.0.0.1");
    assert_eq!(port, 40000);

    // 2. Hostname with port
    let (host, port) = parse_endpoint("vpn.example.com:8443", 1080).unwrap();
    assert_eq!(host, "vpn.example.com");
    assert_eq!(port, 8443);

    // 3. Hostname without port
    let (host, port) = parse_endpoint("vpn.example.com", 1080).unwrap();
    assert_eq!(host, "vpn.example.com");
    assert_eq!(port, 1080);
}

#[tokio::test]
async fn test_warp_route_without_proxy_refused() {
    // 4. WARP route must fail immediately with InvalidInput if no outbound_proxy is set
    let resolver = DefaultResolver::new(true, None);
    let err = resolver
        .resolve_ipv4("example.com", 80, SelectedRoute::Warp)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("no WARP proxy is configured"));
}

#[test]
fn test_dns_transaction_id_validation() {
    // Build a query, get its randomised transaction ID
    let (mut mock_resp, txid) = build_dns_query("example.com");
    // Modify it to QR=1 (response flag)
    mock_resp[2] |= 0x80;

    // Construct a mocked DNS response with a MISMATCHED transaction ID (e.g. txid + 1)
    let bad_txid = txid.wrapping_add(1);
    mock_resp[0..2].copy_from_slice(&bad_txid.to_be_bytes());

    // Parsing must fail with transaction ID mismatch
    let err = parse_dns_response(&mock_resp, txid, "example.com").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("DNS txid mismatch"));
}

#[test]
fn test_dns_ttl_cache_operations() {
    let hostname = "cached.example.com";
    let port = 80;

    // 1. Initially it should be a cache miss
    assert!(DIRECT_DNS_CACHE.get(hostname, port).is_none());

    // 2. Insert positive resolution result
    DIRECT_DNS_CACHE.insert(hostname, &Ok((vec![Ipv4Addr::new(1, 2, 3, 4)], 300)));

    // 3. Cache hit check
    let hit = DIRECT_DNS_CACHE.get(hostname, port).unwrap().unwrap();
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].ip(), &std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

    // 4. Cache negative resolution result
    DIRECT_DNS_CACHE.insert(
        hostname,
        &Err(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "fail")),
    );
    let neg_hit = DIRECT_DNS_CACHE.get(hostname, port).unwrap();
    assert!(neg_hit.is_err());
}

#[test]
fn test_cidr_validation_rules() {
    let mut config = Config::default();
    config.network.ipv4_only = true;

    // 1. Valid IPv4 CIDR must pass validation
    config.routing.rules = vec![RoutingRule {
        domain: None,
        ip: Some(vec!["192.168.1.0/24".to_string()]),
        port: None,
        inbound_tag: None,
        outbound_tag: "direct".to_string(),
    }];
    assert!(config.validate_and_normalize().is_ok());

    // 2. Invalid CIDR prefix length (e.g. /999) must be rejected
    config.routing.rules = vec![RoutingRule {
        domain: None,
        ip: Some(vec!["1.2.3.4/999".to_string()]),
        port: None,
        inbound_tag: None,
        outbound_tag: "direct".to_string(),
    }];
    assert!(config.validate_and_normalize().is_err());

    // 3. Empty CIDR rule must be rejected
    config.routing.rules = vec![RoutingRule {
        domain: None,
        ip: Some(vec!["".to_string()]),
        port: None,
        inbound_tag: None,
        outbound_tag: "direct".to_string(),
    }];
    assert!(config.validate_and_normalize().is_err());

    // 4. IPv6 CIDR must be rejected when in ipv4_only mode
    config.routing.rules = vec![RoutingRule {
        domain: None,
        ip: Some(vec!["2001:db8::/32".to_string()]),
        port: None,
        inbound_tag: None,
        outbound_tag: "direct".to_string(),
    }];
    assert!(config.validate_and_normalize().is_err());
}

#[test]
fn test_singbox_json_generation_hostname_vs_ipv4() {
    use target_core::config::{Client, RealityProfile};

    // 1. Hostname server_address should generate "domain" rule
    let mut profile_host = RealityProfile {
        id: uuid::Uuid::new_v4(),
        name: "test-host".to_string(),
        inbound_tag: "vless".to_string(),
        listen: "127.0.0.1".to_string(),
        port: 443,
        dest: "example.com:443".to_string(),
        server_names: vec!["example.com".to_string()],
        private_key: "hZHP8YPZFBGa3Cno3nepKfop/+KWy3YmpXq5WQdfryI=".to_string(),
        public_key: "".to_string(),
        short_ids: vec!["da09ebd28dc215c8".to_string()],
        fingerprint: "chrome".to_string(),
        created_at: 0,
        updated_at: 0,
    };
    profile_host.validate_and_normalize().unwrap();

    let client = Client {
        id: uuid::Uuid::new_v4().to_string(),
        email: Some("test@example.com".to_string()),
        limit_ip: None,
        total_gb: None,
        expiry_time: None,
        speed_limit: None,
        remaining_gb: None,
        rx: None,
        tx: None,
        reality_profile_id: None,
        inbound_tag: None,
        browsing_warp_id: None,
        low_latency_id: None,
        sub_token_hash: None,
        sni: None,
    };

    let client_params_host = target_core::config::RealityClientParameters::new(
        &profile_host,
        &client,
        "vpn.example.com", // Hostname server address
    );

    let json_host = client_params_host.to_singbox_json();
    assert!(json_host.contains("\"domain\": ["));
    assert!(json_host.contains("\"vpn.example.com\""));
    assert!(!json_host.contains("vpn.example.com/32"));

    // 2. IPv4 literal server_address should generate "ip_cidr" rule
    let client_params_ip = target_core::config::RealityClientParameters::new(
        &profile_host,
        &client,
        "1.2.3.4", // IPv4 literal server address
    );

    let json_ip = client_params_ip.to_singbox_json();
    assert!(json_ip.contains("\"ip_cidr\": ["));
    assert!(json_ip.contains("\"1.2.3.4/32\""));
}

#[test]
fn test_low_latency_direct_block_rules() {
    use target_core::config::{ClientRouteMode, RoutingConfig};
    use target_core::router::{RouteModeTables, Router};

    let mut config = Config::default();
    config.routing = RoutingConfig {
        rules: vec![RoutingRule {
            domain: Some(vec!["regexp:.*ads.*".to_string(), "keyword:facebook".to_string()]),
            ip: None,
            port: None,
            inbound_tag: None,
            outbound_tag: "block".to_string(),
        }],
    };

    let tables = RouteModeTables::compile(&config);
    let router = Router::new();

    // 1. Matched by regexp rule
    let route = router.resolve_route(
        ClientRouteMode::LowLatencyDirect,
        "track.ads.example.com",
        443,
        "inbound-tag",
        &None,
        &tables,
    );
    assert_eq!(route, "block");

    // 2. Matched by keyword rule
    let route = router.resolve_route(
        ClientRouteMode::LowLatencyDirect,
        "facebook.com",
        443,
        "inbound-tag",
        &None,
        &tables,
    );
    assert_eq!(route, "block");

    // 3. Normal traffic goes to direct
    let route = router.resolve_route(
        ClientRouteMode::LowLatencyDirect,
        "google.com",
        443,
        "inbound-tag",
        &None,
        &tables,
    );
    assert_eq!(route, "direct");
}

