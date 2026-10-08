use crate::config::{ClientRouteMode, Config, RoutingRule};
use std::collections::HashSet;

pub struct RouteModeTables {
    pub warp_exact: HashSet<String>,
    pub warp_suffixes: Vec<String>,
    pub direct_exact: HashSet<String>,
    pub direct_suffixes: Vec<String>,
    pub custom_rules: Vec<RoutingRule>,
}

impl RouteModeTables {
    pub fn compile(config: &Config) -> Self {
        let mut warp_exact = HashSet::new();
        let mut warp_suffixes = Vec::new();
        let mut direct_exact = HashSet::new();
        let mut direct_suffixes = Vec::new();

        for set in &config.warp_domain_sets {
            if set.enabled {
                for d in &set.exact_domains {
                    warp_exact.insert(d.to_lowercase());
                }
                for s in &set.domain_suffixes {
                    warp_suffixes.push(s.to_lowercase());
                }
            }
        }

        for set in &config.direct_exception_sets {
            if set.enabled {
                for d in &set.exact_domains {
                    direct_exact.insert(d.to_lowercase());
                }
                for s in &set.domain_suffixes {
                    direct_suffixes.push(s.to_lowercase());
                }
            }
        }

        Self {
            warp_exact,
            warp_suffixes,
            direct_exact,
            direct_suffixes,
            custom_rules: config.routing.rules.clone(),
        }
    }
}

pub fn match_domain_suffix(domain: &str, suffix: &str) -> bool {
    let domain = domain.to_lowercase();
    let suffix = suffix.to_lowercase();
    if domain == suffix {
        return true;
    }
    if domain.ends_with(&suffix) {
        let prefix_len = domain.len() - suffix.len();
        if prefix_len > 0 && domain.as_bytes()[prefix_len - 1] == b'.' {
            return true;
        }
    }
    false
}

fn matches_rule_domain(domain_pattern: &str, host: &str) -> bool {
    let host = host.to_lowercase();
    let pattern = domain_pattern.to_lowercase();
    if pattern.starts_with("domain:") {
        let suffix = &pattern["domain:".len()..];
        host == suffix
            || (host.ends_with(suffix)
                && host.as_bytes().get(host.len() - suffix.len() - 1) == Some(&b'.'))
    } else if pattern.starts_with("keyword:") {
        let keyword = &pattern["keyword:".len()..];
        host.contains(keyword)
    } else if pattern.starts_with("regexp:") {
        let regex_str = &pattern["regexp:".len()..];
        use once_cell::sync::Lazy;
        use parking_lot::Mutex;
        use std::collections::HashMap;
        static REGEX_CACHE: Lazy<Mutex<HashMap<String, Option<regex::Regex>>>> =
            Lazy::new(|| Mutex::new(HashMap::new()));
        let mut cache = REGEX_CACHE.lock();
        let entry = cache.entry(regex_str.to_string()).or_insert_with(|| {
            regex::Regex::new(regex_str).ok()
        });
        if let Some(re) = entry {
            re.is_match(&host)
        } else {
            host.contains(regex_str)
        }
    } else {
        host == pattern
            || (host.ends_with(&pattern)
                && host.as_bytes().get(host.len() - pattern.len() - 1) == Some(&b'.'))
    }
}

fn matches_cidr(cidr_str: &str, ip: &std::net::IpAddr) -> bool {
    let ipv4 = match ip {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => return false,
    };
    // Try parsing as CIDR (e.g. "10.0.0.0/8")
    if let Ok(net) = cidr_str.parse::<ipnet::Ipv4Net>() {
        return net.contains(ipv4);
    }
    // Try parsing as a bare IPv4 literal (exact match)
    if let Ok(std::net::IpAddr::V4(addr)) = cidr_str.parse::<std::net::IpAddr>() {
        return &addr == ipv4;
    }
    false
}

fn is_private_or_local(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if ip.is_loopback() {
            return true;
        }
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                ipv4.is_private()
                    || ipv4.is_link_local()
                    || ipv4.is_broadcast()
                    || ipv4.is_documentation()
            }
            std::net::IpAddr::V6(ipv6) => {
                let octets = ipv6.octets();
                (octets[0] & 0xfe) == 0xfc || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
            }
        }
    } else {
        false
    }
}

pub struct Router {}

impl Router {
    pub fn new() -> Self {
        Self {}
    }

    pub fn get_host(&self, dest_addr: &str) -> String {
        let dest_lower = dest_addr.to_lowercase();
        let host = if let Some(idx) = dest_lower.rfind(':') {
            if dest_lower.starts_with('[') && dest_lower.ends_with(']') {
                &dest_lower
            } else if dest_lower.contains(']') {
                let end = dest_lower.find(']').unwrap_or(dest_lower.len());
                &dest_lower[1..end]
            } else {
                &dest_lower[..idx]
            }
        } else {
            &dest_lower
        };
        host.to_string()
    }

    pub fn resolve_route(
        &self,
        mode: ClientRouteMode,
        dest_addr: &str,
        dest_port: u16,
        inbound_tag: &str,
        sni: &Option<String>,
        tables: &RouteModeTables,
    ) -> String {
        let host = self.get_host(dest_addr);

        // 1. Loop prevention and server infrastructure (bypass WARP for local/internal)
        if host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1" {
            return "direct".to_string();
        }
        if dest_port == 9091 || dest_port == 9100 || dest_port == 40000 {
            return "direct".to_string();
        }

        // 2. Local/private policy
        if is_private_or_local(&host) {
            return "direct".to_string();
        }

        // 3. Per-mode domain overrides
        // Smart:        default = direct (DO IP); warp_domain_sets override to WARP
        // BrowsingWarp: default = warp;           direct_exception_sets override to direct
        // LowLatency:   always direct
        let matched_mode_outbound = match mode {
            ClientRouteMode::LowLatencyDirect => None, // Let custom rules evaluate first (e.g. block rules)
            ClientRouteMode::BrowsingWarp => {
                let is_direct = self.matches_domain(
                    dest_addr,
                    sni,
                    &tables.direct_exact,
                    &tables.direct_suffixes,
                );
                if is_direct {
                    Some("direct".to_string())
                } else {
                    None
                }
            }
            ClientRouteMode::Smart => {
                let is_warp =
                    self.matches_domain(dest_addr, sni, &tables.warp_exact, &tables.warp_suffixes);
                if is_warp {
                    Some("warp".to_string())
                } else {
                    None
                }
            }
        };

        if let Some(outbound) = matched_mode_outbound {
            return outbound;
        }

        // 4. Existing custom routing rules (config.routing.rules)
        let host_ip = host.parse::<std::net::IpAddr>().ok();
        for rule in &tables.custom_rules {
            let mut matches = true;

            // Match domain
            if let Some(ref domains) = rule.domain {
                let mut domain_match = false;
                for d in domains {
                    if matches_rule_domain(d, &host) {
                        domain_match = true;
                        break;
                    }
                    if let Some(ref sni_str) = sni {
                        if matches_rule_domain(d, sni_str) {
                            domain_match = true;
                            break;
                        }
                    }
                }
                if !domain_match {
                    matches = false;
                }
            }

            // Match IP
            if matches {
                if let Some(ref ips) = rule.ip {
                    let mut ip_match = false;
                    if let Some(ref hip) = host_ip {
                        for ip_pattern in ips {
                            if matches_cidr(ip_pattern, hip) {
                                ip_match = true;
                                break;
                            }
                        }
                    }
                    if !ip_match {
                        matches = false;
                    }
                }
            }

            // Match port
            if matches {
                if let Some(ref ports) = rule.port {
                    if !ports.contains(&dest_port) {
                        matches = false;
                    }
                }
            }

            // Match inbound tag
            if matches {
                if let Some(ref inbounds) = rule.inbound_tag {
                    if !inbounds.contains(&inbound_tag.to_string()) {
                        matches = false;
                    }
                }
            }

            if matches {
                return rule.outbound_tag.clone();
            }
        }

        // 5. Default outbound per mode
        // Smart:        direct (show DO IP; WARP only for warp_domain_sets)
        // BrowsingWarp: warp  (all traffic through WARP; direct only for exception sets)
        // LowLatency:   direct (always bare internet)
        match mode {
            ClientRouteMode::Smart => "direct".to_string(),
            ClientRouteMode::BrowsingWarp => "warp".to_string(),
            ClientRouteMode::LowLatencyDirect => "direct".to_string(),
        }
    }

    fn matches_domain(
        &self,
        dest_addr: &str,
        sni: &Option<String>,
        exact: &HashSet<String>,
        suffixes: &[String],
    ) -> bool {
        let host = self.get_host(dest_addr);

        if exact.contains(&host) {
            return true;
        }
        for s in suffixes {
            if match_domain_suffix(&host, s) {
                return true;
            }
        }

        if let Some(ref sni_str) = sni {
            let sni_lower = sni_str.to_lowercase();
            if exact.contains(&sni_lower) {
                return true;
            }
            for s in suffixes {
                if match_domain_suffix(&sni_lower, s) {
                    return true;
                }
            }
        }

        false
    }
}
