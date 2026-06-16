use crate::config::{Config, RoutingRule};

pub struct Router {
    // Stores routing configuration mapping
}

impl Router {
    pub fn new() -> Self {
        Self {}
    }

    pub fn route(
        &self,
        inbound_tag: &str,
        dest_addr: &str,
        dest_port: u16,
        sni: &Option<String>,
        config: &Config,
    ) -> String {
        for rule in &config.routing.rules {
            if self.match_rule(rule, inbound_tag, dest_addr, dest_port, sni) {
                return rule.outbound_tag.clone();
            }
        }

        // Try to default to "freedom" tag if it exists in outbounds, otherwise first outbound, otherwise "freedom" string
        if config.outbounds.iter().any(|o| o.tag == "freedom") {
            "freedom".to_string()
        } else if let Some(outbound) = config.outbounds.first() {
            outbound.tag.clone()
        } else {
            "freedom".to_string()
        }
    }

    fn match_rule(
        &self,
        rule: &RoutingRule,
        inbound_tag: &str,
        dest_addr: &str,
        dest_port: u16,
        sni: &Option<String>,
    ) -> bool {
        // Match inbound tags
        if let Some(ref tags) = rule.inbound_tag {
            if !tags.iter().any(|t| t == inbound_tag) {
                return false;
            }
        }

        // Match ports
        if let Some(ref ports) = rule.port {
            if !ports.iter().any(|&p| p == dest_port) {
                return false;
            }
        }

        // Match sniffed domains or target domains
        if let Some(ref domains) = rule.domain {
            let mut matched = false;
            for domain_pattern in domains {
                // If there's an SNI, match against it
                if let Some(ref sni_str) = sni {
                    if sni_str.contains(domain_pattern) {
                        matched = true;
                        break;
                    }
                }
                // Match against destination address if it's a domain name
                if dest_addr.contains(domain_pattern) {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return false;
            }
        }

        // Match IPs
        if let Some(ref ips) = rule.ip {
            let mut matched = false;
            for ip_pattern in ips {
                if dest_addr == ip_pattern {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return false;
            }
        }

        true
    }
}
