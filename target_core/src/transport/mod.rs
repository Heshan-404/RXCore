pub mod dns_cache;
pub mod mux;
pub mod reality;
pub mod tls;


use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use dns_parser::{Packet, Opcode, QueryType, QueryClass, ResponseCode, Class};

pub fn reject_ipv6_ip(ip: IpAddr, ipv4_only: bool) -> io::Result<Ipv4Addr> {
    match ip {
        IpAddr::V4(ipv4) => Ok(ipv4),
        IpAddr::V6(ipv6) => {
            if ipv4_only {
                static LAST_LOG: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let last = LAST_LOG.load(std::sync::atomic::Ordering::Relaxed);
                if now >= last + 2
                    && LAST_LOG
                        .compare_exchange(
                            last,
                            now,
                            std::sync::atomic::Ordering::Relaxed,
                            std::sync::atomic::Ordering::Relaxed,
                        )
                        .is_ok()
                {
                    tracing::debug!("IPv6 destination rejected because IPv4-only mode is enabled.");
                }
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv6 is rejected under IPv4-only mode",
                ))
            } else if let Some(ipv4) = ipv6.to_ipv4() {
                Ok(ipv4)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Cannot represent non-mapped IPv6 address as IPv4",
                ))
            }
        }
    }
}

pub fn reject_ipv6_socket_addr(addr: SocketAddr, ipv4_only: bool) -> io::Result<SocketAddrV4> {
    let ipv4 = reject_ipv6_ip(addr.ip(), ipv4_only)?;
    Ok(SocketAddrV4::new(ipv4, addr.port()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedRoute {
    Direct,
    Warp,
}

#[async_trait::async_trait]
pub trait OutboundResolver: Send + Sync {
    async fn resolve_ipv4(
        &self,
        hostname: &str,
        port: u16,
        route: SelectedRoute,
    ) -> std::io::Result<Vec<std::net::SocketAddrV4>>;
}

/// Parse a `host:port` or bare `host` string into `(host, port)` without
/// ever appending a second port when the input already contains one.
/// This fixes the double-port bug (`127.0.0.1:40000:1080`) that occurred when
/// a WARP proxy address like `"127.0.0.1:40000"` was passed directly to
/// `resolve_ipv4(..., 1080, ...)` as if it were a bare hostname.
pub fn parse_endpoint(
    input: &str,
    default_port: u16,
) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Empty endpoint address".into());
    }

    if input.contains('[') || input.contains(']') || input.chars().filter(|&c| c == ':').count() > 1 {
        return Err("IPv6 addresses are rejected under IPv4-only mode".into());
    }

    if let Some(colon) = input.rfind(':') {
        let host = &input[..colon];
        let port_str = &input[colon + 1..];
        if port_str.is_empty() {
            return Err("Endpoint has trailing colon but no port".into());
        }
        let port = port_str.parse::<u16>()?;
        if port == 0 {
            return Err("Port 0 is invalid".into());
        }
        if host.trim().is_empty() {
            return Err("Endpoint has empty host".into());
        }
        return Ok((host.to_string(), port));
    }

    if default_port == 0 {
        return Err("Default port 0 is invalid".into());
    }
    Ok((input.to_string(), default_port))
}

pub fn build_dns_query(hostname: &str) -> (Vec<u8>, u16) {
    let txid: u16 = rand::random();
    let mut query = Vec::with_capacity(30 + hostname.len());
    query.extend_from_slice(&txid.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]); // QR=0 Opcode=0 RD=1
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR
    for part in hostname.split('.') {
        if !part.is_empty() {
            query.push(part.len() as u8);
            query.extend_from_slice(part.as_bytes());
        }
    }
    query.push(0);
    query.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    query.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    (query, txid)
}

pub fn parse_dns_response(
    resp: &[u8],
    expected_txid: u16,
    expected_hostname: &str,
) -> std::io::Result<(Vec<std::net::Ipv4Addr>, u32)> {
    let packet = Packet::parse(resp).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("DNS parse error: {:?}", e),
        )
    })?;

    if packet.header.id != expected_txid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS txid mismatch",
        ));
    }

    if packet.header.query {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS message is a query, expected response",
        ));
    }

    if packet.header.opcode != Opcode::StandardQuery {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS opcode is not StandardQuery",
        ));
    }

    if packet.header.response_code != ResponseCode::NoError {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("DNS response error code: {:?}", packet.header.response_code),
        ));
    }

    if packet.header.truncated {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS response is truncated",
        ));
    }

    if packet.questions.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS response has no questions",
        ));
    }

    let question = &packet.questions[0];
    let qname_str = question.qname.to_string();
    if qname_str.trim_end_matches('.') != expected_hostname.trim_end_matches('.') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS question name mismatch",
        ));
    }

    if question.qtype != QueryType::A {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS question type is not A",
        ));
    }

    if question.qclass != QueryClass::IN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS question class is not IN",
        ));
    }

    let mut resolved = Vec::new();
    let mut min_ttl = u32::MAX;
    for answer in &packet.answers {
        if answer.cls != Class::IN {
            continue;
        }
        if let dns_parser::rdata::RData::A(a_rec) = answer.data {
            let ip = a_rec.0;
            if !resolved.contains(&ip) {
                resolved.push(ip);
                if answer.ttl < min_ttl {
                    min_ttl = answer.ttl;
                }
            }
        }
    }

    if resolved.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "No IPv4 addresses found in DNS answer",
        ));
    }

    Ok((resolved, min_ttl))
}

pub async fn resolve_dns_over_tcp_socks(
    hostname: &str,
    dns_server: &str,
    outbound_proxy: &str,
) -> std::io::Result<(Vec<std::net::Ipv4Addr>, u32)> {
    let (dns_host, dns_port) = parse_endpoint(dns_server, 53)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let mut stream = dial_tcp(
        &dns_host,
        dns_port,
        &None,
        &Some(outbound_proxy.to_string()),
    )
    .await
    .map_err(std::io::Error::other)?;
    
    let (query_payload, txid) = build_dns_query(hostname);
    let mut tcp_msg = Vec::with_capacity(2 + query_payload.len());
    tcp_msg.extend_from_slice(&(query_payload.len() as u16).to_be_bytes());
    tcp_msg.extend_from_slice(&query_payload);
    stream.write_all(&tcp_msg).await?;
    
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    const MAX_DNS_RESP: usize = 4096;
    if resp_len > MAX_DNS_RESP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("DNS response too large: {resp_len} bytes"),
        ));
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    parse_dns_response(&resp, txid, hostname)
}

pub struct DefaultResolver {
    pub ipv4_only: bool,
    pub outbound_proxy: Option<String>,
}

impl DefaultResolver {
    pub fn new(ipv4_only: bool, outbound_proxy: Option<String>) -> Self {
        Self {
            ipv4_only,
            outbound_proxy,
        }
    }

    pub async fn resolve_ipv4(
        &self,
        hostname: &str,
        port: u16,
        route: SelectedRoute,
    ) -> std::io::Result<Vec<SocketAddrV4>> {
        OutboundResolver::resolve_ipv4(self, hostname, port, route).await
    }
}

#[async_trait::async_trait]
impl OutboundResolver for DefaultResolver {
    async fn resolve_ipv4(
        &self,
        hostname: &str,
        port: u16,
        route: SelectedRoute,
    ) -> std::io::Result<Vec<std::net::SocketAddrV4>> {
        if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
            let ipv4 = reject_ipv6_ip(ip, self.ipv4_only)?;
            return Ok(vec![std::net::SocketAddrV4::new(ipv4, port)]);
        }

        // Try cache first
        let cache = match route {
            SelectedRoute::Direct => &dns_cache::DIRECT_DNS_CACHE,
            SelectedRoute::Warp => &dns_cache::WARP_DNS_CACHE,
        };
        if let Some(cached_res) = cache.get(hostname, port) {
            return cached_res;
        }

        let key = hostname.to_lowercase();
        let self_ipv4_only = self.ipv4_only;
        let self_outbound_proxy = self.outbound_proxy.clone();
        let hostname_str = hostname.to_string();

        let lookup_fut = async move {
            match route {
                SelectedRoute::Direct => {
                    let addrs =
                        tokio::net::lookup_host(format!("{}:{}", hostname_str, port)).await?;
                    let mut resolved = Vec::new();
                    let mut seen = std::collections::HashSet::new();
                    for addr in addrs {
                        if let std::net::SocketAddr::V4(v4) = addr {
                            let ip = *v4.ip();
                            if seen.insert(ip.octets()) {
                                resolved.push(ip);
                            }
                        } else if !self_ipv4_only {
                            if let std::net::SocketAddr::V6(v6) = addr {
                                if let Some(ipv4) = v6.ip().to_ipv4() {
                                    if seen.insert(ipv4.octets()) {
                                        resolved.push(ipv4);
                                    }
                                }
                            }
                        }
                    }
                    if resolved.is_empty() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::AddrNotAvailable,
                            "No IPv4 addresses resolved",
                        ));
                    }
                    Ok((resolved, 300))
                }
                SelectedRoute::Warp => {
                    let proxy = match &self_outbound_proxy {
                        Some(p) => p.clone(),
                        None => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "WARP route selected but no WARP proxy is configured; \
                                 refusing to fall back to system DNS (would cause DNS leak)",
                            ));
                        }
                    };
                    let dns_servers = ["1.1.1.1", "8.8.8.8"];
                    
                    let warp_dns_res = tokio::time::timeout(std::time::Duration::from_millis(2500), async {
                        let mut last_err = None;
                        for dns in dns_servers {
                            match resolve_dns_over_tcp_socks(&hostname_str, dns, &proxy).await {
                                Ok((ips, ttl)) if !ips.is_empty() => {
                                    return Ok((ips, ttl));
                                }
                                Ok(_) => {}
                                Err(e) => last_err = Some(e),
                            }
                        }
                        Err(last_err.unwrap_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::AddrNotAvailable,
                                "WARP DNS: all servers returned no IPv4 addresses",
                            )
                        }))
                    })
                    .await;

                    match warp_dns_res {
                        Ok(res) => res,
                        Err(_) => Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "WARP DNS query timed out (overall 2.5s deadline reached)",
                        )),
                    }
                }
            }
        };

        let sf = match route {
            SelectedRoute::Direct => &dns_cache::DIRECT_SINGLE_FLIGHT,
            SelectedRoute::Warp => &dns_cache::WARP_SINGLE_FLIGHT,
        };

        let result = sf.execute(&key, || lookup_fut).await;
        
        cache.insert(hostname, &result);
        
        match result {
            Ok((ips, _)) => {
                let mapped = ips
                    .iter()
                    .map(|&ip| std::net::SocketAddrV4::new(ip, port))
                    .collect();
                Ok(mapped)
            }
            Err(e) => Err(e),
        }
    }
}

pub async fn dial_tcp(
    dest_host: &str,
    dest_port: u16,
    bind_ip: &Option<String>,
    outbound_proxy: &Option<String>,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let ipv4_only = crate::config::is_ipv4_only();
    let resolver = DefaultResolver::new(ipv4_only, outbound_proxy.clone());

    if let Some(ref proxy_addr) = outbound_proxy {
        let (proxy_host, proxy_port) = parse_endpoint(proxy_addr, 1080)?;
        let proxy_addrs = resolver
            .resolve_ipv4(&proxy_host, proxy_port, SelectedRoute::Direct)
            .await?;

        let resolved_dest_ips = if let Ok(ip_addr) = dest_host.parse::<std::net::IpAddr>() {
            let ipv4 = reject_ipv6_ip(ip_addr, ipv4_only)?;
            vec![ipv4]
        } else if ipv4_only {
            let resolved = resolver
                .resolve_ipv4(dest_host, dest_port, SelectedRoute::Warp)
                .await?;
            resolved.into_iter().map(|sa| *sa.ip()).collect()
        } else {
            Vec::new()
        };

        let overall_deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
        let mut last_socks_err = None;

        if !resolved_dest_ips.is_empty() {
            for dest_ip in resolved_dest_ips {
                if std::time::Instant::now() >= overall_deadline {
                    last_socks_err = Some(Box::new(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Overall SOCKS dial deadline reached",
                    )) as Box<dyn std::error::Error + Send + Sync>);
                    break;
                }

                let mut stream_res = None;
                for addr in &proxy_addrs {
                    let res = if let Some(ref ip_str) = bind_ip {
                        dial_tcp_with_bind(&addr.to_string(), ip_str).await
                    } else {
                        let s_addr = SocketAddr::V4(*addr);
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(2),
                            TcpStream::connect(s_addr),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => Ok(stream),
                            Ok(Err(e)) => Err(e.into()),
                            Err(_) => Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "connect timed out",
                            )
                            .into()),
                        }
                    };
                    if let Ok(s) = res {
                        let _ = s.set_nodelay(true);
                        stream_res = Some(s);
                        break;
                    }
                }

                let mut stream = match stream_res {
                    Some(s) => s,
                    None => {
                        last_socks_err = Some(Box::new(std::io::Error::new(
                            std::io::ErrorKind::AddrNotAvailable,
                            "Failed to connect to SOCKS proxy",
                        )) as Box<dyn std::error::Error + Send + Sync>);
                        continue;
                    }
                };

                let handshake_res = async {
                    stream.write_all(&[5, 1, 0]).await?;
                    let mut resp = [0u8; 2];
                    stream.read_exact(&mut resp).await?;
                    if resp[0] != 5 || resp[1] != 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "SOCKS5 auth failed",
                        ));
                    }

                    let mut req = Vec::with_capacity(30);
                    req.push(5);
                    req.push(1); // CONNECT
                    req.push(0);
                    req.push(1); // ATYP: IPv4
                    req.extend_from_slice(&dest_ip.octets());
                    req.extend_from_slice(&dest_port.to_be_bytes());

                    stream.write_all(&req).await?;
                    let mut reply = [0u8; 4];
                    stream.read_exact(&mut reply).await?;
                    if reply[0] != 5 || reply[1] != 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "SOCKS5 connect failed",
                        ));
                    }

                    let atyp = reply[3];
                    match atyp {
                        1 => {
                            let mut discard = [0u8; 6];
                            stream.read_exact(&mut discard).await?;
                        }
                        3 => {
                            let mut len_buf = [0u8; 1];
                            stream.read_exact(&mut len_buf).await?;
                            let domain_len = len_buf[0] as usize;
                            let mut discard = vec![0u8; domain_len + 2];
                            stream.read_exact(&mut discard).await?;
                        }
                        4 => {
                            let mut discard = [0u8; 18];
                            stream.read_exact(&mut discard).await?;
                        }
                        _ => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Invalid SOCKS5 address type",
                            ))
                        }
                    }
                    Ok(stream)
                }
                .await;

                match handshake_res {
                    Ok(s) => return Ok(s),
                    Err(e) => {
                        last_socks_err =
                            Some(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
                    }
                }
            }
            return Err(last_socks_err.unwrap_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "All resolved SOCKS destination connect attempts failed",
                )) as Box<dyn std::error::Error + Send + Sync>
            }));
        }

        // Fallback for non-ipv4_only (unreachable)
        let mut stream_res = None;
        let mut last_err = None;
        for attempt in 1..=3 {
            for addr in &proxy_addrs {
                let res = if let Some(ref ip_str) = bind_ip {
                    dial_tcp_with_bind(&addr.to_string(), ip_str).await
                } else {
                    let s_addr = SocketAddr::V4(*addr);
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        TcpStream::connect(s_addr),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => Ok(stream),
                        Ok(Err(e)) => Err(e.into()),
                        Err(_) => Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "connect timed out",
                        )
                        .into()),
                    }
                };
                match res {
                    Ok(s) => {
                        let _ = s.set_nodelay(true);
                        stream_res = Some(s);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                    }
                }
            }
            if stream_res.is_some() {
                break;
            }
            if attempt < 3 {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
        let mut stream = match stream_res {
            Some(s) => s,
            None => return Err(last_err.unwrap()),
        };
        stream.write_all(&[5, 1, 0]).await?;
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;
        if resp[0] != 5 || resp[1] != 0 {
            return Err(Box::from("SOCKS5 auth failed"));
        }
        let mut req = Vec::with_capacity(30);
        req.push(5);
        req.push(1);
        req.push(0);
        req.push(3);
        req.push(dest_host.len() as u8);
        req.extend_from_slice(dest_host.as_bytes());
        req.extend_from_slice(&dest_port.to_be_bytes());
        stream.write_all(&req).await?;
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await?;
        if reply[0] != 5 || reply[1] != 0 {
            return Err(Box::from("SOCKS5 connect failed"));
        }
        let atyp = reply[3];
        match atyp {
            1 => {
                let mut discard = [0u8; 6];
                stream.read_exact(&mut discard).await?;
            }
            3 => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let domain_len = len_buf[0] as usize;
                let mut discard = vec![0u8; domain_len + 2];
                stream.read_exact(&mut discard).await?;
            }
            4 => {
                let mut discard = [0u8; 18];
                stream.read_exact(&mut discard).await?;
            }
            _ => return Err(Box::from("Invalid SOCKS5 address type")),
        }
        Ok(stream)
    } else {
        let resolved_addrs = if let Ok(ip_addr) = dest_host.parse::<std::net::IpAddr>() {
            let ipv4 = reject_ipv6_ip(ip_addr, ipv4_only)?;
            vec![SocketAddrV4::new(ipv4, dest_port)]
        } else {
            resolver
                .resolve_ipv4(dest_host, dest_port, SelectedRoute::Direct)
                .await?
        };
        let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
        for addr in resolved_addrs {
            let res: Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> =
                if let Some(ref ip_str) = bind_ip {
                    if ipv4_only {
                        if let Ok(b) = ip_str.parse::<IpAddr>() {
                            if b.is_ipv6() {
                                last_err = Some(Box::new(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "IPv6 bind address rejected under ipv4_only mode",
                                )));
                                continue;
                            }
                        }
                    }
                    dial_tcp_with_bind(&addr.to_string(), ip_str).await
                } else {
                    let s_addr = SocketAddr::V4(addr);
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        TcpStream::connect(s_addr),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => Ok(stream),
                        Ok(Err(e)) => Err(e.into()),
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "connect timed out",
                        )
                        .into()),
                    }
                };
            match res {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(stream);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            Box::new(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "No addresses resolved",
            ))
        }))
    }
}

pub async fn dial_tcp_with_bind(
    target_addr: &str,
    bind_ip_str: &str,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    use socket2::{Domain, Protocol, Socket, Type};

    let ipv4_only = crate::config::is_ipv4_only();
    if ipv4_only {
        let bind_ip: std::net::IpAddr = bind_ip_str.parse()?;
        if bind_ip.is_ipv6() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv6 bind address is rejected under IPv4-only mode",
            )
            .into());
        }
        let bind_addr = SocketAddr::new(bind_ip, 0);

        let (host, port) = parse_endpoint(target_addr, 80)?;
        let resolver = DefaultResolver::new(true, None);
        let resolved = resolver
            .resolve_ipv4(&host, port, SelectedRoute::Direct)
            .await?;

        let overall_deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
        let mut last_err: Option<std::io::Error> = None;

        for target_v4 in resolved {
            if std::time::Instant::now() >= overall_deadline {
                last_err = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Overall dial_tcp_with_bind deadline reached",
                ));
                break;
            }

            let target = SocketAddr::V4(target_v4);
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_nonblocking(true)?;
            let _ = socket.set_nodelay(true);
            let _ = socket.set_recv_buffer_size(131072);
            let _ = socket.set_send_buffer_size(131072);
            #[cfg(target_os = "linux")]
            {
                let _ = socket.set_value(libc::SOL_TCP, libc::TCP_CONGESTION, b"bbr\0");
                let _ = socket.set_value(
                    libc::SOL_TCP,
                    libc::TCP_QUICKACK,
                    &1i32.to_ne_bytes(),
                );
            }

            if let Err(e) = socket.bind(&bind_addr.into()) {
                last_err = Some(e);
                continue;
            }

            let attempt_timeout = std::time::Duration::from_secs(3).min(
                overall_deadline.saturating_duration_since(std::time::Instant::now()),
            );

            let connect_res = match socket.connect(&target.into()) {
                Ok(_) => {
                    let std_tcp: std::net::TcpStream = socket.into();
                    let tcp = TcpStream::from_std(std_tcp)?;
                    if tcp.take_error()?.is_none() {
                        Ok(tcp)
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "SO_ERROR set on socket",
                        ))
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let std_tcp: std::net::TcpStream = socket.into();
                    let tcp = TcpStream::from_std(std_tcp)?;
                    match tokio::time::timeout(attempt_timeout, tcp.writable()).await {
                        Ok(Ok(())) => {
                            if tcp.take_error()?.is_none() {
                                Ok(tcp)
                            } else {
                                Err(std::io::Error::new(
                                    std::io::ErrorKind::ConnectionRefused,
                                    "SO_ERROR set on socket",
                                ))
                            }
                        }
                        Ok(Err(e)) => Err(e),
                        Err(_) => Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "nonblocking connect timed out awaiting writability",
                        )),
                    }
                }
                Err(e) => Err(e),
            };

            match connect_res {
                Ok(tcp) => return Ok(tcp),
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        let err: Box<dyn std::error::Error + Send + Sync> = last_err
            .map(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            .unwrap_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "No addresses resolved or bind failed",
                ))
            });
        Err(err)
    } else {
        let bind_ip: std::net::IpAddr = bind_ip_str.parse()?;
        let bind_addr = SocketAddr::new(bind_ip, 0);

        let mut target_addrs: Vec<SocketAddr> =
            tokio::net::lookup_host(target_addr).await?.collect();
        target_addrs.sort_by_key(|addr| !addr.is_ipv6());

        let mut last_err: Option<std::io::Error> = None;
        for target in target_addrs {
            let domain = if target.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_nonblocking(true)?;
            if target.is_ipv6() == bind_ip.is_ipv6() {
                if let Err(e) = socket.bind(&bind_addr.into()) {
                    last_err = Some(e);
                    continue;
                }
            }
            match socket.connect(&target.into()) {
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
            let _ = socket.set_nodelay(true);
            let _ = socket.set_recv_buffer_size(131072);
            let _ = socket.set_send_buffer_size(131072);
            #[cfg(target_os = "linux")]
            {
                let _ = socket.set_value(libc::SOL_TCP, libc::TCP_CONGESTION, b"bbr\0");
                let _ = socket.set_value(
                    libc::SOL_TCP,
                    libc::TCP_QUICKACK,
                    &1i32.to_ne_bytes(),
                );
            }
            let std_tcp: std::net::TcpStream = socket.into();
            let tcp = TcpStream::from_std(std_tcp)?;
            return Ok(tcp);
        }
        let err: Box<dyn std::error::Error + Send + Sync> = last_err
            .map(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            .unwrap_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "No addresses resolved",
                ))
            });
        Err(err)
    }
}

pub struct Socks5UdpAssociate {
    pub association_stream: TcpStream,
    pub proxy_udp_addr: SocketAddr,
}

pub async fn socks5_udp_associate(
    proxy_addr: &str,
    bind_ip: &Option<String>,
) -> Result<Socks5UdpAssociate, Box<dyn std::error::Error + Send + Sync>> {
    let proxy_addr_parsed = if proxy_addr.contains(':') {
        proxy_addr.to_string()
    } else {
        format!("{}:1080", proxy_addr)
    };
    let mut stream_res = None;
    let mut last_err = None;
    for attempt in 1..=3 {
        let res = if let Some(ref ip_str) = bind_ip {
            dial_tcp_with_bind(&proxy_addr_parsed, ip_str).await
        } else {
            TcpStream::connect(&proxy_addr_parsed)
                .await
                .map_err(Into::into)
        };
        match res {
            Ok(s) => {
                stream_res = Some(s);
                break;
            }
            Err(e) => {
                last_err = Some(e);
                if attempt < 3 {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
    }
    let mut stream = match stream_res {
        Some(s) => s,
        None => return Err(last_err.unwrap()),
    };
    stream.write_all(&[5, 1, 0]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 5 || resp[1] != 0 {
        return Err(Box::from("SOCKS5 auth failed for UDP associate"));
    }
    let req = vec![5, 3, 0, 1, 0, 0, 0, 0, 0, 0];
    stream.write_all(&req).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 5 || reply[1] != 0 {
        return Err(Box::from("SOCKS5 UDP associate request failed"));
    }
    let atyp = reply[3];
    let proxy_udp_addr = match atyp {
        1 => {
            let mut ip_port = [0u8; 6];
            stream.read_exact(&mut ip_port).await?;
            let octets: [u8; 4] = ip_port[0..4].try_into()?;
            let port = u16::from_be_bytes([ip_port[4], ip_port[5]]);
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)), port)
        }
        4 => {
            if crate::config::is_ipv4_only() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "IPv6 UDP associate reply rejected",
                )
                .into());
            }
            let mut ip_port = [0u8; 18];
            stream.read_exact(&mut ip_port).await?;
            let octets: [u8; 16] = ip_port[0..16].try_into()?;
            let port = u16::from_be_bytes([ip_port[16], ip_port[17]]);
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)), port)
        }
        _ => return Err(Box::from("Unsupported address type in UDP associate reply")),
    };
    Ok(Socks5UdpAssociate {
        association_stream: stream,
        proxy_udp_addr,
    })
}

pub fn wrap_socks5_udp_host(
    dest_host: &str,
    dest_port: u16,
    payload: &[u8],
    out_buf: &mut Vec<u8>,
) {
    out_buf.clear();
    out_buf.push(0);
    out_buf.push(0);
    out_buf.push(0);
    if let Ok(ip_addr) = dest_host.parse::<std::net::IpAddr>() {
        match ip_addr {
            std::net::IpAddr::V4(ipv4) => {
                out_buf.push(1);
                out_buf.extend_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                out_buf.push(4);
                out_buf.extend_from_slice(&ipv6.octets());
            }
        }
    } else {
        out_buf.push(3);
        out_buf.push(dest_host.len() as u8);
        out_buf.extend_from_slice(dest_host.as_bytes());
    }
    out_buf.extend_from_slice(&dest_port.to_be_bytes());
    out_buf.extend_from_slice(payload);
}

pub fn parse_socks5_udp(
    buf: &[u8],
) -> Result<(std::net::IpAddr, u16, usize), Box<dyn std::error::Error + Send + Sync>> {
    if buf.len() < 4 {
        return Err(Box::from("Buffer too short for SOCKS5 UDP header"));
    }
    let atyp = buf[3];
    let mut offset = 4;
    let src_ip = match atyp {
        1 => {
            if buf.len() < 10 {
                return Err(Box::from("Buffer too short for SOCKS5 UDP IPv4 header"));
            }
            let octets: [u8; 4] = buf[offset..offset + 4].try_into()?;
            offset += 4;
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets))
        }
        4 => {
            if buf.len() < 22 {
                return Err(Box::from("Buffer too short for SOCKS5 UDP IPv6 header"));
            }
            let octets: [u8; 16] = buf[offset..offset + 16].try_into()?;
            offset += 16;
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        _ => return Err(Box::from("Unsupported SOCKS5 UDP address type")),
    };
    let src_port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    offset += 2;
    Ok((src_ip, src_port, offset))
}

#[cfg(target_os = "linux")]
pub trait SocketValueExt {
    fn set_value(&self, level: i32, name: i32, value: &[u8]) -> std::io::Result<()>;
}

#[cfg(target_os = "linux")]
impl SocketValueExt for socket2::Socket {
    fn set_value(&self, level: i32, name: i32, value: &[u8]) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let fd = self.as_raw_fd();
        let res = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                value.as_ptr() as *const libc::c_void,
                value.len() as libc::socklen_t,
            )
        };
        if res == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

// --- Rate Limited Bidirectional Copy Helpers ---

fn reserve_quota(remaining: &std::sync::atomic::AtomicI64, requested: usize) -> usize {
    let mut current = remaining.load(std::sync::atomic::Ordering::Acquire);

    loop {
        if current == -1 {
            return requested;
        }

        if current <= 0 {
            return 0;
        }

        let allowed = requested.min(current as usize);
        let new_value = current - allowed as i64;

        match remaining.compare_exchange_weak(
            current,
            new_value,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(_) => return allowed,
            Err(actual) => current = actual,
        }
    }
}

async fn copy_one_way_unlimited<R, W>(
    mut reader: R,
    mut writer: W,
    connection_counter: Arc<std::sync::atomic::AtomicU64>,
    user_stat: Option<Arc<crate::state::UserStats>>,
    engine_state: Arc<crate::state::EngineState>,
    is_rx: bool,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32768];
    let mut total_bytes = 0u64;

    let user_counter = if let Some(ref user) = user_stat {
        if is_rx {
            Some(&user.rx)
        } else {
            Some(&user.tx)
        }
    } else {
        None
    };

    let mut accumulated_bytes = 0u64;
    let mut last_flush = std::time::Instant::now();

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
        let bytes_copied = n as u64;
        total_bytes += bytes_copied;

        accumulated_bytes += bytes_copied;
        if accumulated_bytes >= 1048576 || last_flush.elapsed().as_millis() >= 500 {
            connection_counter.fetch_add(accumulated_bytes, std::sync::atomic::Ordering::Relaxed);
            if let Some(counter) = user_counter {
                counter.fetch_add(accumulated_bytes, std::sync::atomic::Ordering::Relaxed);
            }
            engine_state
                .dirty
                .store(true, std::sync::atomic::Ordering::Relaxed);
            accumulated_bytes = 0;
            last_flush = std::time::Instant::now();
        }
    }

    if accumulated_bytes > 0 {
        connection_counter.fetch_add(accumulated_bytes, std::sync::atomic::Ordering::Relaxed);
        if let Some(counter) = user_counter {
            counter.fetch_add(accumulated_bytes, std::sync::atomic::Ordering::Relaxed);
        }
        engine_state
            .dirty
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    writer.shutdown().await?;
    Ok(total_bytes)
}

async fn copy_one_way_fast<R, W>(
    mut reader: R,
    mut writer: W,
    connection_counter: Arc<std::sync::atomic::AtomicU64>,
    user_stat: Option<Arc<crate::state::UserStats>>,
    engine_state: Arc<crate::state::EngineState>,
    is_rx: bool,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32768];
    let mut total_bytes = 0u64;

    let (user_counter, user_remaining) = if let Some(ref user) = user_stat {
        if is_rx {
            (Some(&user.rx), Some(&user.remaining_bytes))
        } else {
            (Some(&user.tx), Some(&user.remaining_bytes))
        }
    } else {
        (None, None)
    };

    let mut accumulated_bytes = 0u64;
    let mut last_commit = std::time::Instant::now();

    loop {
        if let Some(rem) = user_remaining {
            if rem.load(std::sync::atomic::Ordering::Relaxed) <= 0 {
                break;
            }
        }

        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        let mut allowed_to_write = n;
        if let Some(rem) = user_remaining {
            let reserved = reserve_quota(rem, n);
            if reserved == 0 {
                break;
            }
            allowed_to_write = reserved;
        }

        writer.write_all(&buf[..allowed_to_write]).await?;
        writer.flush().await?;
        let bytes_copied = allowed_to_write as u64;
        total_bytes += bytes_copied;

        accumulated_bytes += bytes_copied;
        if accumulated_bytes >= 1048576 || last_commit.elapsed().as_millis() >= 500 {
            connection_counter.fetch_add(accumulated_bytes, std::sync::atomic::Ordering::Relaxed);
            if let Some(counter) = user_counter {
                counter.fetch_add(accumulated_bytes, std::sync::atomic::Ordering::Relaxed);
            }
            engine_state
                .dirty
                .store(true, std::sync::atomic::Ordering::Relaxed);
            accumulated_bytes = 0;
            last_commit = std::time::Instant::now();
        }

        if allowed_to_write < n {
            break;
        }
    }

    if accumulated_bytes > 0 {
        connection_counter.fetch_add(accumulated_bytes, std::sync::atomic::Ordering::Relaxed);
        if let Some(counter) = user_counter {
            counter.fetch_add(accumulated_bytes, std::sync::atomic::Ordering::Relaxed);
        }
        engine_state
            .dirty
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    writer.shutdown().await?;
    Ok(total_bytes)
}

async fn copy_one_way_rate_limited<R, W>(
    mut reader: R,
    mut writer: W,
    limit: u64,
    connection_counter: Arc<std::sync::atomic::AtomicU64>,
    user_stat: Option<Arc<crate::state::UserStats>>,
    engine_state: Arc<crate::state::EngineState>,
    is_rx: bool,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let adjusted_limit = limit;

    let mut buf = vec![0u8; 65536];
    let mut total_bytes = 0u64;

    let (user_counter, user_remaining) = if let Some(ref user) = user_stat {
        if is_rx {
            (Some(&user.rx), Some(&user.remaining_bytes))
        } else {
            (Some(&user.tx), Some(&user.remaining_bytes))
        }
    } else {
        (None, None)
    };

    let pacing_interval = std::time::Duration::from_millis(5);
    let bytes_per_interval =
        ((adjusted_limit as u128 * pacing_interval.as_nanos()) / 1_000_000_000) as usize;

    let max_chunk_bound = if adjusted_limit < 1_250_000 {
        4096
    } else if adjusted_limit < 12_500_000 {
        16384
    } else {
        65536
    };
    let max_chunk = bytes_per_interval.clamp(256, max_chunk_bound);
    let mut next_send = tokio::time::Instant::now();

    let mut accumulated_bytes = 0u64;
    let mut last_commit = std::time::Instant::now();

    loop {
        if let Some(rem) = user_remaining {
            if rem.load(std::sync::atomic::Ordering::Relaxed) <= 0 {
                break;
            }
        }

        let n = reader.read(&mut buf[..max_chunk]).await?;
        if n == 0 {
            break;
        }

        let mut allowed_to_write = n;
        if let Some(rem) = user_remaining {
            let reserved = reserve_quota(rem, n);
            if reserved == 0 {
                break;
            }
            allowed_to_write = reserved;
        }

        // Virtual-clock sleep before writing
        let delta_secs = std::ops::Div::div(allowed_to_write as f64, adjusted_limit as f64);
        next_send += std::time::Duration::from_secs_f64(delta_secs);

        let now = tokio::time::Instant::now();
        if next_send > now {
            tokio::time::sleep_until(next_send).await;
        } else if now.duration_since(next_send) > std::time::Duration::from_millis(10) {
            next_send = now;
        }

        writer.write_all(&buf[..allowed_to_write]).await?;
        writer.flush().await?;
        let bytes_copied = allowed_to_write as u64;
        total_bytes += bytes_copied;

        accumulated_bytes += bytes_copied;
        if accumulated_bytes >= 1048576 || last_commit.elapsed().as_millis() >= 500 {
            connection_counter.fetch_add(accumulated_bytes, std::sync::atomic::Ordering::Relaxed);
            if let Some(counter) = user_counter {
                counter.fetch_add(accumulated_bytes, std::sync::atomic::Ordering::Relaxed);
            }
            engine_state
                .dirty
                .store(true, std::sync::atomic::Ordering::Relaxed);
            accumulated_bytes = 0;
            last_commit = std::time::Instant::now();
        }

        if allowed_to_write < n {
            break;
        }
    }

    if accumulated_bytes > 0 {
        connection_counter.fetch_add(accumulated_bytes, std::sync::atomic::Ordering::Relaxed);
        if let Some(counter) = user_counter {
            counter.fetch_add(accumulated_bytes, std::sync::atomic::Ordering::Relaxed);
        }
        engine_state
            .dirty
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    writer.shutdown().await?;
    Ok(total_bytes)
}

pub async fn copy_bidirectional_with_rate_limit<R1, W1, R2, W2>(
    inbound_read: R1,
    inbound_write: W1,
    outbound_read: R2,
    outbound_write: W2,
    speed_limit_bytes_per_sec: Option<u64>,
    connection_rx: Arc<std::sync::atomic::AtomicU64>,
    connection_tx: Arc<std::sync::atomic::AtomicU64>,
    user_uuid: Option<[u8; 16]>,
    engine_state: Arc<crate::state::EngineState>,
) -> Result<(), std::io::Error>
where
    R1: tokio::io::AsyncRead + Unpin + Send + 'static,
    W1: tokio::io::AsyncWrite + Unpin + Send + 'static,
    R2: tokio::io::AsyncRead + Unpin + Send + 'static,
    W2: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let u1 = Arc::clone(&engine_state);
    let u2 = Arc::clone(&engine_state);

    let user_stat = if let Some(uuid) = user_uuid {
        engine_state
            .users
            .read()
            .get(&uuid)
            .map(|(u, _)| Arc::clone(u))
    } else {
        None
    };

    let has_quota_limit = if let Some(ref user) = user_stat {
        let rem = user
            .remaining_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        rem != -1
    } else {
        false
    };

    if let Some(limit) = speed_limit_bytes_per_sec.filter(|&l| l > 0) {
        // Path 3: Speed limited
        let upload = copy_one_way_rate_limited(
            inbound_read,
            outbound_write,
            limit,
            Arc::clone(&connection_tx),
            user_stat.clone(),
            u1,
            false,
        );
        let download = copy_one_way_rate_limited(
            outbound_read,
            inbound_write,
            limit,
            Arc::clone(&connection_rx),
            user_stat,
            u2,
            true,
        );
        tokio::pin!(upload);
        tokio::pin!(download);
        tokio::select! {
            res1 = &mut upload => {
                res1?;
                let _ = tokio::time::timeout(std::time::Duration::from_secs(15), &mut download).await;
            }
            res2 = &mut download => {
                res2?;
            }
        }
    } else if has_quota_limit {
        // Path 2: Unlimited speed + limited quota
        let upload = copy_one_way_fast(
            inbound_read,
            outbound_write,
            Arc::clone(&connection_tx),
            user_stat.clone(),
            u1,
            false,
        );
        let download = copy_one_way_fast(
            outbound_read,
            inbound_write,
            Arc::clone(&connection_rx),
            user_stat,
            u2,
            true,
        );
        tokio::pin!(upload);
        tokio::pin!(download);
        tokio::select! {
            res1 = &mut upload => {
                res1?;
                let _ = tokio::time::timeout(std::time::Duration::from_secs(15), &mut download).await;
            }
            res2 = &mut download => {
                res2?;
            }
        }
    } else {
        // Path 1: Unlimited speed + unlimited quota
        let upload = copy_one_way_unlimited(
            inbound_read,
            outbound_write,
            Arc::clone(&connection_tx),
            user_stat.clone(),
            u1,
            false,
        );
        let download = copy_one_way_unlimited(
            outbound_read,
            inbound_write,
            Arc::clone(&connection_rx),
            user_stat,
            u2,
            true,
        );
        tokio::pin!(upload);
        tokio::pin!(download);
        tokio::select! {
            res1 = &mut upload => {
                res1?;
                let _ = tokio::time::timeout(std::time::Duration::from_secs(15), &mut download).await;
            }
            res2 = &mut download => {
                res2?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::state::EngineState;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn make_test_engine() -> Arc<EngineState> {
        let dummy_config = Config {
            inbounds: vec![],
            outbounds: vec![],
            routing: crate::config::RoutingConfig { rules: vec![] },
            api: crate::config::ApiConfig {
                listen: "127.0.0.1".parse().unwrap(),
                port: 9091,
                trusted_proxies: vec![],
            },
            reality_profiles: vec![],
            warp_domain_sets: vec![],
            direct_exception_sets: vec![],
            ..Default::default()
        };
        Arc::new(EngineState::new(dummy_config).0)
    }
    #[tokio::test]
    async fn test_copy_one_way_fast() {
        let engine = make_test_engine();
        let (r, mut w_client) = tokio::io::duplex(1024);
        let (mut r_client, w) = tokio::io::duplex(1024);

        let data = vec![65u8; 100_000];
        let data_clone = data.clone();

        let handle_write = tokio::spawn(async move {
            w_client.write_all(&data_clone).await.unwrap();
            w_client.shutdown().await.unwrap();
        });

        let conn_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let handle_copy = tokio::spawn(async move {
            copy_one_way_fast(r, w, conn_counter, None, engine, true)
                .await
                .unwrap()
        });

        let mut read_buf = Vec::new();
        r_client.read_to_end(&mut read_buf).await.unwrap();

        handle_write.await.unwrap();
        let total_copied = handle_copy.await.unwrap();

        assert_eq!(total_copied, 100_000);
        assert_eq!(read_buf.len(), 100_000);
        assert_eq!(read_buf, data);
    }

    #[tokio::test]
    async fn test_copy_one_way_rate_limited_pacing() {
        // Use tokio time pausing to verify pacing deterministically without actual sleeping delays
        tokio::time::pause();

        let engine = make_test_engine();
        let (r, mut w_client) = tokio::io::duplex(16384);
        let (mut r_client, w) = tokio::io::duplex(16384);

        // Limit is 10,000 bytes per second
        let limit = 10_000;
        // Write 30,000 bytes (which should take approximately 2-3 seconds to fully copy under the rate limit)
        let data = vec![88u8; 30_000];
        let data_clone = data.clone();

        let handle_write = tokio::spawn(async move {
            w_client.write_all(&data_clone).await.unwrap();
            w_client.shutdown().await.unwrap();
        });

        let conn_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let handle_copy = tokio::spawn(async move {
            copy_one_way_rate_limited(r, w, limit, conn_counter, None, engine, true)
                .await
                .unwrap()
        });

        // Let's advance time incrementally and verify progress
        let mut read_buf = Vec::new();

        // Wait briefly for first read
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut chunk = vec![0u8; 30_000];
        // Read whatever is available currently
        let n = tokio::select! {
            res = r_client.read(&mut chunk) => res.unwrap(),
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => 0,
        };
        read_buf.extend_from_slice(&chunk[..n]);

        // Total copied initially should be bounded by token bucket limit (~10ms burst)
        assert!(
            read_buf.len() < 30_000,
            "Should have been rate limited: read {}",
            read_buf.len()
        );

        // Advance time by 3 seconds in total to allow rate limiter to replenish tokens
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let mut chunk = vec![0u8; 30_000];
            let n = tokio::select! {
                res = r_client.read(&mut chunk) => res.unwrap(),
                _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => 0,
            };
            read_buf.extend_from_slice(&chunk[..n]);
        }

        handle_write.await.unwrap();
        let total_copied = handle_copy.await.unwrap();

        assert_eq!(total_copied, 30_000);
        assert_eq!(read_buf.len(), 30_000);
        assert_eq!(read_buf, data);
    }
}
