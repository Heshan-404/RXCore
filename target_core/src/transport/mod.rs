pub mod tls;
pub mod hysteria_proto;
pub mod mux;

use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn dial_tcp(
    dest_host: &str,
    dest_port: u16,
    bind_ip: &Option<String>,
    outbound_proxy: &Option<String>,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ref proxy_addr) = outbound_proxy {
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
                TcpStream::connect(&proxy_addr_parsed).await.map_err(Into::into)
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
            return Err(Box::from("SOCKS5 auth failed"));
        }
        let mut req = Vec::with_capacity(30);
        req.push(5);
        req.push(1);
        req.push(0);
        if let Ok(ip_addr) = dest_host.parse::<std::net::IpAddr>() {
            match ip_addr {
                std::net::IpAddr::V4(ipv4) => {
                    req.push(1);
                    req.extend_from_slice(&ipv4.octets());
                }
                std::net::IpAddr::V6(ipv6) => {
                    req.push(4);
                    req.extend_from_slice(&ipv6.octets());
                }
            }
        } else {
            req.push(3);
            req.push(dest_host.len() as u8);
            req.extend_from_slice(dest_host.as_bytes());
        }
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
        let resolve_addr = format!("{}:{}", dest_host, dest_port);
        if let Some(ref ip_str) = bind_ip {
            dial_tcp_with_bind(&resolve_addr, ip_str).await
        } else {
            Ok(TcpStream::connect(&resolve_addr).await?)
        }
    }
}

pub async fn dial_tcp_with_bind(
    target_addr: &str,
    bind_ip_str: &str,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    use socket2::{Socket, Domain, Type, Protocol};
    let target_addrs: Vec<SocketAddr> = tokio::net::lookup_host(target_addr).await?.collect();
    let target = target_addrs.first().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "Target address lookup failed"))?;
    let bind_ip: std::net::IpAddr = bind_ip_str.parse()?;
    let bind_addr = SocketAddr::new(bind_ip, 0);
    let domain = if target.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.bind(&bind_addr.into())?;
    match socket.connect(&target.clone().into()) {
        Ok(_) => {}
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e.into()),
    }
    let _ = socket.set_nodelay(true);
    let _ = socket.set_recv_buffer_size(131072);
    let _ = socket.set_send_buffer_size(131072);
    #[cfg(target_os = "linux")]
    {
        let _ = socket.set_value(libc::SOL_TCP, libc::TCP_CONGESTION, b"bbr\0");
        let _ = socket.set_value(libc::SOL_TCP, libc::TCP_QUICKACK, &1i32.to_ne_bytes());
    }
    let std_tcp: std::net::TcpStream = socket.into();
    let tcp = TcpStream::from_std(std_tcp)?;
    Ok(tcp)
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
            TcpStream::connect(&proxy_addr_parsed).await.map_err(Into::into)
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
