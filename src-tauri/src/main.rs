#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use parking_lot::Mutex;
use std::time::Instant;
use tauri::State;
use futures_util::{SinkExt, StreamExt};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ProxyConfig {
    pub id: String,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub sni: String,
    pub allow_insecure: Option<bool>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedConfigs {
    configs: Vec<ProxyConfig>,
    active_id: String,
}

fn decode_percent(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let mut hex = String::new();
            if let Some(&h1) = chars.peek() {
                hex.push(h1);
            }
            if hex.len() == 1 {
                let _ = chars.next();
                if let Some(&h2) = chars.peek() {
                    hex.push(h2);
                }
            }
            if hex.len() == 2 {
                let _ = chars.next();
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }
    result
}

fn parse_vless_link(link: &str) -> Option<ProxyConfig> {
    let prefix = "vless:\x2f\x2f";
    if !link.starts_with(prefix) {
        return None;
    }
    let content = &link[prefix.len()..];
    let parts: Vec<&str> = content.split('#').collect();
    let main_part = parts[0];
    let name = if parts.len() > 1 {
        decode_percent(parts[1])
    } else {
        "VLESS Config".to_string()
    };
    let main_parts: Vec<&str> = main_part.split('?').collect();
    let address_part = main_parts[0];
    let query_part = if main_parts.len() > 1 { Some(main_parts[1]) } else { None };
    let at_parts: Vec<&str> = address_part.split('@').collect();
    if at_parts.len() != 2 {
        return None;
    }
    let uuid = at_parts[0].to_string();
    let host_port = at_parts[1];
    let hp_parts: Vec<&str> = host_port.split(':').collect();
    if hp_parts.len() != 2 {
        return None;
    }
    let server = hp_parts[0].to_string();
    let port = hp_parts[1].parse::<u16>().ok()?;
    let mut sni = String::new();
    if let Some(qp) = query_part {
        for param in qp.split('&') {
            let pair: Vec<&str> = param.split('=').collect();
            if pair.len() == 2 && pair[0] == "sni" {
                sni = decode_percent(pair[1]);
            }
        }
    }
    if sni.is_empty() {
        sni = server.clone();
    }
    Some(ProxyConfig {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        server,
        port,
        uuid,
        sni,
        allow_insecure: Some(false),
    })
}

fn load_configs_from_file() -> (Vec<ProxyConfig>, String) {
    let path = "ruve_configs.json";
    if let Ok(mut file) = std::fs::File::open(path) {
        let mut content = String::new();
        use std::io::Read;
        if file.read_to_string(&mut content).is_ok() {
            if let Ok(saved) = serde_json::from_str::<SavedConfigs>(&content) {
                return (saved.configs, saved.active_id);
            }
        }
    }
    (Vec::new(), String::new())
}

fn save_configs_to_file(configs: &[ProxyConfig], active_id: &str) {
    let path = "ruve_configs.json";
    let saved = SavedConfigs {
        configs: configs.to_vec(),
        active_id: active_id.to_string(),
    };
    if let Ok(content) = serde_json::to_string_pretty(&saved) {
        use std::io::Write;
        if let Ok(mut file) = std::fs::File::create(path) {
            let _ = file.write_all(content.as_bytes());
        }
    }
}

fn push_log(logs: &Arc<Mutex<Vec<String>>>, msg: String) {
    let mut g = logs.lock();
    g.push(msg);
    let len = g.len();
    if len > 100 {
        g.drain(..len - 100);
    }
}

pub struct AppState {
    proxy_handle: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
    logs: Arc<Mutex<Vec<String>>>,
    #[cfg(target_os = "windows")]
    wintun_session: Mutex<Option<Arc<wintun::Session>>>,
    configs: Mutex<Vec<ProxyConfig>>,
    active_config_id: Mutex<String>,
    running_server_ip: Mutex<String>,
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct DangerServerCertVerifier;

#[cfg(target_os = "windows")]
impl rustls::client::danger::ServerCertVerifier for DangerServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(target_os = "windows")]
fn refresh_system_proxy_settings() {
    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(
            hInternet: *mut std::ffi::c_void,
            dwOption: u32,
            lpBuffer: *mut std::ffi::c_void,
            dwBufferLength: u32,
        ) -> i32;
    }
    unsafe {
        InternetSetOptionW(std::ptr::null_mut(), 39, std::ptr::null_mut(), 0);
        InternetSetOptionW(std::ptr::null_mut(), 37, std::ptr::null_mut(), 0);
    }
}

#[cfg(target_os = "windows")]
fn set_system_proxy(enable: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let subkey_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    let (key, _disp) = hkcu.create_subkey(subkey_path)?;
    if enable {
        key.set_value("ProxyEnable", &1u32)?;
        key.set_value("ProxyServer", &"http=127.0.0.1:10808;https=127.0.0.1:10808;socks=127.0.0.1:10808")?;
    } else {
        key.set_value("ProxyEnable", &0u32)?;
    }
    refresh_system_proxy_settings();
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn set_system_proxy(_enable: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Ok(())
}

async fn establish_vless_outbound(
    dest_host: &str,
    port: u16,
    config: ProxyConfig,
    _logs: Arc<Mutex<Vec<String>>>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let vps_addr = format!("{}:{}", config.server, config.port);
    let sni_host = &config.sni;
    let uuid_str = &config.uuid;

    let addr: std::net::SocketAddr = vps_addr.parse()?;
    
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        let iface_index = find_physical_interface_index();
        let handle = socket.as_raw_socket();
        if iface_index > 0 {
            if addr.is_ipv4() {
                let value = (iface_index as u32).to_be();
                unsafe {
                    setsockopt(handle, 0, 31, &value as *const u32 as *const u8, 4);
                }
            } else {
                let value = iface_index as u32;
                unsafe {
                    setsockopt(handle, 41, 31, &value as *const u32 as *const u8, 4);
                }
            };
        }
    }

    let tcp = socket.connect(addr).await?;

    let allow_insecure = config.allow_insecure.unwrap_or(true);

    let mut config = if allow_insecure {
        let tls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        tls_cfg
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        if let Ok(certs) = rustls_native_certs::load_native_certs() {
            for cert in certs {
                let _ = root_store.add(cert);
            }
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    #[cfg(target_os = "windows")]
    if allow_insecure {
        config.dangerous().set_certificate_verifier(Arc::new(DangerServerCertVerifier));
    }
    config.alpn_protocols = vec![b"h2".to_vec(), b"http\x2f1.1".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(sni_host.to_string())?.to_owned();
    let mut tls_stream = connector.connect(server_name, tcp).await?;

    let mut addr_payload = Vec::new();
    let vless_atyp = if let Ok(ipv4) = dest_host.parse::<Ipv4Addr>() {
        addr_payload.extend_from_slice(&ipv4.octets());
        1u8
    } else if let Ok(ipv6) = dest_host.parse::<std::net::Ipv6Addr>() {
        addr_payload.extend_from_slice(&ipv6.octets());
        3u8
    } else {
        addr_payload.push(dest_host.len() as u8);
        addr_payload.extend_from_slice(dest_host.as_bytes());
        2u8
    };

    let uuid = uuid::Uuid::parse_str(uuid_str)?;
    let mut vless_header = Vec::with_capacity(64);
    vless_header.push(0x00);
    vless_header.extend_from_slice(uuid.as_bytes());
    vless_header.push(0x00);
    vless_header.push(0x01);
    vless_header.extend_from_slice(&port.to_be_bytes());
    vless_header.push(vless_atyp);
    vless_header.extend_from_slice(&addr_payload);

    tls_stream.write_all(&vless_header).await?;

    let mut response = [0u8; 2];
    tls_stream.read_exact(&mut response).await?;
    if response[0] != 0 {
        return Err("Invalid response protocol version".into());
    }

    Ok(tls_stream)
}

#[cfg(target_os = "windows")]
#[link(name = "ws2_32")]
extern "system" {
    fn setsockopt(
        s: std::os::windows::io::RawSocket,
        level: i32,
        optname: i32,
        optval: *const u8,
        optlen: i32,
    ) -> i32;
}

#[cfg(target_os = "windows")]
fn find_physical_gateway() -> String {
    if let Ok(output) = std::process::Command::new("powershell")
        .args(&[
            "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0\x2f0' | Where-Object {$_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -ne 'RuveTun' -and $_.InterfaceAlias -ne 'RuvePool'} | Sort-Object RouteMetric | Select-Object -First 1).NextHop"
        ])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let gateway = stdout.trim();
        if !gateway.is_empty() && gateway != "0.0.0.0" {
            return gateway.to_string();
        }
    }
    "192.168.8.1".to_string()
}

#[cfg(target_os = "windows")]
fn find_physical_interface_index() -> u32 {
    if let Ok(output) = std::process::Command::new("powershell")
        .args(&[
            "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0\x2f0' | Where-Object {$_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -ne 'RuveTun' -and $_.InterfaceAlias -ne 'RuvePool'} | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex"
        ])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(idx) = stdout.trim().parse::<u32>() {
            return idx;
        }
    }
    3
}

#[tauri::command]
async fn toggle_proxy(
    connect: bool,
    state: State<'_, AppState>,
) -> Result<String, String> {
    if connect {
        {
            let handle_guard = state.proxy_handle.lock();
            if handle_guard.is_some() {
                return Ok("Already connected".to_string());
            }
        }

        let active_config = {
            let configs = state.configs.lock();
            let active_id = state.active_config_id.lock();
            configs.iter().find(|c| c.id == *active_id).cloned()
        };
        let config = active_config.ok_or_else(|| "No active configuration selected".to_string())?;

        {
            let mut running_ip = state.running_server_ip.lock();
            *running_ip = config.server.clone();
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = state;
            return Err("TUN mode is only supported on Windows".to_string());
        }

        #[cfg(target_os = "windows")]
        {
            let wintun = unsafe { wintun::load_from_path("wintun.dll") }
                .map_err(|e| format!("Failed to load Wintun driver: {}", e))?;
            
            let adapter = wintun::Adapter::create(&wintun, "RuvePool", "RuveTun", None)
                .map_err(|e| format!("Failed to create adapter: {}", e))?;
            
            let mut set_addr_res = Err("Failed".to_string());
            for _ in 0..15 {
                if let Ok(_) = adapter.set_network_addresses_tuple(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(255, 255, 255, 0)),
                    Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))),
                ) {
                    set_addr_res = Ok(());
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            }
            if set_addr_res.is_err() {
                return Err("Failed to set TUN IP address after retries".to_string());
            }

            let mut start_sess_res = Err("Failed".to_string());
            for _ in 0..5 {
                if let Ok(s) = adapter.start_session(wintun::MAX_RING_CAPACITY) {
                    start_sess_res = Ok(s);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            }
            let session = Arc::new(start_sess_res.map_err(|_| "Failed to start Wintun session".to_string())?);
            {
                let mut session_guard = state.wintun_session.lock();
                *session_guard = Some(Arc::clone(&session));
            }

            let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
            {
                let mut handle_guard = state.proxy_handle.lock();
                *handle_guard = Some(tx);
            }

            {
                let mut l_guard = state.logs.lock();
                l_guard.clear();
                l_guard.push("TUN engine started, redirecting system traffic...".to_string());
            }

            let gateway = find_physical_gateway();

            std::process::Command::new("netsh")
                .args(&["interface", "ipv4", "set", "subinterface", "RuvePool", "metric=1"])
                .output()
                .ok();
            std::process::Command::new("netsh")
                .args(&["interface", "ipv4", "set", "subinterface", "RuveTun", "metric=1"])
                .output()
                .ok();

            std::process::Command::new("netsh")
                .args(&["interface", "ipv4", "set", "dnsservers", "name=RuvePool", "source=static", "address=10.0.0.1", "register=primary", "validate=no"])
                .output()
                .ok();
            std::process::Command::new("netsh")
                .args(&["interface", "ipv4", "set", "dnsservers", "name=RuveTun", "source=static", "address=10.0.0.1", "register=primary", "validate=no"])
                .output()
                .ok();

            let adapter_index = adapter.get_adapter_index().unwrap_or(1);
            let adapter_index_str = adapter_index.to_string();

            std::process::Command::new("route")
                .args(&["add", &config.server, &gateway, "metric", "1"])
                .output()
                .ok();

            std::process::Command::new("route")
                .args(&["add", "0.0.0.0", "mask", "128.0.0.0", "10.0.0.1", "metric", "5", "if", &adapter_index_str])
                .output()
                .ok();

            std::process::Command::new("route")
                .args(&["add", "128.0.0.0", "mask", "128.0.0.0", "10.0.0.1", "metric", "5", "if", &adapter_index_str])
                .output()
                .ok();

            let (stack, runner, udp_socket, tcp_listener) = netstack_smoltcp::StackBuilder::default()
                .stack_buffer_size(2048)
                .tcp_buffer_size(65535)
                .enable_udp(true)
                .enable_tcp(true)
                .build()
                .map_err(|e| format!("Failed to build netstack: {:?}", e))?;

            if let Some(r) = runner {
                tokio::spawn(r);
            }

            let (mut stack_sink, mut stack_stream) = stack.split();

            let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(2048);
            let session_read = Arc::clone(&session);

            tokio::task::spawn_blocking(move || {
                loop {
                    match session_read.receive_blocking() {
                        Ok(packet) => {
                            let bytes = packet.bytes();
                            let mut is_local = false;

                            if let Ok(value) = etherparse::SlicedPacket::from_ip(bytes) {
                                if let Some(ip_slice) = value.ip {
                                    match ip_slice {
                                        etherparse::InternetSlice::Ipv4(ipv4_slice, _) => {
                                            let d_addr = std::net::Ipv4Addr::from(ipv4_slice.destination());
                                            is_local = d_addr.is_multicast() || d_addr.is_link_local() || d_addr.is_broadcast() || d_addr == std::net::Ipv4Addr::new(10, 0, 0, 255);
                                        }
                                        etherparse::InternetSlice::Ipv6(ipv6_slice, _) => {
                                            let d_addr = std::net::Ipv6Addr::from(ipv6_slice.destination());
                                            is_local = d_addr.is_multicast();
                                        }
                                    };
                                }
                            }
                            if is_local {
                                continue;
                            }
                            let mut vec_bytes = bytes.to_vec();
                            fix_ipv4_checksums(&mut vec_bytes);
                            if let Err(_) = packet_tx.blocking_send(vec_bytes) {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });

            tokio::spawn(async move {
                while let Some(bytes) = packet_rx.recv().await {
                    let frame: netstack_smoltcp::AnyIpPktFrame = bytes.into();
                    if let Err(_) = stack_sink.send(frame).await {
                        break;
                    }
                }
            });

            let session_write = Arc::clone(&session);
            tokio::spawn(async move {
                while let Some(frame_res) = stack_stream.next().await {
                    if let Ok(frame) = frame_res {
                        let bytes = frame.to_vec();
                        if let Ok(mut packet) = session_write.allocate_send_packet(bytes.len() as u16) {
                            packet.bytes_mut().copy_from_slice(&bytes);
                            session_write.send_packet(packet);
                        }
                    }
                }
            });

            let config_udp = config.clone();
            let logs_udp = Arc::clone(&state.logs);
            tokio::spawn(async move {
                if let Some(udp) = udp_socket {
                    let (tx_chan, mut rx_chan) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, SocketAddr, SocketAddr)>();
                    let (mut read_half, mut write_half) = udp.split();
                    
                    tokio::spawn(async move {
                        while let Some((data, local, remote)) = rx_chan.recv().await {
                            let _ = write_half.send((data, remote, local)).await;
                        }
                    });

                    while let Some((data, local, remote)) = read_half.next().await {
                        if remote.port() == 53 {
                            let tx_clone = tx_chan.clone();
                            let logs_err = Arc::clone(&logs_udp);
                            let config_clone = config_udp.clone();
                            tokio::spawn(async move {
                                match establish_vless_outbound("1.1.1.1", 53, config_clone, logs_err.clone()).await {
                                    Ok(mut tcp_stream) => {
                                        let len = data.len() as u16;
                                        let mut req = Vec::with_capacity(2 + data.len());
                                        req.extend_from_slice(&len.to_be_bytes());
                                        req.extend_from_slice(&data);
                                        if tcp_stream.write_all(&req).await.is_ok() {
                                            let mut resp_len_buf = [0u8; 2];
                                            if tcp_stream.read_exact(&mut resp_len_buf).await.is_ok() {
                                                let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
                                                let mut resp_buf = vec![0u8; resp_len];
                                                if tcp_stream.read_exact(&mut resp_buf).await.is_ok() {
                                                    let _ = tx_clone.send((resp_buf, local, remote));
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        push_log(&logs_err, format!("dns: exchange failed: {}", e));
                                    }
                                }
                            });
                        }
                    }
                }
            });

            let logs_clone = Arc::clone(&state.logs);
            let config_tcp = config;
            tokio::spawn(async move {
                if let Some(mut listener) = tcp_listener {
                    loop {
                        tokio::select! {
                            opt = listener.next() => {
                                if let Some((mut stream, _local_addr, remote_addr)) = opt {
                                    let dest_host = remote_addr.ip().to_string();
                                    let dest_port = remote_addr.port();
                                    
                                    let logs_err = Arc::clone(&logs_clone);
                                    let config_clone = config_tcp.clone();
                                    tokio::spawn(async move {
                                        match establish_vless_outbound(&dest_host, dest_port, config_clone, logs_err.clone()).await {
                                            Ok(mut outbound) => {
                                                let _ = tokio::io::copy_bidirectional(&mut stream, &mut outbound).await;
                                            }
                                            Err(e) => {
                                                push_log(&logs_err, format!("proxy connection to {} failed: {}", remote_addr, e));
                                            }
                                        }
                                    });
                                } else {
                                    break;
                                }
                            }
                            _ = rx.recv() => {
                                break;
                            }
                        }
                    }
                }
            });

            Ok("Connected in TUN Mode".to_string())
        }
    } else {
        let tx = {
            let mut handle_guard = state.proxy_handle.lock();
            handle_guard.take()
        };
        if let Some(sender) = tx {
            let _ = sender.send(()).await;
        }

        #[cfg(target_os = "windows")]
        {
            {
                let mut session_guard = state.wintun_session.lock();
                if let Some(session) = session_guard.take() {
                    let _ = session.shutdown();
                }
            }
            std::process::Command::new("netsh")
                .args(&["interface", "ipv4", "set", "dnsservers", "name=RuvePool", "source=dhcp"])
                .output()
                .ok();
            std::process::Command::new("netsh")
                .args(&["interface", "ipv4", "set", "dnsservers", "name=RuveTun", "source=dhcp"])
                .output()
                .ok();
            std::process::Command::new("route")
                .args(&["delete", "0.0.0.0", "mask", "128.0.0.0"])
                .output()
                .ok();
            std::process::Command::new("route")
                .args(&["delete", "128.0.0.0", "mask", "128.0.0.0"])
                .output()
                .ok();
            
            let server_ip = {
                let mut running_ip = state.running_server_ip.lock();
                std::mem::take(&mut *running_ip)
            };
            if !server_ip.is_empty() {
                std::process::Command::new("route")
                    .args(&["delete", &server_ip])
                    .output()
                    .ok();
            }
        }

        Ok("Disconnected".to_string())
    }
}

#[tauri::command]
async fn get_latency(state: State<'_, AppState>) -> Result<u64, String> {
    let active_config = {
        let configs = state.configs.lock();
        let active_id = state.active_config_id.lock();
        configs.iter().find(|c| c.id == *active_id).cloned()
    };
    
    let config = match active_config {
        Some(c) => c,
        None => return Err("No active config".to_string()),
    };

    let start = Instant::now();
    let vps_addr = format!("{}:{}", config.server, config.port);
    let addr = vps_addr.parse::<std::net::SocketAddr>().map_err(|e| e.to_string())?;
    
    let connect_fut = async move {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::io::AsRawSocket;
            let iface_index = find_physical_interface_index();
            let handle = socket.as_raw_socket();
            if iface_index > 0 {
                if addr.is_ipv4() {
                    let value = (iface_index as u32).to_be();
                    unsafe {
                        setsockopt(handle, 0, 31, &value as *const u32 as *const u8, 4);
                    }
                } else {
                    let value = iface_index as u32;
                    unsafe {
                        setsockopt(handle, 41, 31, &value as *const u32 as *const u8, 4);
                    }
                }
            }
        }

        let _tcp = socket.connect(addr).await?;
        Ok::<(), std::io::Error>(())
    };

    match tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        connect_fut
    ).await {
        Ok(Ok(_)) => {
            let duration = start.elapsed().as_millis() as u64;
            Ok(duration)
        }
        _ => Err("Timeout or unreachable".to_string()),
    }
}

#[tauri::command]
async fn get_logs(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let g = state.logs.lock();
    Ok(g.clone())
}

#[tauri::command]
async fn get_configs(state: State<'_, AppState>) -> Result<Vec<ProxyConfig>, String> {
    let configs = state.configs.lock();
    Ok(configs.clone())
}

#[tauri::command]
async fn get_active_config_id(state: State<'_, AppState>) -> Result<String, String> {
    let active_id = state.active_config_id.lock();
    Ok(active_id.clone())
}

#[tauri::command]
async fn select_config(id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut active_id = state.active_config_id.lock();
    *active_id = id.clone();
    let configs = state.configs.lock();
    save_configs_to_file(&configs, &active_id);
    Ok(())
}

#[tauri::command]
async fn delete_config(id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut configs = state.configs.lock();
    let mut active_id = state.active_config_id.lock();
    configs.retain(|c| c.id != id);
    if *active_id == id {
        if let Some(first) = configs.first() {
            *active_id = first.id.clone();
        } else {
            *active_id = "".to_string();
        }
    }
    save_configs_to_file(&configs, &active_id);
    Ok(())
}

#[tauri::command]
async fn add_config(
    name: String,
    server: String,
    port: u16,
    uuid: String,
    sni: String,
    allow_insecure: bool,
    state: State<'_, AppState>,
) -> Result<ProxyConfig, String> {
    let config = ProxyConfig {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        server,
        port,
        uuid,
        sni,
        allow_insecure: Some(allow_insecure),
    };
    let mut configs = state.configs.lock();
    let mut active_id = state.active_config_id.lock();
    configs.push(config.clone());
    if active_id.is_empty() {
        *active_id = config.id.clone();
    }
    save_configs_to_file(&configs, &active_id);
    Ok(config)
}

#[tauri::command]
async fn update_config(
    id: String,
    name: String,
    server: String,
    port: u16,
    uuid: String,
    sni: String,
    allow_insecure: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut configs = state.configs.lock();
    let active_id = state.active_config_id.lock();
    if let Some(config) = configs.iter_mut().find(|c| c.id == id) {
        config.name = name;
        config.server = server;
        config.port = port;
        config.uuid = uuid;
        config.sni = sni;
        config.allow_insecure = Some(allow_insecure);
    }
    save_configs_to_file(&configs, &active_id);
    Ok(())
}

#[tauri::command]
async fn import_config_link(link: String, state: State<'_, AppState>) -> Result<ProxyConfig, String> {
    let config = parse_vless_link(&link).ok_or_else(|| "Invalid VLESS link".to_string())?;
    let mut configs = state.configs.lock();
    let mut active_id = state.active_config_id.lock();
    configs.push(config.clone());
    if active_id.is_empty() {
        *active_id = config.id.clone();
    }
    save_configs_to_file(&configs, &active_id);
    Ok(config)
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    while let Some(chunk) = chunks.next() {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u16::from_be_bytes([last, 0]) as u32;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn fix_ipv4_checksums(packet: &mut [u8]) {
    if packet.len() < 20 {
        return;
    }
    let ver = packet[0] >> 4;
    if ver != 4 {
        return;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if packet.len() < ihl {
        return;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let packet_len = std::cmp::min(packet.len(), total_len);
    if packet_len < ihl {
        return;
    }
    let proto = packet[9];
    packet[10] = 0;
    packet[11] = 0;
    let ip_checksum = internet_checksum(&packet[..ihl]);
    let ip_checksum_bytes = ip_checksum.to_be_bytes();
    packet[10] = ip_checksum_bytes[0];
    packet[11] = ip_checksum_bytes[1];
    if proto == 6 {
        let tcp_len = packet_len - ihl;
        if tcp_len >= 20 {
            let checksum_offset = ihl + 16;
            if packet_len >= checksum_offset + 2 {
                packet[checksum_offset] = 0;
                packet[checksum_offset + 1] = 0;
                let mut pseudo = Vec::with_capacity(12 + tcp_len);
                pseudo.extend_from_slice(&packet[12..16]);
                pseudo.extend_from_slice(&packet[16..20]);
                pseudo.push(0);
                pseudo.push(6);
                pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
                pseudo.extend_from_slice(&packet[ihl..packet_len]);
                let tcp_checksum = internet_checksum(&pseudo);
                let tcp_checksum_bytes = tcp_checksum.to_be_bytes();
                packet[checksum_offset] = tcp_checksum_bytes[0];
                packet[checksum_offset + 1] = tcp_checksum_bytes[1];
            }
        }
    } else if proto == 17 {
        let udp_len = packet_len - ihl;
        if udp_len >= 8 {
            let checksum_offset = ihl + 6;
            if packet_len >= checksum_offset + 2 {
                packet[checksum_offset] = 0;
                packet[checksum_offset + 1] = 0;
                let mut pseudo = Vec::with_capacity(12 + udp_len);
                pseudo.extend_from_slice(&packet[12..16]);
                pseudo.extend_from_slice(&packet[16..20]);
                pseudo.push(0);
                pseudo.push(17);
                pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
                pseudo.extend_from_slice(&packet[ihl..packet_len]);
                let udp_checksum = internet_checksum(&pseudo);
                let udp_checksum_bytes = udp_checksum.to_be_bytes();
                packet[checksum_offset] = udp_checksum_bytes[0];
                packet[checksum_offset + 1] = udp_checksum_bytes[1];
            }
        }
    }
}

fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = set_system_proxy(false);

    let (saved_configs, active_id) = load_configs_from_file();

    tauri::Builder::default()
        .manage(AppState {
            proxy_handle: Mutex::new(None),
            logs: Arc::new(Mutex::new(vec!["Engine ready".to_string()])),
            #[cfg(target_os = "windows")]
            wintun_session: Mutex::new(None),
            configs: Mutex::new(saved_configs),
            active_config_id: Mutex::new(active_id),
            running_server_ip: Mutex::new(String::new()),
        })
        .invoke_handler(tauri::generate_handler![
            toggle_proxy,
            get_latency,
            get_logs,
            get_configs,
            get_active_config_id,
            select_config,
            delete_config,
            add_config,
            update_config,
            import_config_link
        ])
        .run(tauri::generate_context!())
        .expect("error while building tauri application");
}
