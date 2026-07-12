use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;
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
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .on_thread_start(|| {
            static CORE_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let core_ids = core_affinity::get_core_ids().unwrap_or_default();
            if !core_ids.is_empty() {
                let limit = 2;
                let idx = CORE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let target_idx = ((idx % limit) + 2) % core_ids.len();
                let core_id = core_ids[target_idx];
                core_affinity::set_for_current(core_id);
            }
        })
        .build()?;

    runtime.block_on(async {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::WARN)
            .finish();
        tracing::subscriber::set_global_default(subscriber)?;

        info!("Starting high-performance client companion app...");

        #[cfg(target_os = "windows")]
        let wintun_session = Arc::new(parking_lot::Mutex::new(None));

        #[cfg(target_os = "windows")]
        {
            let wintun = unsafe { wintun::load_from_path("wintun.dll") }
                .map_err(|e| format!("Failed to load Wintun driver: {}", e))?;
            
            let adapter = wintun::Adapter::create(&wintun, "RuvePool", "RuveTun", None)
                .map_err(|e| format!("Failed to create adapter: {}", e))?;
            
            adapter.set_address(std::net::Ipv4Addr::new(10, 0, 0, 2)).unwrap();
            adapter.set_netmask(std::net::Ipv4Addr::new(255, 255, 255, 0)).unwrap();
            
            let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());
            *wintun_session.lock() = Some(Arc::clone(&session));

            info!("TUN engine started, redirecting system traffic...");

            std::process::Command::new("netsh")
                .args(&["interface", "ipv4", "set", "subinterface", "RuveTun", "metric=1"])
                .output()
                .ok();

            // High-priority bypass route for the VPS IP through physical router/gateway to prevent routing loop
            std::process::Command::new("route")
                .args(&["add", "68.183.191.244", "192.168.8.1", "metric", "1"])
                .output()
                .ok();
            
            std::process::Command::new("route")
                .args(&["add", "0.0.0.0", "mask", "0.0.0.0", "10.0.0.1", "metric", "5"])
                .output()
                .ok();

            let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(2048);
            let session_read = Arc::clone(&session);

            tokio::task::spawn_blocking(move || {
                loop {
                    match session_read.receive_blocking() {
                        Ok(packet) => {
                            let bytes = packet.bytes();
                            if let Ok(value) = etherparse::SlicedPacket::from_ip(bytes) {
                                if let Some(ip_slice) = value.ip {
                                    let (dest_ip, is_local) = match ip_slice {
                                        etherparse::InternetSlice::Ipv4(ipv4_slice, _) => {
                                            let addr = std::net::Ipv4Addr::from(ipv4_slice.destination());
                                            (std::net::IpAddr::V4(addr), addr.is_multicast() || addr.is_link_local() || addr.is_broadcast())
                                        }
                                        etherparse::InternetSlice::Ipv6(ipv6_slice, _) => {
                                            let addr = std::net::Ipv6Addr::from(ipv6_slice.destination());
                                            (std::net::IpAddr::V6(addr), addr.is_multicast())
                                        }
                                    };
                                    if is_local {
                                        continue;
                                    }
                                    info!("TUN Encapsulating packet to: {}", dest_ip);
                                }
                            }
                            if let Err(_) = packet_tx.blocking_send(bytes.to_vec()) {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });

            tokio::spawn(async move {
                let mut outbound_vless = match establish_vless_outbound("68.183.191.244", 443).await {
                    Ok(out) => out,
                    Err(e) => {
                        error!("Failed to establish VLESS outbound: {}", e);
                        return;
                    }
                };
                while let Some(bytes) = packet_rx.recv().await {
                    if let Err(_) = outbound_vless.write_all(&bytes).await {
                        break;
                    }
                }
            });
        }

        #[cfg(not(target_os = "windows"))]
        {
            error!("TUN mode is only supported on Windows.");
        }

        tokio::signal::ctrl_c().await.ok();
        info!("Ctrl-C detected, restoring routing table and shutting down session");

        #[cfg(target_os = "windows")]
        {
            if let Some(session) = wintun_session.lock().take() {
                let _ = session.shutdown();
            }
            std::process::Command::new("route").args(&["delete", "0.0.0.0"]).output().ok();
            std::process::Command::new("route").args(&["delete", "68.183.191.244"]).output().ok();
        }

        Ok(())
    })
}

#[allow(dead_code)]
async fn establish_vless_outbound(
    dest_host: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let vps_addr = "68.183.191.244:443";
    let sni_host = "aks.ms";
    let uuid_str = "ad60c2b2-cc0c-492a-89aa-c92330a10cc9";

    let tcp = TcpStream::connect(vps_addr).await?;
    let _ = tcp.set_nodelay(true);

    #[cfg(target_os = "windows")]
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    #[cfg(target_os = "windows")]
    config.dangerous().set_certificate_verifier(Arc::new(DangerServerCertVerifier));

    #[cfg(not(target_os = "windows"))]
    let config = {
        let mut root_store = rustls::RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            let _ = root_store.add(cert);
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let mut config_final = config;
    config_final.alpn_protocols = vec![b"h2".to_vec(), vec![104, 116, 116, 112, 47, 49, 46, 49]];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config_final));
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

// End of file
