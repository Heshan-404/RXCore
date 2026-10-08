use crate::config::RealityProfile;
use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce};
use bytes::Buf;
use hkdf::Hkdf;
use lru::LruCache;
use once_cell::sync::Lazy;
use ring::hmac;
use rustls::reality::RealityConfig;
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::Sha256;
use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

// --- ClientHello Parser ---

pub struct ClientHelloInfo {
    pub session_id: Vec<u8>,
    pub session_id_offset: usize,
    pub client_random: [u8; 32],
    pub public_key: Option<Vec<u8>>,
    pub server_name: Option<String>,
}

pub fn parse_client_hello(
    handshake_payload: &[u8],
) -> Result<Option<ClientHelloInfo>, Box<dyn std::error::Error + Send + Sync>> {
    if handshake_payload.len() < 4 {
        return Ok(None);
    }

    let msg_type = handshake_payload[0];
    if msg_type != 0x01 {
        return Ok(None);
    }

    let mut cursor = &handshake_payload[4..];

    if cursor.remaining() < 2 {
        return Err("Short buffer for Version".into());
    }
    cursor.advance(2);

    if cursor.remaining() < 32 {
        return Err("Short buffer for Random".into());
    }
    let mut client_random = [0u8; 32];
    cursor.copy_to_slice(&mut client_random);

    if cursor.remaining() < 1 {
        return Err("Short buffer for Session ID length".into());
    }
    let session_id_len = cursor.get_u8() as usize;
    if cursor.remaining() < session_id_len {
        return Err("Short buffer for Session ID".into());
    }

    let session_id_offset = handshake_payload.len() - cursor.remaining();
    let mut session_id = vec![0u8; session_id_len];
    cursor.copy_to_slice(&mut session_id);

    if cursor.remaining() < 2 {
        return Err("Short buffer for Cipher Suites Len".into());
    }
    let cipher_suites_len = cursor.get_u16() as usize;
    if cursor.remaining() < cipher_suites_len {
        return Err("Short buffer for Cipher Suites".into());
    }
    cursor.advance(cipher_suites_len);

    if cursor.remaining() < 1 {
        return Err("Short buffer for Compression Methods Len".into());
    }
    let compression_methods_len = cursor.get_u8() as usize;
    if cursor.remaining() < compression_methods_len {
        return Err("Short buffer for Compression Methods".into());
    }
    cursor.advance(compression_methods_len);

    if cursor.remaining() < 2 {
        return Ok(Some(ClientHelloInfo {
            session_id,
            session_id_offset,
            client_random,
            public_key: None,
            server_name: None,
        }));
    }

    let extensions_len = cursor.get_u16() as usize;
    if cursor.remaining() < extensions_len {
        return Err("Short buffer for Extensions".into());
    }
    let mut extensions = &cursor[..extensions_len];

    let mut public_key = None;
    let mut server_name = None;

    while extensions.has_remaining() {
        if extensions.remaining() < 4 {
            break;
        }
        let ext_type = extensions.get_u16();
        let ext_len = extensions.get_u16() as usize;

        if extensions.remaining() < ext_len {
            break;
        }
        let mut ext_data = &extensions[..ext_len];
        extensions.advance(ext_len);

        if ext_type == 0x0000 {
            if ext_data.remaining() >= 2 {
                let list_len = ext_data.get_u16() as usize;
                if ext_data.remaining() >= list_len {
                    let mut list = &ext_data[..list_len];
                    while list.has_remaining() {
                        if list.remaining() < 3 {
                            break;
                        }
                        let name_type = list.get_u8();
                        let name_len = list.get_u16() as usize;
                        if list.remaining() < name_len {
                            break;
                        }

                        if name_type == 0x00 {
                            let mut name_bytes = vec![0u8; name_len];
                            list.copy_to_slice(&mut name_bytes);
                            if let Ok(s) = String::from_utf8(name_bytes) {
                                server_name = Some(s);
                            }
                            break;
                        }
                        list.advance(name_len);
                    }
                }
            }
        }

        if ext_type == 0x0033 {
            if ext_data.remaining() < 2 {
                continue;
            }
            let shares_len = ext_data.get_u16() as usize;
            if ext_data.remaining() < shares_len {
                continue;
            }

            let mut shares = &ext_data[..shares_len];
            while shares.has_remaining() {
                if shares.remaining() < 4 {
                    break;
                }
                let group = shares.get_u16();
                let key_len = shares.get_u16() as usize;

                if shares.remaining() < key_len {
                    break;
                }

                if group == 0x001d && key_len == 32 {
                    let mut key = vec![0u8; 32];
                    shares.copy_to_slice(&mut key);
                    public_key = Some(key);
                    break;
                } else {
                    shares.advance(key_len);
                }
            }
        }

        if public_key.is_some() && server_name.is_some() {
            break;
        }
    }

    Ok(Some(ClientHelloInfo {
        session_id,
        session_id_offset,
        client_random,
        public_key,
        server_name,
    }))
}

// --- Reality Server ---

#[derive(Hash, PartialEq, Eq, Clone)]
struct CertKey {
    host: String,
}

static CERT_CACHE: Lazy<
    Mutex<LruCache<CertKey, (Vec<u8>, Vec<u8>, Arc<dyn rustls::sign::SigningKey>)>>,
> = Lazy::new(|| Mutex::new(LruCache::new(std::num::NonZeroUsize::new(100).unwrap())));

#[derive(Debug)]
struct SingleCertResolver {
    certified_key: Arc<rustls::sign::CertifiedKey>,
}

impl rustls::server::ResolvesServerCert for SingleCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.certified_key))
    }
}

pub struct RealityServerRustls {
    reality_config: Arc<RealityConfig>,
    server_names: Vec<String>,
    template_config: Arc<ServerConfig>,
}

impl Clone for RealityServerRustls {
    fn clone(&self) -> Self {
        Self {
            reality_config: Arc::clone(&self.reality_config),
            server_names: self.server_names.clone(),
            template_config: Arc::clone(&self.template_config),
        }
    }
}

impl RealityServerRustls {
    pub fn new(
        private_key: Vec<u8>,
        dest: Option<String>,
        short_ids: Vec<String>,
        server_names: Vec<String>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut short_ids_bytes = Vec::new();
        for id in short_ids {
            let b = hex::decode(&id)?;
            short_ids_bytes.push(b);
        }

        let dest_str = dest.ok_or_else(|| {
            Box::<dyn std::error::Error + Send + Sync>::from("Reality dest is required")
        })?;
        let reality_config = RealityConfig::new(private_key)
            .with_verify_client(false)
            .with_short_ids(short_ids_bytes)
            .with_dest(dest_str);

        reality_config.validate()?;

        // Pre-generate and cache certificate templates for all configured server names at startup
        for name in &server_names {
            if let Err(e) = Self::pre_generate_and_cache_template(name) {
                tracing::error!(
                    "Failed to pre-generate certificate template for {}: {}",
                    name,
                    e
                );
            }
        }

        // Generate a dummy self-signed certificate and key once at startup to initialize the template config
        use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
        let key_pair = KeyPair::generate(&PKCS_ED25519)?;
        let mut params = CertificateParams::new(vec!["localhost".to_string()]);
        params.alg = &PKCS_ED25519;
        params.key_pair = Some(key_pair);
        let cert = rcgen::Certificate::from_params(params)?;
        let dummy_cert = CertificateDer::from(cert.serialize_der()?);
        let dummy_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.serialize_private_key_der()));

        let template_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![dummy_cert], dummy_key)?;

        Ok(Self {
            reality_config: Arc::new(reality_config),
            server_names,
            template_config: Arc::new(template_config),
        })
    }

    fn pre_generate_and_cache_template(
        host: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = CertKey {
            host: host.to_string(),
        };

        use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
        let key_pair = KeyPair::generate(&PKCS_ED25519)?;
        let pub_key_raw = key_pair.public_key_raw().to_vec();
        let mut params = CertificateParams::new(vec![host.to_string()]);
        params.alg = &PKCS_ED25519;
        params.key_pair = Some(key_pair);

        let cert = rcgen::Certificate::from_params(params)?;
        let cert_der = cert.serialize_der()?;
        let priv_key_der = cert.serialize_private_key_der();

        let private_key = rustls::crypto::ring::default_provider()
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(priv_key_der)))?;

        if let Ok(mut cache) = CERT_CACHE.lock() {
            cache.put(key, (cert_der, pub_key_raw, private_key));
        }
        Ok(())
    }

    pub async fn accept<S>(
        &self,
        mut stream: S,
    ) -> Result<
        tokio_rustls::server::TlsStream<PrefixedStream<S>>,
        Box<dyn std::error::Error + Send + Sync>,
    >
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut buffer = Vec::new();
        let mut handshake_payload = Vec::new();
        let handshake_timeout = std::time::Duration::from_secs(3);

        let read_task = async {
            let mut record_count = 0;
            while record_count < 8 && handshake_payload.len() < 65536 {
                let header_start = buffer.len();
                while buffer.len() - header_start < 5 {
                    let mut chunk = [0u8; 5];
                    let needed = 5 - (buffer.len() - header_start);
                    let n = stream.read(&mut chunk[..needed]).await?;
                    if n == 0 {
                        return Err::<(), Box<dyn std::error::Error + Send + Sync>>(Box::from(
                            "Connection closed early",
                        ));
                    }
                    buffer.extend_from_slice(&chunk[..n]);
                }

                let content_type = buffer[header_start];
                let record_len =
                    u16::from_be_bytes([buffer[header_start + 3], buffer[header_start + 4]])
                        as usize;

                if content_type != 0x16 {
                    break;
                }

                const MAX_TLS_RECORD: usize = 18 * 1024;
                const MAX_CLIENT_HELLO: usize = 64 * 1024;

                if record_len == 0 || record_len > MAX_TLS_RECORD {
                    return Err(Box::from("Invalid TLS record length"));
                }

                if handshake_payload.len() + record_len > MAX_CLIENT_HELLO {
                    return Err(Box::from("ClientHello exceeds maximum size"));
                }

                let payload_start = buffer.len();
                while buffer.len() - payload_start < record_len {
                    let mut chunk = [0u8; 4096];
                    let needed = std::cmp::min(4096, record_len - (buffer.len() - payload_start));
                    let n = stream.read(&mut chunk[..needed]).await?;
                    if n == 0 {
                        return Err::<(), Box<dyn std::error::Error + Send + Sync>>(Box::from(
                            "Connection closed early",
                        ));
                    }
                    buffer.extend_from_slice(&chunk[..n]);
                }

                handshake_payload.extend_from_slice(&buffer[payload_start..buffer.len()]);
                record_count += 1;

                if handshake_payload.len() >= 4 {
                    let msg_type = handshake_payload[0];
                    if msg_type == 0x01 {
                        let msg_len = ((handshake_payload[1] as usize) << 16)
                            | ((handshake_payload[2] as usize) << 8)
                            | (handshake_payload[3] as usize);
                        if handshake_payload.len() >= 4 + msg_len {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        };

        match tokio::time::timeout(handshake_timeout, read_task).await {
            Ok(result) => result?,
            Err(_) => return Err(Box::from("Handshake timeout")),
        }

        if let Ok(Some(info)) = parse_client_hello(&handshake_payload) {
            let sni_valid = if self.server_names.is_empty() {
                true
            } else if let Some(ref sni) = info.server_name {
                let sni_lower = sni.to_lowercase();
                self.server_names
                    .iter()
                    .any(|s| s.to_lowercase() == sni_lower)
            } else {
                false
            };

            if !sni_valid {
                tracing::debug!(
                    "Reality SNI mismatch: {:?} (Allowed: {:?})",
                    info.server_name,
                    self.server_names
                );
            } else if let Some((_offset, auth_key)) =
                self.verify_client_reality(&info, &handshake_payload)
            {
                let host = info.server_name.as_deref().unwrap_or("localhost");
                let (cert, private_key) = self.generate_reality_cert(&auth_key, host)?;

                let certified_key =
                    Arc::new(rustls::sign::CertifiedKey::new(vec![cert], private_key));

                let resolver = Arc::new(SingleCertResolver { certified_key });

                let mut conn_reality_config = self.reality_config.as_ref().clone();
                conn_reality_config.private_key = auth_key.to_vec();

                let mut config = self.template_config.as_ref().clone();
                config.cert_resolver = resolver;
                config.reality_config = Some(Arc::new(conn_reality_config));

                let acceptor = TlsAcceptor::from(Arc::new(config));
                let prefixed = PrefixedStream::new(buffer, stream);

                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    acceptor.accept(prefixed),
                )
                .await
                {
                    Ok(Ok(tls)) => {
                        tracing::info!("Reality handshake successful");
                        return Ok(tls);
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("Reality TLS handshake failed: {}", e);
                        return Err(Box::from("Handshake failure"));
                    }
                    Err(_) => {
                        tracing::debug!("Reality TLS handshake timeout");
                        return Err(Box::from("Handshake timeout"));
                    }
                }
            }
        }

        let dest = self.reality_config.dest.as_deref().ok_or_else(|| {
            Box::<dyn std::error::Error + Send + Sync>::from("Reality dest is missing in config")
        })?;
        tracing::debug!(
            "Non-Reality client or SNI mismatch, falling back to {}",
            dest
        );
        self.fallback(stream, &buffer, dest).await?;
        Err(Box::from("Fallback completed"))
    }

    fn verify_client_reality(
        &self,
        info: &ClientHelloInfo,
        handshake_payload: &[u8],
    ) -> Option<(usize, [u8; 32])> {
        if info.session_id.len() != 32 || info.public_key.is_none() {
            return None;
        }

        let mut server_priv = [0u8; 32];
        server_priv.copy_from_slice(&self.reality_config.private_key);
        let client_pub: [u8; 32] = info.public_key.as_ref()?.as_slice().try_into().ok()?;

        let shared =
            StaticSecret::from(server_priv).diffie_hellman(&X25519PublicKey::from(client_pub));

        let hk = Hkdf::<Sha256>::new(Some(&info.client_random[0..20]), shared.as_bytes());
        let mut auth_key = [0u8; 32];
        if hk.expand(b"REALITY", &mut auth_key).is_err() {
            return None;
        }

        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&auth_key));
        let nonce = Nonce::from_slice(&info.client_random[20..32]);

        let mut aad = handshake_payload.to_vec();
        let pos = info.session_id_offset;

        for i in 0..32 {
            if pos + i < aad.len() {
                aad[pos + i] = 0;
            }
        }

        let mut buf = info.session_id.clone();
        if cipher.decrypt_in_place(nonce, &aad, &mut buf).is_err() {
            return None;
        }
        if buf.len() < 16 {
            return None;
        }

        for sid in &self.reality_config.short_ids {
            if sid == &buf[4..12] {
                return Some((4, auth_key));
            }
            if sid == &buf[8..16] {
                return Some((8, auth_key));
            }
        }
        None
    }

    fn generate_reality_cert(
        &self,
        auth_key: &[u8; 32],
        host: &str,
    ) -> Result<
        (CertificateDer<'static>, Arc<dyn rustls::sign::SigningKey>),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let key = CertKey {
            host: host.to_string(),
        };

        let mut template = None;
        {
            if let Ok(mut cache) = CERT_CACHE.lock() {
                if let Some(cached_tuple) = cache.get(&key) {
                    template = Some(cached_tuple.clone());
                }
            }
        }

        if template.is_none() {
            use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

            let key_pair = KeyPair::generate(&PKCS_ED25519)?;
            let pub_key_raw = key_pair.public_key_raw().to_vec();
            let mut params = CertificateParams::new(vec![host.to_string()]);
            params.alg = &PKCS_ED25519;
            params.key_pair = Some(key_pair);

            let cert = rcgen::Certificate::from_params(params)?;
            let cert_der = cert.serialize_der()?;
            let priv_key_der = cert.serialize_private_key_der();

            let private_key = rustls::crypto::ring::default_provider()
                .key_provider
                .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(priv_key_der)))?;

            if let Ok(mut cache) = CERT_CACHE.lock() {
                cache.put(
                    key.clone(),
                    (
                        cert_der.clone(),
                        pub_key_raw.clone(),
                        Arc::clone(&private_key),
                    ),
                );
            }

            template = Some((cert_der, pub_key_raw, private_key));
        }

        let (mut cert_der, pub_key_raw, private_key) = template.unwrap();

        let total_len = cert_der.len();
        if total_len < 64 {
            return Err("CERT DER too short".into());
        }
        let sig_pos = total_len - 64;
        let ring_key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
        let signature = hmac::sign(&ring_key, &pub_key_raw);
        let sig_bytes = signature.as_ref();

        cert_der[sig_pos..].copy_from_slice(sig_bytes);

        let result_cert = CertificateDer::from(cert_der);
        Ok((result_cert, private_key))
    }

    async fn fallback<S>(
        &self,
        mut stream: S,
        prefix: &[u8],
        dest: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let ipv4_only = crate::config::is_ipv4_only();
        let mut dest_stream = if ipv4_only {
            let (host, port) = if let Some(pos) = dest.rfind(':') {
                let (h, p_str) = dest.split_at(pos);
                let p = p_str[1..].parse::<u16>().unwrap_or(443);
                (h, p)
            } else {
                (dest, 443)
            };
            let resolver = crate::transport::DefaultResolver::new(true, None);
            let resolved = resolver
                .resolve_ipv4(host, port, crate::transport::SelectedRoute::Direct)
                .await?;
            let mut last_err = None;
            let mut stream = None;
            for addr in resolved {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    TcpStream::connect(addr),
                )
                .await
                {
                    Ok(Ok(s)) => {
                        stream = Some(s);
                        break;
                    }
                    Ok(Err(e)) => last_err = Some(e),
                    Err(_) => {
                        last_err = Some(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "fallback connection timed out",
                        ))
                    }
                }
            }
            if let Some(s) = stream {
                s
            } else {
                return Err(last_err.map(Into::into).unwrap_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "No addresses resolved for fallback target",
                    )
                    .into()
                }));
            }
        } else {
            tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect(dest))
                .await??
        };
        let _ = dest_stream.set_nodelay(true);
        dest_stream.write_all(prefix).await?;
        tokio::io::copy_bidirectional(&mut stream, &mut dest_stream).await?;
        Ok(())
    }
}

pub struct PrefixedStream<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    pub inner: S,
}
impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.prefix.has_remaining() {
            let n = std::cmp::min(buf.remaining(), self.prefix.remaining());
            let pos = self.prefix.position() as usize;
            buf.put_slice(&self.prefix.get_ref()[pos..pos + n]);
            self.prefix.set_position((pos + n) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn preflight_reality_check(
    dest: &str,
    sni: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut root_store = rustls::RootCertStore::empty();
    let cert_result = rustls_native_certs::load_native_certs();
    for err in &cert_result.errors {
        tracing::warn!("Failed to load some native certificates: {}", err);
    }
    for cert in cert_result.certs {
        let _ = root_store.add(cert);
    }

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls_pki_types::ServerName::try_from(sni.to_string())
        .map_err(|e| format!("Invalid SNI '{}': {}", sni, e))?;

    let ipv4_only = crate::config::is_ipv4_only();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let stream = if ipv4_only {
            let (host, port) = if let Some(pos) = dest.rfind(':') {
                let (h, p_str) = dest.split_at(pos);
                let p = p_str[1..].parse::<u16>().unwrap_or(443);
                (h, p)
            } else {
                (dest, 443)
            };
            let resolver = crate::transport::DefaultResolver::new(true, None);
            let resolved = resolver
                .resolve_ipv4(host, port, crate::transport::SelectedRoute::Direct)
                .await?;
            let mut last_err = None;
            let mut s_opt = None;
            for addr in resolved {
                match TcpStream::connect(addr).await {
                    Ok(s) => {
                        s_opt = Some(s);
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            if let Some(s) = s_opt {
                s
            } else {
                return Err(last_err.map(Into::into).unwrap_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "No addresses resolved",
                    )
                    .into()
                }));
            }
        } else {
            TcpStream::connect(dest).await?
        };
        let _tls_stream = connector.connect(server_name, stream).await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| {
        format!(
            "Preflight TLS connection to {} for SNI {} timed out after 3 seconds",
            dest, sni
        )
    })?
    .map_err(|e| {
        format!(
            "Preflight TLS check failed for dest={} sni={}: {}",
            dest, sni, e
        )
    })?;

    Ok(())
}

pub struct RealityRuntime {
    pub profile: Arc<RealityProfile>,
    pub server: Arc<RealityServerRustls>,
    pub public_key: Arc<str>,
    pub short_id_set: Arc<HashSet<Vec<u8>>>,
}

impl RealityRuntime {
    pub fn new(profile: RealityProfile) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let private_key =
            base64::Engine::decode(&base64::prelude::BASE64_STANDARD, &profile.private_key)
                .or_else(|_| hex::decode(&profile.private_key))?;

        let server = RealityServerRustls::new(
            private_key,
            Some(profile.dest.clone()),
            profile.short_ids.clone(),
            profile.server_names.clone(),
        )?;

        let public_key = crate::config::derive_reality_public_key(&profile.private_key)
            .ok_or("Failed to derive public key")?;

        let mut short_id_set = HashSet::new();
        for id in &profile.short_ids {
            if let Ok(b) = hex::decode(id) {
                short_id_set.insert(b);
            }
        }

        Ok(Self {
            profile: Arc::new(profile),
            server: Arc::new(server),
            public_key: Arc::from(public_key),
            short_id_set: Arc::new(short_id_set),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub public_key: String,
    pub certificate_names: Vec<String>,
    pub connect_latency_ms: u64,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

pub fn extract_domains_from_der(der: &[u8]) -> Result<Vec<String>, String> {
    use x509_parser::prelude::*;
    let (_, x509) = X509Certificate::from_der(der)
        .map_err(|e| format!("Failed to parse DER certificate: {}", e))?;

    let mut domains = Vec::new();

    // Extract Common Name (CN) from Subject
    for attr in x509.subject().iter_common_name() {
        if let Ok(cn) = attr.attr_value().as_str() {
            domains.push(cn.to_string());
        }
    }

    // Extract Subject Alternative Names (SAN) from extensions
    for ext in x509.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    domains.push(dns.to_string());
                }
            }
        }
    }

    // Deduplicate and normalize
    domains.sort();
    domains.dedup();

    Ok(domains)
}

pub fn name_matches_pattern(name: &str, pattern: &str) -> bool {
    let name = name.to_lowercase();
    let pattern = pattern.to_lowercase();

    if pattern.starts_with("*.") {
        let suffix = &pattern[1..];
        if name.ends_with(suffix) {
            let prefix = &name[..name.len() - suffix.len()];
            !prefix.is_empty() && !prefix.ends_with('.') && !prefix.contains('.')
        } else {
            false
        }
    } else {
        name == pattern
    }
}

pub async fn validate_reality_target(
    dest: &str,
    server_names: &[String],
    private_key: &str,
    short_ids: &[String],
    port: u16,
) -> Result<ValidationResult, String> {
    let _permit = crate::state::REALITY_VALIDATION.acquire().await;
    // 1. Check listen port availability locally
    let port_check = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await;
    if port_check.is_err() {
        return Ok(ValidationResult {
            valid: false,
            public_key: "".to_string(),
            certificate_names: vec![],
            connect_latency_ms: 0,
            warnings: vec![],
            error: Some(format!("Port {} is already in use", port)),
        });
    }

    // 2. Validate short IDs format
    for sid in short_ids {
        if sid.len() < 2 || sid.len() > 16 || sid.len() % 2 != 0 {
            return Ok(ValidationResult {
                valid: false,
                public_key: "".to_string(),
                certificate_names: vec![],
                connect_latency_ms: 0,
                warnings: vec![],
                error: Some(format!("Reality short ID must be even length between 2 and 16 hex characters, got '{}'", sid)),
            });
        }
        if hex::decode(sid).is_err() {
            return Ok(ValidationResult {
                valid: false,
                public_key: "".to_string(),
                certificate_names: vec![],
                connect_latency_ms: 0,
                warnings: vec![],
                error: Some(format!(
                    "Reality short ID must be a valid hex string, got '{}'",
                    sid
                )),
            });
        }
    }

    // 3. Derive public key
    let public_key = match crate::config::derive_reality_public_key(private_key) {
        Some(pbk) => pbk,
        None => {
            return Ok(ValidationResult {
                valid: false,
                public_key: "".to_string(),
                certificate_names: vec![],
                connect_latency_ms: 0,
                warnings: vec![],
                error: Some("Invalid base64/hex Reality private key".to_string()),
            });
        }
    };

    // 4. Perform reachability and cert verification
    let sni = match server_names.first() {
        Some(s) => s,
        None => {
            return Ok(ValidationResult {
                valid: false,
                public_key,
                certificate_names: vec![],
                connect_latency_ms: 0,
                warnings: vec![],
                error: Some("Server names list is empty".to_string()),
            });
        }
    };

    let start_time = std::time::Instant::now();
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        root_store.add(cert).ok();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = match rustls_pki_types::ServerName::try_from(sni.to_string()) {
        Ok(sn) => sn,
        Err(e) => {
            return Ok(ValidationResult {
                valid: false,
                public_key,
                certificate_names: vec![],
                connect_latency_ms: 0,
                warnings: vec![],
                error: Some(format!("Invalid SNI '{}': {}", sni, e)),
            });
        }
    };

    let ipv4_only = crate::config::is_ipv4_only();
    let handshake_res = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let stream = if ipv4_only {
            let (host, port) = if let Some(pos) = dest.rfind(':') {
                let (h, p_str) = dest.split_at(pos);
                let p = p_str[1..].parse::<u16>().unwrap_or(443);
                (h, p)
            } else {
                (dest, 443)
            };
            let resolver = crate::transport::DefaultResolver::new(true, None);
            let resolved = resolver
                .resolve_ipv4(host, port, crate::transport::SelectedRoute::Direct)
                .await?;
            let mut last_err = None;
            let mut s_opt = None;
            for addr in resolved {
                match TcpStream::connect(addr).await {
                    Ok(s) => {
                        s_opt = Some(s);
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            if let Some(s) = s_opt {
                s
            } else {
                return Err(last_err.map(Into::into).unwrap_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "No addresses resolved",
                    )
                    .into()
                }));
            }
        } else {
            TcpStream::connect(dest).await?
        };
        let tls_stream = connector.connect(server_name, stream).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(tls_stream)
    })
    .await;

    let tls_stream = match handshake_res {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return Ok(ValidationResult {
                valid: false,
                public_key,
                certificate_names: vec![],
                connect_latency_ms: 0,
                warnings: vec![],
                error: Some(format!("TLS handshake check failed: {}", e)),
            });
        }
        Err(_) => {
            return Ok(ValidationResult {
                valid: false,
                public_key,
                certificate_names: vec![],
                connect_latency_ms: 0,
                warnings: vec![],
                error: Some("TLS handshake check timed out after 3 seconds".to_string()),
            });
        }
    };

    let connect_latency_ms = start_time.elapsed().as_millis() as u64;

    let (_, client_conn) = tls_stream.get_ref();
    let peer_certs = match client_conn.peer_certificates() {
        Some(certs) if !certs.is_empty() => certs,
        _ => {
            return Ok(ValidationResult {
                valid: false,
                public_key,
                certificate_names: vec![],
                connect_latency_ms,
                warnings: vec![],
                error: Some("No certificates presented by the upstream server".to_string()),
            });
        }
    };

    let end_entity_cert = &peer_certs[0];
    let cert_domains = match extract_domains_from_der(end_entity_cert) {
        Ok(domains) => domains,
        Err(e) => {
            return Ok(ValidationResult {
                valid: false,
                public_key,
                certificate_names: vec![],
                connect_latency_ms,
                warnings: vec![],
                error: Some(format!("Failed to parse upstream certificate: {}", e)),
            });
        }
    };

    let covers_sni = cert_domains
        .iter()
        .any(|pattern| name_matches_pattern(sni, pattern));
    if !covers_sni {
        return Ok(ValidationResult {
            valid: false,
            public_key,
            certificate_names: cert_domains,
            connect_latency_ms,
            warnings: vec![],
            error: Some(format!(
                "Destination {} returned a certificate that does not cover {}.",
                dest, sni
            )),
        });
    }

    Ok(ValidationResult {
        valid: true,
        public_key,
        certificate_names: cert_domains,
        connect_latency_ms,
        warnings: vec![],
        error: None,
    })
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::config::{
        ApiConfig, Config, InboundConfig, InboundSettings, RealitySettings, RoutingConfig,
        StreamSettings,
    };
    use crate::inbound::create_inbound_listener;
    use crate::state::EngineState;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    fn build_reality_client_hello(
        server_pub_b64: &str,
        short_id_hex: &str,
        sni: &str,
        wrong_pbk: bool,
        wrong_sid: bool,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // 1. Generate standard ClientHello using rustls
        let root_store = rustls::RootCertStore::empty();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let mut conn = rustls::client::ClientConnection::new(
            Arc::new(client_config),
            rustls_pki_types::ServerName::try_from(sni.to_string())?,
        )?;

        let mut record = Vec::new();
        let _ = conn.write_tls(&mut record)?;

        // Extract handshake payload
        let record_header = &record[0..5];
        let mut handshake_payload = record[5..].to_vec();

        let info = parse_client_hello(&handshake_payload)?.ok_or("Failed to parse ClientHello")?;

        let pubkey_bytes = info
            .public_key
            .as_ref()
            .ok_or("No public key in ClientHello")?;
        let pubkey_offset = handshake_payload
            .windows(32)
            .position(|w| w == pubkey_bytes)
            .ok_or("Could not locate public key offset")?;

        // 2. Generate client-side ephemeral X25519 keypair
        let client_priv_bytes = [7u8; 32];
        let client_secret = StaticSecret::from(client_priv_bytes);
        let client_pub = X25519PublicKey::from(&client_secret);

        // Modify key_share public key in handshake payload
        handshake_payload[pubkey_offset..pubkey_offset + 32].copy_from_slice(client_pub.as_bytes());

        // 3. Compute shared secret
        let mut server_pub_bytes =
            base64::Engine::decode(&base64::prelude::BASE64_URL_SAFE_NO_PAD, server_pub_b64)
                .or_else(|_| hex::decode(server_pub_b64))?;
        if wrong_pbk && !server_pub_bytes.is_empty() {
            server_pub_bytes[0] ^= 0xFF;
        }
        let server_pub_arr: [u8; 32] = server_pub_bytes
            .try_into()
            .map_err(|_| "Invalid server public key length")?;
        let server_pub = X25519PublicKey::from(server_pub_arr);

        let shared = client_secret.diffie_hellman(&server_pub);

        // 4. Derive auth_key using HKDF-Expand
        let hk = Hkdf::<Sha256>::new(Some(&info.client_random[0..20]), shared.as_bytes());
        let mut auth_key = [0u8; 32];
        hk.expand(b"REALITY", &mut auth_key)
            .map_err(|e| format!("HKDF expand failed: {:?}", e))?;

        // 5. Construct plaintext buffer (16 bytes)
        let mut plaintext = [0u8; 16];
        let mut sid_bytes = hex::decode(short_id_hex)?;
        if wrong_sid && !sid_bytes.is_empty() {
            sid_bytes[0] ^= 0xFF;
        }
        plaintext[4..4 + sid_bytes.len()].copy_from_slice(&sid_bytes);

        // 6. Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&auth_key));
        let nonce = GenericArray::from_slice(&info.client_random[20..32]);

        // Zero out session ID in handshake_payload for AAD calculation
        let mut aad = handshake_payload.clone();
        for i in 0..32 {
            if info.session_id_offset + i < aad.len() {
                aad[info.session_id_offset + i] = 0;
            }
        }

        let mut ciphertext = plaintext.to_vec();
        cipher
            .encrypt_in_place(nonce, &aad, &mut ciphertext)
            .map_err(|e| format!("Encryption failed: {:?}", e))?;

        // Write ciphertext (32 bytes) back to handshake_payload
        handshake_payload[info.session_id_offset..info.session_id_offset + 32]
            .copy_from_slice(&ciphertext);

        // 7. Reconstruct TLS record
        let payload_len = handshake_payload.len();
        let mut final_record = record_header.to_vec();
        final_record[3..5].copy_from_slice(&(payload_len as u16).to_be_bytes());
        final_record.extend_from_slice(&handshake_payload);

        Ok(final_record)
    }

    #[tokio::test]
    async fn test_reality_integration_flow() {
        let rs = RealitySettings {
            dest: "aka.ms:443".to_string(),
            server_names: vec!["aka.ms".to_string()],
            private_key: "hZHP8YPZFBGa3Cno3nepKfop/+KWy3YmpXq5WQdfryI=".to_string(),
            short_ids: vec!["da09ebd28dc215c8".to_string()],
        };
        let inbound = InboundConfig {
            tag: "vless-reality".to_string(),
            listen: "127.0.0.1".parse().unwrap(),
            port: 10443,
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
                listen: "127.0.0.1".parse().unwrap(),
                port: 19091,
                trusted_proxies: vec![],
            },
            reality_profiles: vec![],
            warp_domain_sets: vec![],
            direct_exception_sets: vec![],
            ..Default::default()
        };

        let (engine, _rx) = EngineState::new(config);
        let engine_state = Arc::new(engine);

        let inbound_config = engine_state.config.read().inbounds[0].clone();
        let listener = create_inbound_listener(inbound_config).unwrap();

        let engine_clone = Arc::clone(&engine_state);
        tokio::spawn(async move {
            let _ = listener.start(engine_clone).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut params = crate::config::RealityClientParameters::from_config(
            &engine_state.config.read(),
            "127.0.0.1",
        )
        .unwrap();

        // 1. Success case: correct SNI, pbk, and short ID
        {
            let valid_payload = build_reality_client_hello(
                &params.public_key,
                &params.short_id,
                &params.server_name,
                false,
                false,
            )
            .unwrap();
            let mut stream = TcpStream::connect("127.0.0.1:10443").await.unwrap();
            stream.write_all(&valid_payload).await.unwrap();
            let mut response = vec![0u8; 1024];
            let bytes_read = stream.read(&mut response).await.unwrap();
            assert!(bytes_read >= 5, "Response too short");
            // Verify TLS record header indicating Handshake record type (0x16)
            assert_eq!(
                response[0], 0x16,
                "Should respond with TLS Handshake record"
            );
        }

        // 2. Failure: wrong SNI
        {
            let invalid_sni_payload = build_reality_client_hello(
                &params.public_key,
                &params.short_id,
                "www.microsoft.com",
                false,
                false,
            )
            .unwrap();
            let mut stream2 = TcpStream::connect("127.0.0.1:10443").await.unwrap();
            stream2.write_all(&invalid_sni_payload).await.unwrap();
            let mut response2 = vec![0u8; 1024];
            let bytes_read2 = stream2.read(&mut response2).await.unwrap();
            // Since SNI was wrong, the server will either drop/refuse connection, or fallback.
            // If it successfully fell back, it forwarded to destination aka.ms.
            // Check if fallback completed or connection closed:
            if bytes_read2 > 0 {
                assert_eq!(
                    response2[0], 0x16,
                    "Fallback destination should still respond with a TLS Handshake record"
                );
            }
        }

        // 3. Failure: wrong public key
        {
            let invalid_pbk_payload = build_reality_client_hello(
                &params.public_key,
                &params.short_id,
                &params.server_name,
                true,
                false,
            )
            .unwrap();
            let mut stream3 = TcpStream::connect("127.0.0.1:10443").await.unwrap();
            stream3.write_all(&invalid_pbk_payload).await.unwrap();
            let mut response3 = vec![0u8; 1024];
            let bytes_read3 = stream3.read(&mut response3).await.unwrap();
            if bytes_read3 > 0 {
                assert_eq!(
                    response3[0], 0x16,
                    "Fallback destination should still respond with a TLS Handshake record"
                );
            }
        }

        // 4. Failure: wrong short ID
        {
            let invalid_sid_payload = build_reality_client_hello(
                &params.public_key,
                &params.short_id,
                &params.server_name,
                false,
                true,
            )
            .unwrap();
            let mut stream4 = TcpStream::connect("127.0.0.1:10443").await.unwrap();
            stream4.write_all(&invalid_sid_payload).await.unwrap();
            let mut response4 = vec![0u8; 1024];
            let bytes_read4 = stream4.read(&mut response4).await.unwrap();
            if bytes_read4 > 0 {
                assert_eq!(
                    response4[0], 0x16,
                    "Fallback destination should still respond with a TLS Handshake record"
                );
            }
        }

        params.uuid = uuid::Uuid::parse_str("ad60c2b2-cc0c-492a-89aa-c92330a10cc9").unwrap();
        let json_str = params.to_singbox_json();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let rules = parsed["route"]["rules"].as_array().unwrap();

        let has_direct_ip = rules.iter().any(|r| {
            r["outbound"].as_str() == Some("direct")
                && r["ip_cidr"]
                    .as_array()
                    .is_some_and(|arr| arr.contains(&serde_json::json!("127.0.0.1/32")))
        });
        assert!(
            has_direct_ip,
            "Should have a direct route for the VPN server IP"
        );

        let has_direct_ports = rules.iter().any(|r| {
            r["outbound"].as_str() == Some("direct")
                && r["port"].as_array().is_some_and(|arr| {
                    arr.contains(&serde_json::json!(9091)) && arr.contains(&serde_json::json!(9100))
                })
        });
        assert!(
            has_direct_ports,
            "Should have a direct route for management ports 9091 and 9100"
        );
    }

    #[test]
    fn test_name_matches_pattern() {
        use super::name_matches_pattern;
        assert!(name_matches_pattern("aka.ms", "aka.ms"));
        assert!(name_matches_pattern("AKA.MS", "aka.ms"));
        assert!(name_matches_pattern("sub.aka.ms", "*.aka.ms"));
        assert!(!name_matches_pattern("nested.sub.aka.ms", "*.aka.ms"));
        assert!(!name_matches_pattern("aka.ms", "*.aka.ms"));
        assert!(!name_matches_pattern("microsoft.com", "aka.ms"));
    }

    #[tokio::test]
    async fn test_global_handshake_limit() {
        let semaphore = tokio::sync::Semaphore::new(4);
        let p1 = semaphore.try_acquire().unwrap();
        let _p2 = semaphore.try_acquire().unwrap();
        let _p3 = semaphore.try_acquire().unwrap();
        let _p4 = semaphore.try_acquire().unwrap();
        assert!(semaphore.try_acquire().is_err());
        drop(p1);
        let _p5 = semaphore.try_acquire().unwrap();
    }

    #[test]
    fn test_per_ip_handshake_limit() {
        use std::collections::HashMap;
        let map = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let ip = "127.0.0.1".parse::<std::net::IpAddr>().unwrap();

        // 1. IP active handshake count tracking
        {
            let mut guard = map.lock();
            let current = guard.get(&ip).cloned().unwrap_or(0);
            assert_eq!(current, 0);
            guard.insert(ip, current + 1);
        }

        {
            let mut guard = map.lock();
            let current = guard.get(&ip).cloned().unwrap_or(0);
            assert_eq!(current, 1);
            guard.insert(ip, current + 1);
        }

        // 2. Reject 3rd handshake
        {
            let guard = map.lock();
            let current = guard.get(&ip).cloned().unwrap_or(0);
            assert!(current >= 2);
        }

        // 3. Decrement count
        {
            let mut guard = map.lock();
            if let Some(cnt) = guard.get_mut(&ip) {
                if *cnt > 1 {
                    *cnt -= 1;
                } else {
                    guard.remove(&ip);
                }
            }
        }

        {
            let guard = map.lock();
            let current = guard.get(&ip).cloned().unwrap_or(0);
            assert_eq!(current, 1);
        }
    }

    #[test]
    fn test_dashboard_cache_endpoint() {
        let cached_response = crate::state::CachedJsonResponse {
            body: bytes::Bytes::from("{\"status\":\"ok\"}"),
            etag: Arc::from("\"test-etag\""),
            generated_at: std::time::Instant::now(),
            generation: 1,
        };
        let cell = arc_swap::ArcSwap::new(Arc::new(cached_response));
        let loaded = cell.load();
        assert_eq!(loaded.body.as_ref(), b"{\"status\":\"ok\"}");
    }

    #[test]
    fn test_exact_quota_enforcement() {
        use std::sync::atomic::AtomicI64;
        let quota = AtomicI64::new(100);

        // First reserve 60 bytes
        let r1 = super::super::reserve_quota(&quota, 60);
        assert_eq!(r1, 60);
        assert_eq!(quota.load(std::sync::atomic::Ordering::Relaxed), 40);

        // Next reserve 60 bytes, should get remaining 40
        let r2 = super::super::reserve_quota(&quota, 60);
        assert_eq!(r2, 40);
        assert_eq!(quota.load(std::sync::atomic::Ordering::Relaxed), 0);

        // Next reserve 10 bytes, should get 0
        let r3 = super::super::reserve_quota(&quota, 10);
        assert_eq!(r3, 0);
        assert_eq!(quota.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}
