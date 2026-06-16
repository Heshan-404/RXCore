use std::sync::Arc;
use tokio_rustls::rustls;
use tokio_rustls::{TlsConnector, TlsAcceptor};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{info, warn};

pub mod tls_helper {
    use super::*;

    // Low-overhead TLS client configuration using native OS roots
    pub fn create_client_config(
        _server_name: &str,
    ) -> Result<TlsConnector, Box<dyn std::error::Error + Send + Sync>> {
        let mut root_store = rustls::RootCertStore::empty();
        
        // Load native platform root certificates
        let native_certs = rustls_native_certs::load_native_certs();
        if !native_certs.errors.is_empty() {
            for err in native_certs.errors {
                warn!(error = %err, "Failed to load a native platform root certificate");
            }
        }

        for cert in native_certs.certs {
            if let Err(e) = root_store.add(cert) {
                warn!(error = %e, "Failed to add native certificate to trust store");
            }
        }

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(TlsConnector::from(Arc::new(config)))
    }

    // Auto-generate self-signed certs for server TLS configuration if custom files are not configured
    pub fn create_server_config(
        cert_path: Option<&str>,
        key_path: Option<&str>,
    ) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
        let (certs, key) = if let (Some(c_path), Some(k_path)) = (cert_path, key_path) {
            info!(cert = %c_path, key = %k_path, "Loading configured TLS credentials");
            let certs = load_certs(c_path)?;
            let key = load_key(k_path)?;
            (certs, key)
        } else {
            warn!("No certificate files configured. Generating ephemeral self-signed certificates.");
            let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
            let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;
            let cert_der = cert.serialize_der()?;
            let key_der = cert.serialize_private_key_der();
            (vec![CertificateDer::from(cert_der)], PrivateKeyDer::Pkcs8(key_der.into()))
        };

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, std::io::Error> {
        let certfile = std::fs::File::open(path)?;
        let mut reader = std::io::BufReader::new(certfile);
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(certs)
    }

    fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, std::io::Error> {
        let keyfile = std::fs::File::open(path)?;
        let mut reader = std::io::BufReader::new(keyfile);
        let key = rustls_pemfile::private_key(&mut reader)?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No private key found"))?;
        Ok(key)
    }
}
