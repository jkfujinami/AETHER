use crate::{Config, Result, AetherError};
use quinn::Endpoint;
use std::net::SocketAddr;
use std::sync::Arc;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

pub struct QuicServer {
    endpoint: Endpoint,
}

impl QuicServer {
    pub fn new(config: &Config) -> Result<Self> {
        let (cert, key) = Self::generate_self_signed_cert()?;

        let server_config = quinn::ServerConfig::with_single_cert(
            vec![cert],
            key,
        ).map_err(|e| AetherError::Quic(e.to_string()))?;

        let addr = SocketAddr::from(([0, 0, 0, 0], config.listen_port));
        let endpoint = Endpoint::server(server_config, addr)
             .map_err(AetherError::Network)?;

        Ok(Self { endpoint })
    }

    /// 既存のUDPソケットを使用してサーバーを起動する (Hole Punching用)
    pub fn new_with_socket(socket: std::net::UdpSocket) -> Result<Self> {
        let (cert, key) = Self::generate_self_signed_cert()?;

        let server_config = quinn::ServerConfig::with_single_cert(
            vec![cert],
            key,
        ).map_err(|e| AetherError::Quic(e.to_string()))?;

        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        ).map_err(AetherError::Network)?;

        Ok(Self { endpoint })
    }

    fn generate_self_signed_cert() -> Result<(rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>)> {
        let cert = rcgen::generate_simple_self_signed(vec!["aether-node".into()])
            .map_err(|e| AetherError::Crypto(e.to_string()))?;

        let key_der = cert.key_pair.serialize_der();
        let cert_der = cert.cert.der().to_vec();

        Ok((
            rustls::pki_types::CertificateDer::from(cert_der),
            rustls::pki_types::PrivateKeyDer::try_from(key_der)
                .map_err(|e| AetherError::Crypto(format!("Invalid private key: {:?}", e)))?
        ))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().map_err(AetherError::Network)
    }

    pub async fn accept(&self) -> Option<quinn::Incoming> {
        self.endpoint.accept().await
    }
}

pub struct QuicClient {
    endpoint: Endpoint,
}

impl QuicClient {
    pub fn new() -> Result<Self> {
        let client_config = Self::skip_verify_config()?;
        let mut endpoint = Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))
            .map_err(AetherError::Network)?;
        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint })
    }

    /// 既存のUDPソケットを使用してクライアントを起動する
    pub fn new_with_socket(socket: std::net::UdpSocket) -> Result<Self> {
        let client_config = Self::skip_verify_config()?;

        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None, // Server configなし = Client only
            socket,
            Arc::new(quinn::TokioRuntime),
        ).map_err(AetherError::Network)?;

        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint })
    }

    fn skip_verify_config() -> Result<quinn::ClientConfig> {
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        config.dangerous().set_certificate_verifier(Arc::new(SkipServerVerification));

        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(config)
             .map_err(|e| AetherError::Config(format!("Failed to convert rustls config: {:?}", e)))?;

        Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
    }

    pub async fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<quinn::Connection> {
        let connecting = self.endpoint.connect(addr, server_name)
            .map_err(|e| AetherError::Quic(e.to_string()))?;

        connecting.await.map_err(|e| AetherError::Quic(e.to_string()))
    }
}

// 共通型
pub type QuicConnection = quinn::Connection;

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
         Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
         Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
         vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}
