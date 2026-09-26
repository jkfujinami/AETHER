use crate::{Config, Result, AetherError};
use crate::net::shared_socket::{SharedSocket, SideChannelDatagram};
use quinn::Endpoint;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

/// 保ち続ける接続の keepalive 間隔（quinn の既定アイドル上限 30 秒より十分短く）
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

pub struct QuicServer {
    endpoint: Endpoint,
    /// QUIC が使っているソケット
    ///
    /// STUN も punch もここから撃つ。別ソケットだと NAT マッピングが
    /// 別物になり、得た外部アドレスも開けた穴も QUIC には使えない。
    socket: Arc<SharedSocket>,
    /// 横取りした STUN の受け口（1度だけ取り出せる）
    side_rx: Mutex<Option<mpsc::UnboundedReceiver<SideChannelDatagram>>>,
}

impl QuicServer {
    pub fn new(config: &Config) -> Result<Self> {
        let (cert, key) = Self::generate_self_signed_cert()?;

        let server_config = quinn::ServerConfig::with_single_cert(
            vec![cert],
            key,
        ).map_err(|e| AetherError::Quic(e.to_string()))?;

        // **デュアルスタックで bind する。**
        // IPv6 が使える環境では NAT が存在しないため、
        // punch なしで到達可能になる（日本の IPoE 環境で効く）。
        // v4 のピアは ::ffff:a.b.c.d として見えるので、
        // アドレスをキーに使う箇所では addr::normalize を通すこと。
        let raw = crate::net::addr::bind_dual_stack(config.listen_port)
            .map_err(AetherError::Network)?;

        // **STUN と QUIC を同じソケットに同居させる。**
        let runtime = quinn::TokioRuntime;
        let (socket, side_rx) = SharedSocket::from_std(raw, &runtime)
            .map_err(AetherError::Network)?;

        let endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket.clone(),
            Arc::new(runtime),
        ).map_err(AetherError::Network)?;

        // **同じエンドポイントから発信もする。**
        //
        // 別ソケットで発信すると:
        // - 観測される送信元が広告アドレスと食い違い、フィルタ判定が狂う
        // - outbound が inbound 側の NAT マッピングを維持しない
        //   （発信で穴が開くのは発信に使ったソケットの分だけ）
        // - NAT のセッション表を2つ消費する
        let mut endpoint = endpoint;
        endpoint.set_default_client_config(QuicClient::skip_verify_config()?);

        Ok(Self {
            endpoint,
            socket,
            side_rx: Mutex::new(Some(side_rx)),
        })
    }

    /// 発信にも使うエンドポイント
    ///
    /// **待ち受けと発信で同じソケットを使うこと。**
    /// 別にすると NAT マッピングが2つになり、
    /// 広告しているポートの穴を outbound が維持しなくなる。
    pub fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }

    /// QUIC が使っているソケット（STUN / punch の送出に使う）
    pub fn shared_socket(&self) -> Arc<SharedSocket> {
        self.socket.clone()
    }

    /// 横取りした STUN の受け口を取り出す
    ///
    /// 1度しか取れない。受け取った側が全ての STUN を捌く責任を持つ。
    pub fn take_side_channel(&self) -> Option<mpsc::UnboundedReceiver<SideChannelDatagram>> {
        self.side_rx.lock().unwrap().take()
    }

    /// 取り出した受け口を返す
    ///
    /// **一時的に使ったら必ず返すこと。** 返さないと常時の消費者が
    /// 立てられず、punch の応答もフィルタ判定もできなくなる。
    pub fn restore_side_channel(&self, rx: mpsc::UnboundedReceiver<SideChannelDatagram>) {
        *self.side_rx.lock().unwrap() = Some(rx);
    }

    /// 既存のUDPソケットを使用してサーバーを起動する (Hole Punching用)
    pub fn new_with_socket(socket: std::net::UdpSocket) -> Result<Self> {
        let (cert, key) = Self::generate_self_signed_cert()?;

        let server_config = quinn::ServerConfig::with_single_cert(
            vec![cert],
            key,
        ).map_err(|e| AetherError::Quic(e.to_string()))?;

        let runtime = quinn::TokioRuntime;
        let (socket, side_rx) = SharedSocket::from_std(socket, &runtime)
            .map_err(AetherError::Network)?;

        let endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket.clone(),
            Arc::new(runtime),
        ).map_err(AetherError::Network)?;

        Ok(Self {
            endpoint,
            socket,
            side_rx: Mutex::new(Some(side_rx)),
        })
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

        // クライアント側もデュアルスタック。
        // v6 のリレーへ繋げなくなるのを防ぐ
        let socket = crate::net::addr::bind_dual_stack(0).map_err(AetherError::Network)?;

        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        ).map_err(AetherError::Network)?;

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

    pub(crate) fn skip_verify_config() -> Result<quinn::ClientConfig> {
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        config.dangerous().set_certificate_verifier(Arc::new(SkipServerVerification));

        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(config)
             .map_err(|e| AetherError::Config(format!("Failed to convert rustls config: {:?}", e)))?;

        Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
    }

    /// 保ち続ける接続用の設定（keepalive 付き）
    ///
    /// 通常の接続はアイドルで切れてよいが、返信トンネルの終端（ガード → 自分）は
    /// **自分が張った接続だけが唯一の戻り道**になる。切れると NAT の内側へは
    /// 二度と届かないので、無通信でも keepalive で生かしておく。
    pub(crate) fn keepalive_config() -> Result<quinn::ClientConfig> {
        let mut config = Self::skip_verify_config()?;
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(KEEPALIVE_INTERVAL));
        config.transport_config(Arc::new(transport));
        Ok(config)
    }

    /// keepalive 付きで接続する
    pub async fn connect_keepalive(&self, addr: SocketAddr, server_name: &str) -> Result<quinn::Connection> {
        let connecting = self.endpoint.connect_with(Self::keepalive_config()?, addr, server_name)
            .map_err(|e| AetherError::Quic(e.to_string()))?;

        connecting.await.map_err(|e| AetherError::Quic(e.to_string()))
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
