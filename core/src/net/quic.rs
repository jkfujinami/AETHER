use crate::{Config, Result, AetherError};
use crate::net::shared_socket::{SharedSocket, SideChannelDatagram};
use quinn::Endpoint;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

/// ALPN（一般的な HTTP/3 と同じ値。空の ALPN もそれ自体が目印になる）
const ALPN: &[u8] = b"h3";

/// 証明書に入れる名前（起動ごとの乱数。固定名は能動的な調査で一覧化される）
fn random_host_name() -> String {
    use rand::Rng;
    const TLDS: &[&str] = &["com", "net", "org", "io", "jp"];
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(6..=12);
    let label: String = (0..len)
        .map(|_| (b'a' + rng.gen_range(0..26)) as char)
        .collect();
    format!("{}.{}", label, TLDS[rng.gen_range(0..TLDS.len())])
}

/// 接続先の名前（SNI）
///
/// **IP アドレスを名前にすると rustls は SNI を送らない。** 固定名（旧 `aether-node`）は
/// 暗号化されない ClientHello に載り、ISP が DPI をかけるだけで利用者を一覧化できた。
pub(crate) fn server_name_for(addr: &SocketAddr) -> String {
    addr.ip().to_string()
}

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
        let server_config = Self::server_config()?;

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
        let server_config = Self::server_config()?;

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

    /// 待ち受けの TLS 設定
    ///
    /// **目印を残さない。** 証明書の名前は起動ごとの乱数、ALPN は一般的な HTTP/3 と同じ `h3`。
    /// 固定名（旧 `aether-node`）だと、能動的に繋いで証明書を見るだけで AETHER と分かる。
    /// 自己署名である以上、正規のサイトと完全には見分けがつかなくならないが、
    /// 名前一つで一覧化される状態は避ける。
    fn server_config() -> Result<quinn::ServerConfig> {
        let (cert, key) = Self::generate_self_signed_cert()?;
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| AetherError::Quic(e.to_string()))?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| AetherError::Config(format!("Failed to convert rustls config: {:?}", e)))?;
        Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
    }

    fn generate_self_signed_cert() -> Result<(rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>)> {
        let cert = rcgen::generate_simple_self_signed(vec![random_host_name()])
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
        config.alpn_protocols = vec![ALPN.to_vec()];

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
    pub async fn connect_keepalive(&self, addr: SocketAddr) -> Result<quinn::Connection> {
        let connecting = self.endpoint.connect_with(Self::keepalive_config()?, addr, &server_name_for(&addr))
            .map_err(|e| AetherError::Quic(e.to_string()))?;

        connecting.await.map_err(|e| AetherError::Quic(e.to_string()))
    }

    /// 接続する（SNI は送らない。[`server_name_for`]）
    pub async fn connect(&self, addr: SocketAddr) -> Result<quinn::Connection> {
        let connecting = self.endpoint.connect(addr, &server_name_for(&addr))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_sni_is_sent_for_ip_addresses() {
        // IP アドレスの名前は rustls で IpAddress として扱われ、SNI 拡張が付かない
        for addr in ["203.0.113.5:9000", "[2001:db8::1]:443"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let name = ServerName::try_from(server_name_for(&addr)).unwrap();
            assert!(matches!(name, ServerName::IpAddress(_)), "{} で SNI が付く", addr);
        }
    }

    #[tokio::test]
    async fn client_and_server_agree_on_alpn() {
        // ALPN を両側で揃えないとハンドシェイクが通らない
        let server = QuicServer::new(&Config { listen_port: 0, ..Default::default() }).unwrap();
        let port = server.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let incoming = server.endpoint().accept().await.unwrap();
            let conn = incoming.await.unwrap();
            conn.handshake_data()
                .and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|h| h.protocol)
        });
        let client = QuicClient::new().unwrap();
        client
            .connect(format!("127.0.0.1:{}", port).parse().unwrap())
            .await
            .expect("ハンドシェイクが通らない");
        assert_eq!(accept.await.unwrap().as_deref(), Some(ALPN));
    }

    #[test]
    fn certificate_names_are_random() {
        let a = random_host_name();
        let b = random_host_name();
        assert_ne!(a, b);
        assert!(!a.contains("aether"));
    }
}
