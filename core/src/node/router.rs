use crate::error::{Result, AetherError};
use crate::crypto::identity::Identity;
use crate::net::onion::{self, OnionAction};
use crate::net::seen_cache::SeenCache;
use crate::net::quic::QuicClient;
use crate::net::connection_pool::ConnectionPool;
use crate::protocol::wire::{self, PacketType};
use std::sync::Arc;
use tracing::debug;
use std::net::SocketAddr;

/// Routerがパケットを処理した結果のアクション
pub enum RoutingAction {
    /// 別のノードに転送した
    Forwarded,
    /// 自分が最終目的地だった（復号されたペイロードを含む）
    LocalProcessing(Vec<u8>),
}

/// Onion パケットの一時公開鍵を覚えておく時間
///
/// 経路に入れた時刻が ±`MAX_CLOCK_SKEW_MINUTES` 分を外れたパケットは時刻で弾くので、
/// その窓（前後合わせて 20 分）より長く覚えていれば再送は必ずどちらかで止まる。
const ONION_REPLAY_TTL: std::time::Duration =
    std::time::Duration::from_secs(2 * 60 * (onion::MAX_CLOCK_SKEW_MINUTES as u64 + 5));

/// リプレイ検出に覚えておく件数（1世代あたり）
const ONION_REPLAY_CAPACITY: usize = 1_000_000;

/// Onion Routing のパケット処理を担当するコンポーネント
pub struct Router {
    identity: Arc<Identity>,
    connection_pool: ConnectionPool,
    /// 処理した Onion パケットの一時公開鍵。同じパケットを二度処理しない
    seen_layers: std::sync::Mutex<SeenCache>,
}

fn replay_cache() -> std::sync::Mutex<SeenCache> {
    std::sync::Mutex::new(SeenCache::with_params(
        ONION_REPLAY_CAPACITY,
        ONION_REPLAY_TTL,
        1e-6,
    ))
}

impl Router {
    pub fn new(identity: Arc<Identity>) -> Result<Self> {
        let quic_client = Arc::new(QuicClient::new()?);
        let connection_pool = ConnectionPool::new(quic_client);
        Ok(Self { identity, connection_pool, seen_layers: replay_cache() })
    }

    /// 待ち受けと同じエンドポイントから発信する Router
    ///
    /// **ノードはこちらを使うこと。** 別ソケットで発信すると、
    /// 観測される送信元が広告アドレスと食い違い、
    /// outbound が広告ポートの NAT マッピングを維持しなくなる。
    pub fn with_endpoint(identity: Arc<Identity>, endpoint: quinn::Endpoint) -> Result<Self> {
        Ok(Self {
            identity,
            connection_pool: ConnectionPool::from_endpoint(endpoint),
            seen_layers: replay_cache(),
        })
    }

    /// 受信した Onion パケットの 1 層を処理する
    ///
    /// ヘッダの MAC と時刻を確かめ、次のホップへ同じ長さのまま転送するか、
    /// 自分が出口なら中身を返す。
    ///
    /// `is_allowed_next` で次ホップの妥当性を確かめてから転送する。
    /// **Router 自身はディレクトリを持たない**ので、呼び出し側（ノード）が
    /// 「自分自身か既知リレーか」を判定する述語を渡す。これが無いと、
    /// 中継が任意の踏み台・内部アドレスへダイヤルさせられる。
    pub async fn handle_packet(
        &self,
        packet: &[u8],
        is_allowed_next: impl Fn(SocketAddr) -> bool,
    ) -> Result<RoutingAction> {
        let (alpha, action) = onion::process_layer(&self.identity.x25519_secret(), packet)?;

        // **リプレイは捨てる。** 同じパケットを何度でも処理すると、ガードが同じものを
        // N 回流して出口側の反応を数え、回路の両端を突き合わせられる。
        // 一時公開鍵 α はパケットごとに作り直されるので、同じ α は再送。
        // 記録は MAC と時刻の検査に通ってから（偽パケットでキャッシュを埋めさせない）。
        // 時刻の窓（±MAX_CLOCK_SKEW_MINUTES）より古いものは process_layer が弾くので、
        // キャッシュはその窓より長く覚えていれば足りる。
        if !self.seen_layers.lock().unwrap().insert(alpha) {
            return Err(AetherError::Protocol("Replayed onion layer dropped".into()));
        }

        match action {
            OnionAction::Forward { next, packet } => {
                if !is_allowed_next(next) {
                    return Err(AetherError::Protocol(format!(
                        "Onion forward to disallowed next hop {} dropped",
                        next
                    )));
                }
                debug!("Forwarding packet to {}", next);
                self.forward_packet(next, &packet).await?;
                Ok(RoutingAction::Forwarded)
            }
            OnionAction::Exit { payload } => {
                debug!("Packet reached destination (self). Payload size: {}", payload.len());
                Ok(RoutingAction::LocalProcessing(payload))
            }
        }
    }

    /// Tunnel Buildパケットを処理し、リレー登録情報を抽出する
    /// Payload: [TunnelID(32)][EphPK(32)][Nonce(12)][EncInst]
    pub fn process_tunnel_build(&self, payload: &[u8]) -> Result<([u8; 32], [u8; 32], crate::net::tunnel::HopInstruction)> {
        crate::net::tunnel::open_build(&self.identity.x25519_secret(), payload)
    }

    /// accept した接続をプールへ登録する
    ///
    /// **これを呼ばないと NAT 内の相手へ送り返せない。**
    /// 相手が張った接続だけが、その相手への唯一の到達経路になる。
    pub async fn register_inbound(&self, connection: quinn::Connection) {
        self.connection_pool.register_inbound(connection).await;
    }

    /// **既存接続だけで**送る。無ければ失敗する
    ///
    /// 相手が NAT の内側にいる場合、ダイヤルは必ず失敗するので
    /// 「相手が張った接続があるか」が到達可否そのものになる。
    /// ダイヤルにフォールバックすると、届かない相手に対して
    /// タイムアウトぶんの時間を無駄にする。
    pub async fn send_packet_existing(
        &self,
        addr: SocketAddr,
        packet_type: PacketType,
        payload: &[u8],
    ) -> Result<()> {
        let conn = self
            .connection_pool
            .live_connection(addr)
            .await
            .ok_or_else(|| AetherError::Config(format!("No live connection to {}", addr)))?;

        let mut stream = conn.open_uni().await.map_err(|e| AetherError::Quic(e.to_string()))?;
        wire::write_packet(&mut stream, packet_type, payload).await?;
        stream.finish().map_err(|e| AetherError::Quic(e.to_string()))?;
        Ok(())
    }

    /// `addr` への keepalive 付き接続を張って保つ（返信トンネルの戻り道）
    pub async fn pin_connection(&self, addr: SocketAddr) -> Result<()> {
        self.connection_pool.pin_connection(addr).await?;
        Ok(())
    }

    /// 接続プールの掃除を走らせる
    pub async fn maintain_connections(&self) {
        self.connection_pool.maintain().await;
    }

    /// 生きた接続があるか（診断用）
    pub async fn has_live_connection(&self, addr: SocketAddr) -> bool {
        self.connection_pool.has_live_connection(addr).await
    }

    /// 新規 outbound 接続の通知を受け取る
    pub fn subscribe_opened(&self) -> tokio::sync::mpsc::UnboundedReceiver<quinn::Connection> {
        self.connection_pool.subscribe_opened()
    }

    /// 保持している inbound 接続の数（診断用）
    pub async fn inbound_count(&self) -> usize {
        self.connection_pool.inbound_count().await
    }

    /// 任意のパケットを指定した宛先に送信する
    pub async fn send_packet(&self, addr: SocketAddr, packet_type: PacketType, payload: &[u8]) -> Result<()> {
        // Connection Pool から接続を取得
        let conn = self.connection_pool.get_connection(addr).await?;
        let mut stream = conn.open_uni().await.map_err(|e| AetherError::Quic(e.to_string()))?;

        wire::write_packet(&mut stream, packet_type, payload).await?;
        stream.finish().map_err(|e| AetherError::Quic(e.to_string()))?;

        // Connection Pool が接続を保持するため、sleep 不要
        Ok(())
    }

    /// 次のホップへパケットを転送する (OnionPacket用)
    async fn forward_packet(&self, addr: SocketAddr, payload: &[u8]) -> Result<()> {
        self.send_packet(addr, PacketType::OnionPacket, payload).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::onion::OnionCircuit;
    use x25519_dalek::PublicKey;

    /// 自分宛て（出口）の1層パケットを作る
    fn packet_for(identity: &Identity) -> Vec<u8> {
        let mut circuit = OnionCircuit::new();
        let pubkey = PublicKey::from(&identity.x25519_secret()).to_bytes();
        circuit
            .add_hop("127.0.0.1:9000".parse().unwrap(), pubkey)
            .unwrap();
        circuit.wrap_packet(b"payload").unwrap()
    }

    #[tokio::test]
    async fn replayed_onion_layer_is_dropped() {
        let identity = Arc::new(Identity::generate());
        let router = Router::new(identity.clone()).unwrap();
        let packet = packet_for(&identity);

        assert!(matches!(
            router.handle_packet(&packet, |_| true).await.unwrap(),
            RoutingAction::LocalProcessing(_)
        ));
        assert!(router.handle_packet(&packet, |_| true).await.is_err(), "同じ層を二度処理した");

        // 同じ回路でも別パケット（一時鍵が違う）は通る
        let other = packet_for(&identity);
        assert!(router.handle_packet(&other, |_| true).await.is_ok());
    }

    /// 次ホップが許可述語に落ちる場合は転送しない（踏み台・内部アドレス対策）
    #[tokio::test]
    async fn forward_to_disallowed_next_hop_is_rejected() {
        let identity = Arc::new(Identity::generate());
        let router = Router::new(identity.clone()).unwrap();

        // 2ホップの回路: 自分は最初のホップ（転送役）
        let mut circuit = OnionCircuit::new();
        let self_pubkey = PublicKey::from(&identity.x25519_secret()).to_bytes();
        circuit.add_hop("127.0.0.1:9000".parse().unwrap(), self_pubkey).unwrap();
        let stranger = Identity::generate();
        let stranger_pubkey = PublicKey::from(&stranger.x25519_secret()).to_bytes();
        circuit.add_hop("203.0.113.9:9001".parse().unwrap(), stranger_pubkey).unwrap();
        let packet = circuit.wrap_packet(b"payload").unwrap();

        // 何も許可しない述語 → 転送されず、エラーになる
        assert!(router.handle_packet(&packet, |_| false).await.is_err());
    }
}
