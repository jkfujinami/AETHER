use crate::error::{Result, AetherError};
use crate::crypto::identity::Identity;
use crate::net::onion::OnionCircuit;
use crate::net::quic::QuicClient;
use crate::net::connection_pool::ConnectionPool;
use crate::protocol::wire::{self, PacketType};
use std::sync::Arc;
use tracing::debug;
use std::net::SocketAddr;
use x25519_dalek::PublicKey;

/// Routerがパケットを処理した結果のアクション
pub enum RoutingAction {
    /// 別のノードに転送した
    Forwarded,
    /// 自分が最終目的地だった（復号されたペイロードを含む）
    LocalProcessing(Vec<u8>),
}

/// Onion Routing のパケット処理を担当するコンポーネント
pub struct Router {
    identity: Arc<Identity>,
    connection_pool: ConnectionPool,
}

impl Router {
    pub fn new(identity: Arc<Identity>) -> Result<Self> {
        let quic_client = Arc::new(QuicClient::new()?);
        let connection_pool = ConnectionPool::new(quic_client);
        Ok(Self { identity, connection_pool })
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
        })
    }

    /// 受信したOnion Packetを処理する
    /// 1. パケット先頭の一時公開鍵と自分の秘密鍵で共有鍵を導出
    /// 2. パケットを復号（皮剥き）
    /// 3. 次のホップがあれば転送、なければペイロードを返す
    pub async fn handle_packet(&self, packet: &[u8]) -> Result<RoutingAction> {
        // パケット先頭のEphemeral Keyを取得
        if packet.len() < 32 {
            return Err(AetherError::Crypto("Packet too short for key derivation".into()));
        }

        let ephemeral_bytes: [u8; 32] = packet[0..32].try_into().unwrap();
        let ephemeral_pub = PublicKey::from(ephemeral_bytes);

        // 自分の秘密鍵と相手の公開鍵でDH計算
        let my_secret = self.identity.x25519_secret();
        let shared_secret_bytes = my_secret.diffie_hellman(&ephemeral_pub).to_bytes();

        // 復号とルーティング情報の取得
        // unwrap_packet 内部で先頭32バイト(Pubkey)はスキップされる
        let (next_hop, payload) = OnionCircuit::unwrap_packet(&shared_secret_bytes, packet)?;

        match next_hop {
            Some(addr) => {
                debug!("Forwarding packet to {}", addr);
                self.forward_packet(addr, &payload).await?;
                Ok(RoutingAction::Forwarded)
            }
            None => {
                debug!("Packet reached destination (self). Payload size: {}", payload.len());
                Ok(RoutingAction::LocalProcessing(payload))
            }
        }
    }

    /// Tunnel Buildパケットを処理し、リレー登録情報を抽出する
    /// Payload: [TunnelID(32)][EphPK(32)][Nonce(12)][EncInst]
    pub fn process_tunnel_build(&self, payload: &[u8]) -> Result<([u8; 32], [u8; 32], crate::net::tunnel::HopInstruction)> {
        if payload.len() < 32 + 32 + 12 {
            return Err(AetherError::Protocol("TunnelBuild packet too short".into()));
        }

        // Parse parts
        let tunnel_id: [u8; 32] = payload[0..32].try_into().unwrap();
        let eph_pk_bytes: [u8; 32] = payload[32..64].try_into().unwrap();
        let nonce: [u8; 12] = payload[64..76].try_into().unwrap();
        let ciphertext = &payload[76..];

        // DH
        let eph_pk = PublicKey::from(eph_pk_bytes);
        let my_secret = self.identity.x25519_secret();
        let shared_secret = my_secret.diffie_hellman(&eph_pk).to_bytes();

        // Decrypt Instruction
        let inst_bytes = crate::crypto::cipher::decrypt(&shared_secret, &nonce, ciphertext)?;
        let instruction: crate::net::tunnel::HopInstruction = bincode::deserialize(&inst_bytes)
            .map_err(|e| AetherError::Protocol(format!("Invalid instruction: {}", e)))?;

        Ok((tunnel_id, shared_secret, instruction))
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
        let conn = self.connection_pool.get_connection(addr, "aether-node").await?;
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
