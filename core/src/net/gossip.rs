use crate::error::{Result, AetherError};
use crate::net::relay::RelayClient;
use crate::protocol::hint::HintPacket;
use crate::protocol::wire::PacketType;
use std::collections::HashSet;
use std::sync::Mutex;
use sha2::{Sha256, Digest};

/// Gossip プロトコルのクライアント
/// Relay ネットワークを通じて Hint を送受信する
pub struct GossipClient {
    relay: RelayClient,
    seen_hints: Mutex<HashSet<[u8; 32]>>, // SHA256ハッシュで管理
}

impl GossipClient {
    pub fn new(relay: RelayClient) -> Self {
        Self {
            relay,
            seen_hints: Mutex::new(HashSet::new()),
        }
    }

    /// Hint をネットワーク全体にブロードキャストする
    /// 実際には、接続している Entry Relay に送信し、そこから拡散してもらう
    pub async fn broadcast(&self, hint: &HintPacket) -> Result<()> {
        // Hint をシリアライズ
        let packet_bytes = bincode::serialize(hint)
            .map_err(|e| AetherError::Config(e.to_string()))?;

        // Relay に送信 (GossipHint として)
        // Router (Server) はこのパケットタイプを見てGossipServerに渡す
        self.relay.send_raw_packet(PacketType::GossipHint, &packet_bytes).await?;

        // 自分が送ったものは既知とする
        self.mark_as_seen(hint)?;

        Ok(())
    }

    /// 受信した Hint を処理する
    /// 重複していたら無視し、新規なら true を返す
    pub fn process_received_hint(&self, hint: &HintPacket) -> Result<bool> {
        let hash = self.calculate_hash(hint)?;

        let mut seen = self.seen_hints.lock().unwrap();
        if seen.contains(&hash) {
            return Ok(false); // 重複
        }

        seen.insert(hash);
        Ok(true) // 新規
    }

    fn mark_as_seen(&self, hint: &HintPacket) -> Result<()> {
        let hash = self.calculate_hash(hint)?;
        let mut seen = self.seen_hints.lock().unwrap();
        seen.insert(hash);
        Ok(())
    }

    fn calculate_hash(&self, hint: &HintPacket) -> Result<[u8; 32]> {
         let bytes = bincode::serialize(hint)
            .map_err(|e| AetherError::Config(e.to_string()))?;
         let mut hasher = Sha256::new();
         hasher.update(&bytes);
         Ok(hasher.finalize().into())
    }
}
