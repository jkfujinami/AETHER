use crate::error::{Result, AetherError};
use crate::net::relay::RelayClient;
use crate::net::seen_cache::SeenCache;
use crate::protocol::hint::HintPacket;
use crate::protocol::wire::InnerPacketType;
use std::sync::Mutex;

/// Gossip プロトコルのクライアント
/// Relay ネットワークを通じて Hint を送受信する
pub struct GossipClient {
    relay: RelayClient,
    seen_hints: Mutex<SeenCache>,
}

impl GossipClient {
    pub fn new(relay: RelayClient) -> Self {
        Self {
            relay,
            seen_hints: Mutex::new(SeenCache::default()),
        }
    }

    /// Hint をネットワーク全体にブロードキャストする
    ///
    /// **必ず Onion 回路を経由する。**
    /// 直接 Entry Relay へ送ると、Entry Relay に
    /// 「この IP がこの blind_tag を持つ Hint の発信源である」を平文で観測される。
    /// Mailbox PUT だけ Onion を通して Hint を素で流すと、送信の片肺が露出する。
    ///
    /// Hint の投入点は Onion の出口リレー自身になる。宛先指定は不要。
    pub async fn broadcast(&self, hint: &HintPacket) -> Result<()> {
        if !self.relay.has_circuit() {
            return Err(AetherError::Config(
                "Refusing to broadcast Hint without an Onion circuit (would leak origin IP)".into(),
            ));
        }

        let packet_bytes = bincode::serialize(hint)
            .map_err(|e| AetherError::Serialization(e.to_string()))?;

        // 出口リレーが GossipHint として Gossip ネットワークへ投入する
        self.relay
            .send_onion_inner(InnerPacketType::GossipHint, &packet_bytes)
            .await?;

        // 自分が送ったものは既知とする（回帰パケットを無視するため）
        self.mark_as_seen(hint);

        Ok(())
    }

    /// 受信した Hint を処理する
    /// 重複していたら false、新規なら true を返す
    pub fn process_received_hint(&self, hint: &HintPacket) -> Result<bool> {
        let mut seen = self.seen_hints.lock().unwrap();
        Ok(seen.insert(hint.id()))
    }

    fn mark_as_seen(&self, hint: &HintPacket) {
        let mut seen = self.seen_hints.lock().unwrap();
        seen.insert(hint.id());
    }

    /// 期限切れエントリを掃除する（定期タスクから呼ぶ）
    pub fn cleanup(&self) {
        self.seen_hints.lock().unwrap().cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> GossipClient {
        GossipClient::new(RelayClient::new().unwrap())
    }

    fn hint(tag: u8) -> HintPacket {
        HintPacket::new([tag; 4], [0u8; 12], vec![tag; 48], 5)
    }

    #[tokio::test]
    async fn broadcast_without_circuit_is_refused() {
        let c = client();

        let err = c.broadcast(&hint(1)).await.unwrap_err();
        assert!(
            matches!(err, AetherError::Config(_)),
            "回路が無いまま送ると発信元 IP が露出するため拒否しなければならない"
        );
    }

    // RelayClient::new() が QUIC エンドポイントを張るため、
    // 同期テストでも Tokio ランタイムが必要
    #[tokio::test]
    async fn duplicate_hints_are_rejected() {
        let c = client();
        let h = hint(2);

        assert!(c.process_received_hint(&h).unwrap(), "初回は新規");
        assert!(!c.process_received_hint(&h).unwrap(), "2回目は重複");
    }

    #[tokio::test]
    async fn ttl_change_does_not_defeat_dedup() {
        let c = client();
        let h = hint(3);
        let mut relayed = h.clone();
        relayed.decrement_ttl();

        assert!(c.process_received_hint(&h).unwrap());
        assert!(
            !c.process_received_hint(&relayed).unwrap(),
            "TTL が減った同一 Hint を新規と誤認すると Gossip が無限ループする"
        );
    }
}
