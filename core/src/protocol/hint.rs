use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

/// Gossip で配信される Hint パケット
/// 誰宛てかは暗号化されており、受信者だけが blind_tag と復号試行で判断できる。
///
/// このパケットは全ノードにブロードキャストされるため、1バイトの増加が
/// ネットワーク全体でノード数倍のコストになる。フィールド追加は慎重に。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HintPacket {
    pub version: u8,
    pub ttl: u8,
    pub blind_tag: [u8; 4],   // HMAC(SharedSecret, Nonce)[0..4]
    pub nonce: [u8; 12],      // Encryption Nonce (ChaCha20)
    pub ciphertext: Vec<u8>,  // Encrypted Payload (末尾16バイトが Poly1305 タグ)
}

impl HintPacket {
    /// 新しいパケットを作成
    pub fn new(blind_tag: [u8; 4], nonce: [u8; 12], ciphertext: Vec<u8>, ttl: u8) -> Self {
        Self {
            version: 1,
            ttl,
            blind_tag,
            nonce,
            ciphertext,
        }
    }

    /// TTLを減らす（0になったら廃棄）
    pub fn decrement_ttl(&mut self) -> bool {
        if self.ttl > 0 {
            self.ttl -= 1;
            true
        } else {
            false
        }
    }

    /// 重複排除用の識別子
    ///
    /// **ttl を意図的に除外している。** ttl は中継のたびに変化するため、
    /// パケット全体をハッシュすると同一 Hint が別物として扱われ、
    /// 重複排除が機能せず Gossip が無限ループする。
    pub fn id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.version]);
        hasher.update(self.blind_tag);
        hasher.update(self.nonce);
        hasher.update(&self.ciphertext);
        hasher.finalize().into()
    }
}

/// Hint の中身（復号後）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintPayload {
    pub nonce: [u8; 32],      // Mailbox Key 生成用 Nonce (SHA256(Nonce) = Key)
    pub message_id: u64,      // メッセージID
    pub timestamp: u64,       // 送信時刻 (UNIX秒)
}

/// Hint として許容する時刻のズレ (±15分)
///
/// SeenCache の TTL と揃えることで
/// 「15分以内の再送は SeenCache が、それ以前は時刻検査が弾く」の二重防御になる。
pub const MAX_TIME_DRIFT_SECS: u64 = 15 * 60;

/// 現在時刻 (UNIX秒)
pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl HintPayload {
    /// タイムスタンプが許容範囲内か検証する（リプレイ対策）
    pub fn is_fresh(&self, now: u64) -> bool {
        let drift = now.abs_diff(self.timestamp);
        drift <= MAX_TIME_DRIFT_SECS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> HintPacket {
        HintPacket::new([1, 2, 3, 4], [9u8; 12], vec![0xAA; 64], 5)
    }

    #[test]
    fn id_is_independent_of_ttl() {
        let a = sample();
        let mut b = sample();
        b.decrement_ttl();
        b.decrement_ttl();

        assert_ne!(a.ttl, b.ttl);
        assert_eq!(a.id(), b.id(), "TTL の変化で ID が変わってはならない");
    }

    #[test]
    fn id_changes_with_content() {
        let a = sample();
        let mut b = sample();
        b.ciphertext[0] ^= 0xFF;
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn decrement_ttl_stops_at_zero() {
        let mut p = HintPacket::new([0; 4], [0; 12], vec![], 1);
        assert!(p.decrement_ttl());
        assert_eq!(p.ttl, 0);
        assert!(!p.decrement_ttl(), "TTL 0 では false を返して破棄させる");
    }

    #[test]
    fn freshness_window() {
        let now = 1_000_000u64;
        let payload = |ts| HintPayload { nonce: [0; 32], message_id: 0, timestamp: ts };

        assert!(payload(now).is_fresh(now));
        assert!(payload(now - MAX_TIME_DRIFT_SECS).is_fresh(now));
        assert!(payload(now + MAX_TIME_DRIFT_SECS).is_fresh(now));
        assert!(!payload(now - MAX_TIME_DRIFT_SECS - 1).is_fresh(now));
        assert!(!payload(now + MAX_TIME_DRIFT_SECS + 1).is_fresh(now));
    }
}
