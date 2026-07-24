use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use crate::error::Result;

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
    /// Hint 生成コストを課す PoW nonce（フラッド対策 / 19.2.1）。
    ///
    /// **`id()` には含めない。** 含めると、攻撃者が同じ中身に対して別の有効な
    /// pow_nonce を見つけて「別の Hint」として再フラッドできてしまう（ttl と同じ理由）。
    pub pow_nonce: u64,
    pub ciphertext: Vec<u8>,  // Encrypted Payload (末尾16バイトが Poly1305 タグ)
}

impl HintPacket {
    /// 新しいパケットを作成（PoW 未解決。放流前に [`seal_pow`](Self::seal_pow) を呼ぶ）
    pub fn new(blind_tag: [u8; 4], nonce: [u8; 12], ciphertext: Vec<u8>, ttl: u8) -> Self {
        Self {
            version: 1,
            ttl,
            blind_tag,
            nonce,
            pow_nonce: 0,
            ciphertext,
        }
    }

    /// 放流前に PoW を解いて `pow_nonce` を確定する
    ///
    /// PoW は [`id`](Self::id)（＝ttl・pow_nonce を除いた中身）に束ねるので、
    /// 中継で ttl が変わっても検証は通り、別 Hint への使い回しはできない。
    pub fn seal_pow(&mut self, difficulty: u32) -> Result<()> {
        self.pow_nonce = crate::crypto::pow::hint::solve(&self.id(), difficulty)?;
        Ok(())
    }

    /// PoW が難易度を満たすか（難易度 0 なら常に true）
    pub fn verify_pow(&self, difficulty: u32) -> bool {
        crate::crypto::pow::hint::verify(&self.id(), self.pow_nonce, difficulty)
    }

    /// ワイヤ形式へ
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| crate::error::AetherError::Serialization(e.to_string()))
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
    /// **ttl と pow_nonce を意図的に除外している。** どちらも中身とは独立に
    /// 変えられる値で、ハッシュに含めると同一 Hint を別物として再フラッドできる
    /// （ttl は中継で変化、pow_nonce は別解で差し替え可能）。
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
        self.is_fresh_within(now, MAX_TIME_DRIFT_SECS)
    }

    /// 指定した窓で鮮度を見る
    ///
    /// **受信者の取得判断**では backlog(24h)を許す ── オフライン明けに
    /// 拾った古い Hint も、本体がまだ生きていれば取りに行けるべきだから
    /// (19.1.3)。拡散側のリプレイ対策 (`is_fresh`) とは窓が別。
    pub fn is_fresh_within(&self, now: u64, window: u64) -> bool {
        now.abs_diff(self.timestamp) <= window
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
    fn pow_seals_and_verifies() {
        let mut p = sample();
        assert!(p.verify_pow(0), "難易度0は常に通る");

        p.seal_pow(12).unwrap();
        assert!(p.verify_pow(12), "解いた PoW は通る");

        // pow_nonce を改竄すると落ちる
        let mut tampered = p.clone();
        tampered.pow_nonce = tampered.pow_nonce.wrapping_add(1);
        assert!(!tampered.verify_pow(12), "改竄した pow_nonce は通ってはならない");

        // 中身を変えると PoW が無効になる（別 Hint への使い回し不可）
        let mut reused = p.clone();
        reused.ciphertext[0] ^= 0xFF;
        assert!(!reused.verify_pow(12), "別ペイロードに PoW を使い回せてはならない");
    }

    #[test]
    fn pow_nonce_is_excluded_from_id() {
        // pow_nonce の差し替えで id が変わると、別解で再フラッドできてしまう
        let mut a = sample();
        a.seal_pow(8).unwrap();

        let mut b = a.clone();
        b.pow_nonce = b.pow_nonce.wrapping_add(999);

        assert_eq!(a.id(), b.id(), "pow_nonce は id に影響してはならない");
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
