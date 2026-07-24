//! Proof of Work (設計書 18.11)
//!
//! **用途によってハッシュ関数を使い分ける。** これは最適化ではなく設計上の要請。
//!
//! 攻撃者のコア数 M、ハッシュ1回のコスト C、難易度 D とすると:
//!
//! ```text
//! 攻撃者の生成レート = M / (2^D × C)
//! 各ノードの検証負荷 = 生成レート × C = M / 2^D
//! 飽和条件: M ≥ 2^D
//! ```
//!
//! **C が約分で消える。** フラッド耐性は難易度 D だけで決まり、
//! ハッシュ関数の重さとは無関係である。したがって:
//!
//! | 用途 | 関数 | 理由 |
//! |---|---|---|
//! | [`hint`] | SHA-256 | 全ノードが全件検証するため検証コストを限界まで削る |
//! | [`node_id`] | Argon2id | 検証は新規ピア登録時のみ。ASIC 優位を潰す価値がそのまま効く |
//!
//! 実測 (`core/tests/pow_cost.rs`): SHA-256 0.241us / Argon2id(1MB) 276us (1146倍)。
//! Hint に Argon2 を使うと、耐性を1ビットも増やさずに
//! 正直な利用者のコストだけが1146倍になる。

use crate::error::{AetherError, Result};
use sha2::{Digest, Sha256};

/// ハッシュ先頭の連続ゼロビット数
pub fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for byte in hash {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// 難易度を満たすか
#[inline]
pub fn meets_difficulty(hash: &[u8; 32], difficulty: u32) -> bool {
    leading_zero_bits(hash) >= difficulty
}

/// Hint 用の軽量 PoW（SHA-256）
///
/// 全ノードが受信した全 Hint を検証するため、**検証コストが支配的**。
/// メモリハード関数を使ってはならない。
pub mod hint {
    use super::*;

    /// 探索を打ち切るまでの試行回数
    ///
    /// 難易度に対して十分大きく取るが、無限ループは避ける。
    const MAX_ATTEMPTS: u64 = 1 << 32;

    fn digest(payload: &[u8], nonce: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"aether_hint_pow_v1");
        hasher.update(payload);
        hasher.update(nonce.to_be_bytes());
        hasher.finalize().into()
    }

    /// 難易度を満たす nonce を探す
    pub fn solve(payload: &[u8], difficulty: u32) -> Result<u64> {
        if difficulty == 0 {
            return Ok(0);
        }

        for nonce in 0..MAX_ATTEMPTS {
            if meets_difficulty(&digest(payload, nonce), difficulty) {
                return Ok(nonce);
            }
        }
        Err(AetherError::Crypto("Hint PoW search exhausted".into()))
    }

    /// 検証する（1ハッシュ）
    pub fn verify(payload: &[u8], nonce: u64, difficulty: u32) -> bool {
        difficulty == 0 || meets_difficulty(&digest(payload, nonce), difficulty)
    }

    /// この nonce が実際に達成した先頭ゼロビット数
    ///
    /// ランク付け (2-7) に使う。要求難易度を満たしているかだけでなく、
    /// **どれだけ積んだか**を weight として扱う。偽れない（実ハッシュの結果）。
    pub fn achieved_bits(payload: &[u8], nonce: u64) -> u32 {
        super::leading_zero_bits(&digest(payload, nonce))
    }
}

/// NodeId 用のメモリハード PoW（Argon2id）
///
/// リング座標のグラインディング (設計書 18.5.3) を高くするのが目的。
/// Ed25519 鍵は毎秒数百万個生成できるため、これが無いと
/// 攻撃者は狙った `mailbox_key` の隣に着地する NodeId を選べてしまう。
///
/// 検証は新しいピアをリレーリストへ入れる時だけなので、
/// 1回 276us かかっても問題にならない。
pub mod node_id {
    use super::*;
    use argon2::{Algorithm, Argon2, Params, Version};

    /// メモリコスト (KiB)
    pub const M_COST_KIB: u32 = 1024;
    /// 時間コスト
    pub const T_COST: u32 = 1;
    /// 既定の難易度
    ///
    /// 参加障壁と Sybil コストのバランス。Argon2id(1MB) 276us なので
    /// 難易度 16 で約 18 秒（1回だけ払う）。
    pub const DEFAULT_DIFFICULTY: u32 = 16;

    const SALT: &[u8; 16] = b"aether_nodeid_v1";

    fn hasher() -> Result<Argon2<'static>> {
        let params = Params::new(M_COST_KIB, T_COST, 1, Some(32))
            .map_err(|e| AetherError::Crypto(format!("Invalid Argon2 params: {}", e)))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    fn digest(node_id: &[u8; 32], nonce: u64) -> Result<[u8; 32]> {
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(node_id);
        input.extend_from_slice(&nonce.to_be_bytes());

        let mut out = [0u8; 32];
        hasher()?
            .hash_password_into(&input, SALT, &mut out)
            .map_err(|e| AetherError::Crypto(format!("Argon2 failed: {}", e)))?;
        Ok(out)
    }

    /// 難易度を満たす nonce を探す（生成時に1回だけ）
    ///
    /// 難易度によっては数十秒〜数分かかる。呼び出し側でブロッキングを避けること。
    pub fn solve(node_id: &[u8; 32], difficulty: u32, max_attempts: u64) -> Result<u64> {
        if difficulty == 0 {
            return Ok(0);
        }

        for nonce in 0..max_attempts {
            if meets_difficulty(&digest(node_id, nonce)?, difficulty) {
                return Ok(nonce);
            }
        }
        Err(AetherError::Crypto("NodeId PoW search exhausted".into()))
    }

    /// 検証する（1ハッシュ）
    pub fn verify(node_id: &[u8; 32], nonce: u64, difficulty: u32) -> Result<bool> {
        if difficulty == 0 {
            return Ok(true);
        }
        Ok(meets_difficulty(&digest(node_id, nonce)?, difficulty))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_leading_zero_bits() {
        let mut h = [0u8; 32];
        assert_eq!(leading_zero_bits(&h), 256, "全ゼロ");

        h[0] = 0xFF;
        assert_eq!(leading_zero_bits(&h), 0);

        h[0] = 0x0F;
        assert_eq!(leading_zero_bits(&h), 4);

        h[0] = 0x00;
        h[1] = 0x80;
        assert_eq!(leading_zero_bits(&h), 8);

        h[1] = 0x01;
        assert_eq!(leading_zero_bits(&h), 15);
    }

    #[test]
    fn hint_pow_roundtrip() {
        let payload = b"a hint packet";
        let difficulty = 12;

        let nonce = hint::solve(payload, difficulty).unwrap();
        assert!(hint::verify(payload, nonce, difficulty));
    }

    #[test]
    fn hint_pow_rejects_wrong_nonce() {
        let payload = b"a hint packet";
        let difficulty = 12;
        let nonce = hint::solve(payload, difficulty).unwrap();

        assert!(
            !hint::verify(payload, nonce.wrapping_add(1), difficulty),
            "別の nonce が通ってはならない"
        );
    }

    #[test]
    fn hint_pow_is_bound_to_the_payload() {
        // 別のペイロードに使い回せると、1回の計算で無限にスパムできる
        let difficulty = 12;
        let nonce = hint::solve(b"original", difficulty).unwrap();

        assert!(!hint::verify(b"different", nonce, difficulty));
    }

    #[test]
    fn zero_difficulty_is_a_noop() {
        assert_eq!(hint::solve(b"x", 0).unwrap(), 0);
        assert!(hint::verify(b"x", 0, 0));
    }

    #[test]
    fn node_id_pow_roundtrip() {
        // 検証コストが高いので、テストでは低い難易度を使う
        let node_id = [0x42u8; 32];
        let difficulty = 6;

        let nonce = node_id::solve(&node_id, difficulty, 100_000).unwrap();
        assert!(node_id::verify(&node_id, nonce, difficulty).unwrap());
    }

    #[test]
    fn node_id_pow_is_bound_to_the_id() {
        // 使い回せると、1回の計算で任意個の NodeId を作れてしまう
        let difficulty = 6;
        let nonce = node_id::solve(&[0x42u8; 32], difficulty, 100_000).unwrap();

        assert!(
            !node_id::verify(&[0x43u8; 32], nonce, difficulty).unwrap(),
            "別の NodeId に使い回せてはならない"
        );
    }
}
