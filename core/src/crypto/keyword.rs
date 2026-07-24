//! 公開モードの鍵導出 (19.3.1 / 19.7)
//!
//! **キーワードを知る者全員が同じ `K_pub` に到達する。** これが公開共有の入口。
//! 導出した鍵は私信の共有秘密とまったく同じように使える
//! （blind_tag = HMAC(K_pub, nonce)、位置 = H(mailbox_key ‖ K_pub) …）ので、
//! Mailbox 側は無改造で公開モードに対応できる。
//!
//! # なぜ Argon2id か
//!
//! キーワードの**総当たり列挙**を高価にするため。公開前提なので防御は弱いが、
//! 「どんなキーワードが使われているか」を安価に舐められるのは避けたい。
//! 全員が使うたびに1回計算するので、パラメータは中庸に取る。
//!
//! # 決定論
//!
//! ソルトは固定。全ノードが同じキーワードから同じ鍵へ**独立に**到達する必要がある。
//! キーワードは前後空白のみ正規化する（大文字小文字は区別する ── Unicode 変換は
//! ロケール依存で収束が壊れるため、利用者が正確な語を共有する前提）。

use crate::error::{AetherError, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};

/// メモリコスト (KiB) = 32 MiB
const M_COST_KIB: u32 = 32 * 1024;
/// 時間コスト
const T_COST: u32 = 2;
/// 固定ソルト（決定論のため全員共通）
const SALT: &[u8; 16] = b"aether_kw_pub_v1";

/// キーワードから公開共有鍵 `K_pub` を導出する
pub fn derive_public_key(keyword: &str) -> Result<[u8; 32]> {
    let normalized = keyword.trim();
    if normalized.is_empty() {
        return Err(AetherError::Config("Keyword is empty".into()));
    }

    let params = Params::new(M_COST_KIB, T_COST, 1, Some(32))
        .map_err(|e| AetherError::Crypto(format!("Invalid Argon2 params: {}", e)))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    argon
        .hash_password_into(normalized.as_bytes(), SALT, &mut out)
        .map_err(|e| AetherError::Crypto(format!("Argon2 failed: {}", e)))?;
    Ok(out)
}

/// 公開鍵に対応する、ローカル contacts マップ用の安定した識別子
///
/// 公開モードには特定の宛先が無い。K_pub を contacts マップに収めるための
/// NodeId 代わりに、鍵のハッシュを使う（送受信で一致する必要はない）。
pub fn subscription_id(k_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"aether_kw_target_v1");
    h.update(k_pub);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_keyword_yields_same_key() {
        // 決定論：別々のノードが同じキーワードから同じ鍵に到達できること
        let a = derive_public_key("winny-successor").unwrap();
        let b = derive_public_key("winny-successor").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn whitespace_is_normalized() {
        assert_eq!(
            derive_public_key("  hello ").unwrap(),
            derive_public_key("hello").unwrap()
        );
    }

    #[test]
    fn different_keywords_diverge() {
        assert_ne!(
            derive_public_key("cats").unwrap(),
            derive_public_key("dogs").unwrap()
        );
    }

    #[test]
    fn case_is_significant() {
        assert_ne!(
            derive_public_key("Foo").unwrap(),
            derive_public_key("foo").unwrap()
        );
    }

    #[test]
    fn empty_keyword_is_rejected() {
        assert!(derive_public_key("   ").is_err());
    }
}
