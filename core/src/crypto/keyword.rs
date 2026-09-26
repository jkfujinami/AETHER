//! 板の識別子から contacts マップ用の識別子を作る
//!
//! 板そのものは乱数 32 バイトの ID（[`aether_client::boards::BoardId`] 側）で決まり、
//! ここでの入力もその由来の鍵（`K_pub`）。板には特定の宛先ノードが無いので、
//! contacts マップに載せるための NodeId 代わりに、鍵から安定した識別子を作る。

use sha2::{Digest, Sha256};

/// 鍵に対応する、ローカル contacts マップ用の安定した識別子
///
/// 板には特定の宛先が無い。この鍵を contacts マップに収めるための
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
    fn same_key_yields_same_id() {
        let k_pub = [7u8; 32];
        assert_eq!(subscription_id(&k_pub), subscription_id(&k_pub));
    }

    #[test]
    fn different_keys_diverge() {
        assert_ne!(subscription_id(&[1u8; 32]), subscription_id(&[2u8; 32]));
    }
}
