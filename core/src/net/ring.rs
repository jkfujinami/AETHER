//! リング座標と K最近接の計算 (設計書 18.5)
//!
//! Kademlia の反復 FIND_VALUE は使わない。それをやると Part 10.1 の
//! 「検索の可視性 = 誰が誰を探しているか分かる」が再発する。
//!
//! 代わりに、
//! - リレーの座標は NodeId から決定論的に導出する（広告不要）
//! - 各ノードはリレーリストをローカル保持する（Tor の consensus と同型）
//! - K最近接は**ローカル計算のみ**。ネットワークへ問い合わせない
//!
//! # 位置導出に鍵を混ぜる理由
//!
//! `position = H(mailbox_key)` だと誰でも計算できてしまい、
//! Gossip を観測するノードが任意コンテンツの保持者を完全に列挙できる。
//!
//! `position = H(mailbox_key ‖ K)` （K = Hint の復号鍵）とすることで、
//! **私信モードの保持者位置は原理的に計算不能**になる。追加コストはゼロ。
//! 公開モードは K が辞書攻撃可能なので位置も割れるが、
//! これは公開検索可能性と交換不能なトレードオフ (18.4.3)。

use crate::crypto::identity::NodeId;
use sha2::{Digest, Sha256};

/// リング上の位置 `[0.0, 1.0)`
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct RingPosition(f64);

impl RingPosition {
    /// ハッシュの先頭8バイトを `[0,1)` へ写す
    fn from_hash(hash: &[u8; 32]) -> Self {
        let raw = u64::from_be_bytes(hash[0..8].try_into().expect("32バイトから8バイト"));
        // 2^64 で割るので 1.0 には到達しない
        Self(raw as f64 / (2f64.powi(64)))
    }

    pub fn value(&self) -> f64 {
        self.0
    }

    /// リング上の最短距離 `[0, 0.5]`
    pub fn distance(a: Self, b: Self) -> f64 {
        let d = (a.0 - b.0).abs();
        d.min(1.0 - d)
    }
}

/// エポックビーコン（設計書 18.5.3）
///
/// 位置グラインディング対策として、いずれ日次で更新される乱数を混ぜる。
/// 合意層を必要とするため Phase 3 へ延期しているが、
/// **NodeId の形式だけは今のうちに確定させておく**
/// （後から変えるとネットワーク全体の互換性が切れるため）。
///
/// 当面は固定値。有効化する際はここを外部ビーコン (drand / Bitcoin) 由来にする。
pub const EPOCH_SEED_PLACEHOLDER: [u8; 32] = [0u8; 32];

/// リレーのリング座標を NodeId から導出する
///
/// 広告不要・検証可能。`epoch_seed` を混ぜてあるので、
/// エポック方式を有効化しても NodeId の形式は変わらない。
pub fn position_of_node(node_id: &NodeId, epoch_seed: &[u8; 32]) -> RingPosition {
    let mut hasher = Sha256::new();
    hasher.update(b"aether_ring_node_v1");
    hasher.update(node_id.as_bytes());
    hasher.update(epoch_seed);
    RingPosition::from_hash(&hasher.finalize().into())
}

/// Mailbox の配置座標
///
/// `key` は Hint の復号鍵。これを混ぜないと保持者が誰にでも列挙される。
pub fn position_of_mailbox(mailbox_key: &[u8; 32], key: &[u8; 32]) -> RingPosition {
    let mut hasher = Sha256::new();
    hasher.update(b"aether_ring_mailbox_v1");
    hasher.update(mailbox_key);
    hasher.update(key);
    RingPosition::from_hash(&hasher.finalize().into())
}

/// Reed-Solomon シャードの配置座標 (設計書 18.5.4)
///
/// シャードごとに独立した座標を与え、リング全体に散らす。
/// 攻撃者が1つの弧を支配しても取れるシャードは1個で復元できず、
/// 検閲するには離れた位置の3個を同時に押さえる必要がある。
pub fn position_of_shard(mailbox_key: &[u8; 32], key: &[u8; 32], shard_index: u8) -> RingPosition {
    let mut hasher = Sha256::new();
    hasher.update(b"aether_ring_shard_v1");
    hasher.update(mailbox_key);
    hasher.update(key);
    hasher.update([shard_index]);
    RingPosition::from_hash(&hasher.finalize().into())
}

/// `target` に近い順に最大 `k` 個を返す
///
/// **ネットワークへの問い合わせを一切行わない。**
/// 呼び出し側がローカルのリレーリストを渡すこと。
pub fn k_nearest<T, F>(items: &[T], target: RingPosition, k: usize, position_of: F) -> Vec<&T>
where
    F: Fn(&T) -> RingPosition,
{
    let mut scored: Vec<(f64, &T)> = items
        .iter()
        .map(|item| (RingPosition::distance(target, position_of(item)), item))
        .collect();

    // 距離が同値の場合も決定論的な順序になるよう、位置で二次ソートする
    scored.sort_by(|a, b| {
        a.0.partial_cmp(&b.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                position_of(a.1)
                    .value()
                    .partial_cmp(&position_of(b.1).value())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    scored.into_iter().take(k).map(|(_, item)| item).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    #[test]
    fn positions_stay_in_range() {
        for n in 0..=255u8 {
            let p = position_of_node(&node(n), &EPOCH_SEED_PLACEHOLDER);
            assert!((0.0..1.0).contains(&p.value()), "位置が範囲外: {}", p.value());
        }
    }

    #[test]
    fn node_position_is_deterministic() {
        let a = position_of_node(&node(7), &EPOCH_SEED_PLACEHOLDER);
        let b = position_of_node(&node(7), &EPOCH_SEED_PLACEHOLDER);
        assert_eq!(a.value(), b.value(), "同じ NodeId なら同じ座標でなければならない");
    }

    #[test]
    fn epoch_seed_moves_positions() {
        // エポック方式を有効化したとき、グラインドした座標が持ち越されないこと
        let a = position_of_node(&node(7), &[0u8; 32]);
        let b = position_of_node(&node(7), &[1u8; 32]);
        assert_ne!(a.value(), b.value());
    }

    #[test]
    fn distance_wraps_around_the_ring() {
        let a = RingPosition(0.99);
        let b = RingPosition(0.01);
        let d = RingPosition::distance(a, b);
        assert!((d - 0.02).abs() < 1e-9, "リングを跨いだ距離が最短にならない: {}", d);
    }

    #[test]
    fn distance_never_exceeds_half() {
        let a = RingPosition(0.0);
        let b = RingPosition(0.5);
        assert!((RingPosition::distance(a, b) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn mailbox_position_depends_on_the_key() {
        // ここが崩れると、観測ノードが任意コンテンツの保持者を列挙できる
        let mailbox_key = [0xAAu8; 32];
        let with_k1 = position_of_mailbox(&mailbox_key, &[1u8; 32]);
        let with_k2 = position_of_mailbox(&mailbox_key, &[2u8; 32]);

        assert_ne!(
            with_k1.value(),
            with_k2.value(),
            "復号鍵を知らなければ Mailbox 位置を計算できないこと"
        );
    }

    #[test]
    fn shards_spread_across_the_ring() {
        // 1つの弧を支配しても複数シャードを取れないこと
        let mailbox_key = [0xBBu8; 32];
        let key = [0xCCu8; 32];

        let positions: Vec<f64> = (0..5)
            .map(|i| position_of_shard(&mailbox_key, &key, i).value())
            .collect();

        // 全て相異なり、かつ極端に固まっていない
        for i in 0..positions.len() {
            for j in (i + 1)..positions.len() {
                let d = RingPosition::distance(RingPosition(positions[i]), RingPosition(positions[j]));
                assert!(d > 0.001, "シャード {} と {} が近すぎる: {}", i, j, d);
            }
        }
    }

    #[test]
    fn k_nearest_picks_the_closest() {
        let items: Vec<f64> = vec![0.10, 0.20, 0.30, 0.90, 0.95];
        let target = RingPosition(0.92);

        let picked = k_nearest(&items, target, 2, |p| RingPosition(*p));

        assert_eq!(picked.len(), 2);
        assert!(picked.contains(&&0.90));
        assert!(picked.contains(&&0.95));
    }

    #[test]
    fn k_nearest_wraps_around() {
        let items: Vec<f64> = vec![0.02, 0.50, 0.98];
        let target = RingPosition(0.0);

        let picked = k_nearest(&items, target, 2, |p| RingPosition(*p));

        assert!(picked.contains(&&0.02));
        assert!(picked.contains(&&0.98), "リングを跨いだ近傍が選ばれていない");
        assert!(!picked.contains(&&0.50));
    }

    #[test]
    fn k_nearest_handles_fewer_items_than_k() {
        let items: Vec<f64> = vec![0.1];
        let picked = k_nearest(&items, RingPosition(0.5), 5, |p| RingPosition(*p));
        assert_eq!(picked.len(), 1);
    }

    #[test]
    fn k_nearest_is_deterministic() {
        // 送信側と受信側が独立に計算して同じ集合に到達する必要がある
        let items: Vec<f64> = (0..50).map(|n| f64::from(n) / 50.0).collect();
        let target = RingPosition(0.33);

        let a = k_nearest(&items, target, 5, |p| RingPosition(*p));
        let b = k_nearest(&items, target, 5, |p| RingPosition(*p));
        assert_eq!(a, b);
    }
}
