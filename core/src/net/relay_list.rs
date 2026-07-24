//! ローカルに保持するリレーリスト (設計書 18.5.2)
//!
//! Kademlia を廃止した代わりに、各ノードがリレー全体のリストを持つ。
//! Tor の consensus と同じ構造で、**K最近接をローカル計算だけで決められる**。
//! ネットワークへ「誰が近い?」と問い合わせないので、
//! Part 10.1 の「検索の可視性」が原理的に発生しない。
//!
//! スケール上限は約100万リレー (66MB)。それ以上は階層化が必要 (18.12)。

use crate::crypto::identity::NodeId;
use crate::crypto::pow;
use crate::error::{AetherError, Result};
use crate::net::ring::{self, RingPosition};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

/// リレー1台の記述子
///
/// PEX で配布される。受け取った側は必ず [`RelayDirectory::insert`] で
/// NodeId PoW を検証すること。検証せずに入れると Sybil 対策が無意味になる。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDescriptor {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    /// Onion 層の鍵導出に使う X25519 公開鍵
    pub x25519_pub: [u8; 32],
    /// NodeId PoW の解
    pub pow_nonce: u64,
    /// 稼働実績（秒）。ガード選択の重み付けに使う
    pub uptime_secs: u64,
    /// 到達性の等級
    ///
    /// **ガード候補の絞り込みと Mailbox 配置に使う。**
    /// 到達不能なノードを Mailbox に選ぶとデータが届かない。
    pub tier: crate::net::reachability::Tier,
}

/// リレーリスト
pub struct RelayDirectory {
    relays: HashMap<NodeId, RelayDescriptor>,
    epoch_seed: [u8; 32],
    /// NodeId PoW に要求する難易度
    pow_difficulty: u32,
}

impl Default for RelayDirectory {
    fn default() -> Self {
        Self::new(ring::EPOCH_SEED_PLACEHOLDER, pow::node_id::DEFAULT_DIFFICULTY)
    }
}

impl RelayDirectory {
    pub fn new(epoch_seed: [u8; 32], pow_difficulty: u32) -> Self {
        Self {
            relays: HashMap::new(),
            epoch_seed,
            pow_difficulty,
        }
    }

    /// リレーを登録する
    ///
    /// **NodeId PoW を検証してから入れる。**
    /// 検証を省くと、攻撃者が Ed25519 鍵を大量生成して
    /// 狙った mailbox_key の隣に着地する NodeId を選べてしまう (18.5.3)。
    pub fn insert(&mut self, descriptor: RelayDescriptor) -> Result<()> {
        let valid = pow::node_id::verify(
            descriptor.node_id.as_bytes(),
            descriptor.pow_nonce,
            self.pow_difficulty,
        )?;

        if !valid {
            return Err(AetherError::Crypto(format!(
                "RelayDescriptor for {} has invalid NodeId PoW",
                descriptor.node_id
            )));
        }

        self.relays.insert(descriptor.node_id, descriptor);
        Ok(())
    }

    /// PoW 検証を省いて登録する（テスト・ブートストラップ専用）
    pub fn insert_unchecked(&mut self, descriptor: RelayDescriptor) {
        self.relays.insert(descriptor.node_id, descriptor);
    }

    pub fn remove(&mut self, node_id: &NodeId) -> Option<RelayDescriptor> {
        self.relays.remove(node_id)
    }

    pub fn get(&self, node_id: &NodeId) -> Option<&RelayDescriptor> {
        self.relays.get(node_id)
    }

    pub fn len(&self) -> usize {
        self.relays.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    pub fn all(&self) -> Vec<&RelayDescriptor> {
        self.relays.values().collect()
    }

    /// リレーのリング座標
    pub fn position_of(&self, descriptor: &RelayDescriptor) -> RingPosition {
        ring::position_of_node(&descriptor.node_id, &self.epoch_seed)
    }

    /// 指定座標に近い順に最大 k 台
    ///
    /// **問い合わせを一切行わない。** 送信側と受信側が独立に計算して
    /// 同じ集合に到達することが前提。
    pub fn k_nearest(&self, target: RingPosition, k: usize) -> Vec<RelayDescriptor> {
        let all: Vec<&RelayDescriptor> = self.relays.values().collect();
        ring::k_nearest(&all, target, k, |r| self.position_of(r))
            .into_iter()
            .map(|r| (*r).clone())
            .collect()
    }

    /// 指定座標に近い順に、**見知らぬ相手を受けられる**ノードを最大 k 台
    ///
    /// 到達不能なノードを Mailbox に選ぶと配送が落ちる。
    /// Tier はディレクトリで共有されているので、送信側と受信側が
    /// 同じ基準で絞り込めば集合はずれない。
    fn k_nearest_reachable(&self, target: RingPosition, k: usize) -> Vec<RelayDescriptor> {
        let all: Vec<&RelayDescriptor> = self
            .relays
            .values()
            .filter(|r| r.tier.accepts_strangers())
            .collect();

        ring::k_nearest(&all, target, k, |r| self.position_of(r))
            .into_iter()
            .map(|r| (*r).clone())
            .collect()
    }

    /// mailbox_key の担当リレーを決める
    pub fn mailbox_targets(
        &self,
        mailbox_key: &[u8; 32],
        key: &[u8; 32],
        k: usize,
    ) -> Vec<RelayDescriptor> {
        self.k_nearest_reachable(ring::position_of_mailbox(mailbox_key, key), k)
    }

    /// Hint backlog の担当ノードを決める (19.1.3)
    ///
    /// **全ノードから選ぶ**（到達性で絞らない）。担当割り当ては決定論的で、
    /// 自ノードが含まれるかの判定にも使うため。Reversed 相手も Connection
    /// Reversal で reconcile できるので保持者になれる。
    pub fn hint_holders(&self, hint_id: &[u8; 32], k: usize) -> Vec<RelayDescriptor> {
        self.k_nearest(ring::position_of_hint(hint_id, &self.epoch_seed), k)
    }

    /// 自ノードが `hint_id` の担当（K 最近接）かどうか
    pub fn is_hint_holder(&self, hint_id: &[u8; 32], me: &NodeId, k: usize) -> bool {
        self.hint_holders(hint_id, k)
            .iter()
            .any(|d| &d.node_id == me)
    }

    /// シャードの担当リレーを決める (18.5.4)
    pub fn shard_targets(
        &self,
        mailbox_key: &[u8; 32],
        key: &[u8; 32],
        shard_index: u8,
        k: usize,
    ) -> Vec<RelayDescriptor> {
        self.k_nearest_reachable(ring::position_of_shard(mailbox_key, key, shard_index), k)
    }

    /// ガード候補
    ///
    /// **Tier 0 だけを返す。** punch が要る相手をガードにすると、
    /// 仲介役にクライアントとガードの対応が漏れる。
    pub fn guard_candidates(&self) -> Vec<crate::net::guard::GuardCandidate> {
        self.relays
            .values()
            .filter(|r| r.tier.can_be_guard())
            .map(|r| crate::net::guard::GuardCandidate {
                node_id: r.node_id,
                addr: r.addr,
                uptime_secs: r.uptime_secs,
            })
            .collect()
    }

    /// Onion 回路用にランダムな `hops` 台を選ぶ
    ///
    /// 同一リレーを2回使わない。
    pub fn random_path(&self, hops: usize, exclude: &[NodeId]) -> Vec<RelayDescriptor> {
        use rand::seq::SliceRandom;

        let mut pool: Vec<&RelayDescriptor> = self
            .relays
            .values()
            .filter(|r| !exclude.contains(&r.node_id))
            .collect();

        pool.shuffle(&mut rand::thread_rng());
        pool.into_iter().take(hops).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(n: u8) -> RelayDescriptor {
        RelayDescriptor {
            node_id: NodeId([n; 32]),
            addr: format!("127.0.0.1:{}", 9000 + u16::from(n)).parse().unwrap(),
            x25519_pub: [n; 32],
            pow_nonce: 0,
            uptime_secs: u64::from(n) * 3600,
            tier: crate::net::reachability::Tier::Open,
        }
    }

    fn directory(count: u8) -> RelayDirectory {
        // PoW 難易度 0 = 検証を通す（テスト用）
        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 0);
        for n in 1..=count {
            dir.insert(descriptor(n)).unwrap();
        }
        dir
    }

    #[test]
    fn rejects_descriptors_without_valid_pow() {
        // ここを素通しすると Sybil で座標を狙い撃ちできる
        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 8);
        let err = dir.insert(descriptor(1)).unwrap_err();
        assert!(matches!(err, AetherError::Crypto(_)));
        assert!(dir.is_empty());
    }

    #[test]
    fn accepts_descriptors_with_valid_pow() {
        let difficulty = 6;
        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, difficulty);

        let mut d = descriptor(1);
        d.pow_nonce = pow::node_id::solve(d.node_id.as_bytes(), difficulty, 100_000).unwrap();

        dir.insert(d).unwrap();
        assert_eq!(dir.len(), 1);
    }

    #[test]
    fn sender_and_receiver_agree_on_targets() {
        // 送信側と受信側が独立に計算して同じ担当集合に到達する必要がある。
        // ここが崩れると、置いた場所と取りに行く場所がずれてメッセージが届かない。
        let dir_a = directory(30);
        let dir_b = directory(30);

        let mailbox_key = [0xABu8; 32];
        let key = [0xCDu8; 32];

        let targets_a = dir_a.mailbox_targets(&mailbox_key, &key, 5);
        let targets_b = dir_b.mailbox_targets(&mailbox_key, &key, 5);

        assert_eq!(targets_a.len(), 5);
        assert_eq!(targets_a, targets_b);
    }

    #[test]
    fn targets_depend_on_the_decryption_key() {
        // 鍵を知らなければ担当リレーを列挙できないこと (18.5.2)
        let dir = directory(30);
        let mailbox_key = [0xABu8; 32];

        let with_k1 = dir.mailbox_targets(&mailbox_key, &[1u8; 32], 3);
        let with_k2 = dir.mailbox_targets(&mailbox_key, &[2u8; 32], 3);

        assert_ne!(
            with_k1.iter().map(|r| r.node_id).collect::<Vec<_>>(),
            with_k2.iter().map(|r| r.node_id).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn shards_land_on_different_relays() {
        // 1つの弧を支配しても復元に足るシャードを集められないこと (18.5.4)
        let dir = directory(50);
        let mailbox_key = [0x11u8; 32];
        let key = [0x22u8; 32];

        let mut first_choice = Vec::new();
        for i in 0..5u8 {
            let t = dir.shard_targets(&mailbox_key, &key, i, 1);
            first_choice.push(t[0].node_id);
        }

        let unique: std::collections::HashSet<_> = first_choice.iter().collect();
        assert!(
            unique.len() >= 4,
            "5シャードが同じリレーに集中している: {:?}",
            first_choice
        );
    }

    #[test]
    fn k_nearest_is_capped_by_directory_size() {
        let dir = directory(3);
        assert_eq!(dir.mailbox_targets(&[0u8; 32], &[0u8; 32], 10).len(), 3);
    }

    #[test]
    fn random_path_has_no_duplicates() {
        let dir = directory(20);
        let path = dir.random_path(3, &[]);

        assert_eq!(path.len(), 3);
        let unique: std::collections::HashSet<_> = path.iter().map(|r| r.node_id).collect();
        assert_eq!(unique.len(), 3, "同一リレーを複数ホップに使ってはならない");
    }

    #[test]
    fn random_path_honours_exclusions() {
        let dir = directory(20);
        let excluded = NodeId([1u8; 32]);
        let path = dir.random_path(19, &[excluded]);

        assert!(!path.iter().any(|r| r.node_id == excluded));
    }

    #[test]
    fn guard_candidates_carry_uptime() {
        let dir = directory(5);
        let candidates = dir.guard_candidates();

        assert_eq!(candidates.len(), 5);
        assert!(candidates.iter().any(|c| c.uptime_secs > 0));
    }
}
