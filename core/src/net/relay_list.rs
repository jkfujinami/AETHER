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
    /// 稼働実績（秒）の自己申告
    ///
    /// **選択には使わない。** 誰でも好きな値を書けるので、これで重み付けすると
    /// 大きく申告した Sybil がガード枠を独占する。ガードの重みは
    /// [`RelayDirectory`] が自分で観測した在籍時間から作る。
    pub uptime_secs: u64,
    /// 到達性の等級
    ///
    /// **ガード候補の絞り込みと Mailbox 配置に使う。**
    /// 到達不能なノードを Mailbox に選ぶとデータが届かない。
    pub tier: crate::net::reachability::Tier,
    /// 署名した時刻 (UNIX秒)。同じ NodeId の記述子は新しい方だけを採る
    pub issued_at: u64,
    /// 上の全フィールドへの Ed25519 署名（NodeId の鍵で）
    ///
    /// PoW は NodeId にしか掛かっていない。署名が無いと、他人の NodeId と
    /// pow_nonce を写して自分のアドレスを書いた記述子で**そのノードに成り代われる**
    /// （Onion 層も Mailbox の担当位置も奪われる）。
    pub signature: Vec<u8>,
}

/// 記述子の署名に混ぜるドメイン分離タグ
const DESCRIPTOR_SIG_DOMAIN: &[u8] = b"aether_relay_descriptor_v1";

/// これより未来の `issued_at` は受け取らない（時計のずれの許容幅）
///
/// 遠い未来の記述子を一度入れると、以後の正しい更新が全て「古い」として弾かれる。
pub const MAX_DESCRIPTOR_CLOCK_SKEW_SECS: u64 = 600;

impl RelayDescriptor {
    /// 自分の記述子を組み立てて署名する
    ///
    /// `x25519_pub` は identity から導出する（NodeId と一致しない鍵は受け手が弾く）。
    pub fn new_signed(
        identity: &crate::crypto::identity::Identity,
        addr: SocketAddr,
        pow_nonce: u64,
        tier: crate::net::reachability::Tier,
    ) -> Self {
        let mut d = Self {
            node_id: identity.public_id(),
            addr,
            x25519_pub: x25519_dalek::PublicKey::from(&identity.x25519_secret()).to_bytes(),
            pow_nonce,
            uptime_secs: 0,
            tier,
            issued_at: 0,
            signature: Vec::new(),
        };
        d.resign(identity);
        d
    }

    /// 内容を変えたあとに署名し直す
    ///
    /// `issued_at` は単調に進める。同じ秒に2回更新すると、2回目が「同じ古さ」として
    /// 他ノードに無視されるため。
    pub fn resign(&mut self, identity: &crate::crypto::identity::Identity) {
        debug_assert_eq!(self.node_id, identity.public_id());
        let now = crate::protocol::hint::current_timestamp();
        self.issued_at = now.max(self.issued_at + 1);
        self.signature = identity.sign(&self.signing_bytes());
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let body = (
            &self.node_id,
            &self.addr,
            &self.x25519_pub,
            self.pow_nonce,
            self.uptime_secs,
            &self.tier,
            self.issued_at,
        );
        let mut buf = DESCRIPTOR_SIG_DOMAIN.to_vec();
        buf.extend_from_slice(&bincode::serialize(&body).expect("固定形のタプルは直列化できる"));
        buf
    }

    /// 記述子が NodeId の持ち主によって書かれたものか確かめる
    ///
    /// - 署名が NodeId の鍵で通ること
    /// - `x25519_pub` が NodeId から導出した鍵と一致すること（Onion 層を包む鍵のすり替え防止）
    pub fn verify_authenticity(&self) -> Result<()> {
        let expected = crate::crypto::identity::x25519_public_from_node_id(&self.node_id)?;
        if expected != self.x25519_pub {
            return Err(AetherError::Crypto(format!(
                "RelayDescriptor for {} carries an X25519 key not derived from its NodeId",
                self.node_id
            )));
        }
        crate::crypto::identity::verify_signature(&self.node_id, &self.signing_bytes(), &self.signature)
    }
}

/// 回路の多様性を測るネットワークの単位（IPv4 /16・IPv6 /32）
///
/// ループバック・プライベート・リンクローカルは対象外（`None`）。手元のテスト網は
/// 全員が 127.0.0.1 や同じ LAN にいるので、制限すると回路が組めなくなる。
fn subnet_key(addr: &SocketAddr) -> Option<Vec<u8>> {
    let ip = crate::net::addr::normalize(*addr).ip();
    match ip {
        std::net::IpAddr::V4(v4) => {
            (!(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()))
                .then(|| v4.octets()[..2].to_vec())
        }
        std::net::IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            let local = v6.is_loopback()
                || v6.is_unspecified()
                || (seg0 & 0xfe00) == 0xfc00 // ULA
                || (seg0 & 0xffc0) == 0xfe80; // リンクローカル
            (!local).then(|| v6.octets()[..4].to_vec())
        }
    }
}

/// 2 つのアドレスが同じネットワークにあるか（テスト網のアドレスは常に「別」）
pub fn same_subnet(a: &SocketAddr, b: &SocketAddr) -> bool {
    match (subnet_key(a), subnet_key(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// リレーリスト
pub struct RelayDirectory {
    relays: HashMap<NodeId, RelayDescriptor>,
    /// 各リレーを最初に見た時刻 (UNIX秒)。**自分で観測した値なので偽れない**
    ///
    /// ガードの重み付けに使う。自己申告の `uptime_secs` は使わない。
    first_seen: HashMap<NodeId, u64>,
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
            first_seen: HashMap::new(),
            epoch_seed,
            pow_difficulty,
        }
    }

    /// リレーを登録する
    ///
    /// **NodeId PoW を検証してから入れる。**
    /// 検証を省くと、攻撃者が Ed25519 鍵を大量生成して
    /// 狙った mailbox_key の隣に着地する NodeId を選べてしまう (18.5.3)。
    /// **署名も検証する**（NodeId の鍵で署名され、X25519 鍵が NodeId 由来であること）。
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

        descriptor.verify_authenticity()?;

        let now = crate::protocol::hint::current_timestamp();
        if descriptor.issued_at > now + MAX_DESCRIPTOR_CLOCK_SKEW_SECS {
            return Err(AetherError::Protocol(format!(
                "RelayDescriptor for {} is dated in the future",
                descriptor.node_id
            )));
        }

        // **古い記述子で新しいものを上書きさせない。** 署名済みでも、過去に配った
        // 記述子（旧アドレス・旧 Tier）を攻撃者が再送すれば巻き戻せてしまう。
        if let Some(existing) = self.relays.get(&descriptor.node_id)
            && existing.issued_at >= descriptor.issued_at
        {
            return Ok(());
        }

        self.store(descriptor);
        Ok(())
    }

    /// 検証を省いて登録する（自ノードの記述子・テスト専用）
    ///
    /// **網から受け取った記述子には使わないこと。**
    pub fn insert_unchecked(&mut self, descriptor: RelayDescriptor) {
        self.store(descriptor);
    }

    fn store(&mut self, descriptor: RelayDescriptor) {
        self.first_seen
            .entry(descriptor.node_id)
            .or_insert_with(crate::protocol::hint::current_timestamp);
        self.relays.insert(descriptor.node_id, descriptor);
    }

    pub fn remove(&mut self, node_id: &NodeId) -> Option<RelayDescriptor> {
        self.first_seen.remove(node_id);
        self.relays.remove(node_id)
    }

    /// 自分が観測した在籍時間（秒）
    pub fn observed_age(&self, node_id: &NodeId) -> u64 {
        let now = crate::protocol::hint::current_timestamp();
        self.first_seen
            .get(node_id)
            .map(|t| now.saturating_sub(*t))
            .unwrap_or(0)
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

    /// 現在のエポックシード
    pub fn epoch_seed(&self) -> [u8; 32] {
        self.epoch_seed
    }

    /// エポックシードを差し替える（エポックビーコンが日次で回転する / 3-4）
    ///
    /// ノードのリング座標 [`position_of`](Self::position_of) と Hint 保持位置に混ざる。
    /// **全ノードが同じシードに到達している必要がある**（食い違うと保持者計算がずれる）。
    /// 送信側・受信側は drand の同一ラウンドから独立に同じ値を導出する。
    /// 回転で保持者集合が変わったコンテンツは、既存の republish ループ（保持者による
    /// 定期再配置）が現在の K 最近接へ移すので、境界後しばらくで追従する。
    pub fn set_epoch_seed(&mut self, seed: [u8; 32]) {
        self.epoch_seed = seed;
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
    ///
    /// 稼働実績は**自分が観測した在籍時間**を渡す（自己申告の `uptime_secs` は偽れる）。
    pub fn guard_candidates(&self) -> Vec<crate::net::guard::GuardCandidate> {
        self.relays
            .values()
            .filter(|r| r.tier.can_be_guard())
            .map(|r| crate::net::guard::GuardCandidate {
                node_id: r.node_id,
                addr: r.addr,
                x25519_pub: r.x25519_pub,
                uptime_secs: self.observed_age(&r.node_id),
            })
            .collect()
    }

    /// ガードの後ろに続く中間・出口リレーを選ぶ（3ホップ回路 = ガード → 中間 → 出口）
    ///
    /// - **中間を挟むのが要点。** 1ホップだと入口が出口を兼ね、
    ///   「発信者の IP」と「復号した中身」が同じ1台に揃う。
    /// - 中間・出口は**見知らぬ相手を受けられる**ノードに限る。到達不能ノードを
    ///   挟むと黙って落ちるが、出口の生死を発信者が直接確かめると
    ///   出口に発信者の IP を晒すので、事前に絞るしかない。
    /// - `exclude` は一切使わない相手（自分など）、`avoid_exit` は出口にだけ
    ///   使わない相手（回路分離で他の回路が使った出口）。
    /// - **ホップどうしを同じネットワーク（IPv4 /16・IPv6 /32）から選ばない。**
    ///   `avoid_subnets_of`（ガードなど）とも重ねない。1 つの事業者で安く大量に立てた
    ///   偽リレーが 1 本の回路の複数ホップを占めにくくする（Tor と同じ規則）。
    ///
    /// 候補が足りなければ `None`。**短い回路へ黙って落とさない**（fail closed）。
    pub fn circuit_hops(
        &self,
        guard: &NodeId,
        avoid_subnets_of: &[SocketAddr],
        exclude: &[NodeId],
        avoid_exit: &[NodeId],
    ) -> Option<(RelayDescriptor, RelayDescriptor)> {
        use rand::seq::SliceRandom;

        let mut pool: Vec<&RelayDescriptor> = self
            .relays
            .values()
            .filter(|r| {
                r.node_id != *guard
                    && !exclude.contains(&r.node_id)
                    && r.tier.accepts_strangers()
                    && !avoid_subnets_of.iter().any(|a| same_subnet(a, &r.addr))
            })
            .collect();
        pool.shuffle(&mut rand::thread_rng());

        let exit_idx = pool.iter().position(|r| !avoid_exit.contains(&r.node_id))?;
        let exit = pool.remove(exit_idx).clone();
        // 中間は出口と別のネットワークから
        let middle = pool.into_iter().find(|r| !same_subnet(&r.addr, &exit.addr))?;
        Some((middle.clone(), exit))
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
            issued_at: 0,
            signature: Vec::new(),
        }
    }

    /// 選択ロジックを試すためのディレクトリ（検証は下の専用テストで見る）
    fn directory(count: u8) -> RelayDirectory {
        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 0);
        for n in 1..=count {
            dir.insert_unchecked(descriptor(n));
        }
        dir
    }

    fn signed(identity: &crate::crypto::identity::Identity, port: u16) -> RelayDescriptor {
        RelayDescriptor::new_signed(
            identity,
            format!("10.0.0.1:{}", port).parse().unwrap(),
            0,
            crate::net::reachability::Tier::Open,
        )
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

        let id = crate::crypto::identity::Identity::generate();
        let nonce = pow::node_id::solve(id.public_id().as_bytes(), difficulty, 100_000).unwrap();
        let d = RelayDescriptor::new_signed(
            &id,
            "10.0.0.1:9000".parse().unwrap(),
            nonce,
            crate::net::reachability::Tier::Open,
        );

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
    fn circuit_hops_are_distinct_from_guard_and_each_other() {
        let dir = directory(10);
        let guard = NodeId([1u8; 32]);
        let me = NodeId([2u8; 32]);
        for _ in 0..50 {
            let (middle, exit) = dir.circuit_hops(&guard, &[], &[me], &[]).unwrap();
            assert_ne!(middle.node_id, exit.node_id);
            for hop in [&middle, &exit] {
                assert_ne!(hop.node_id, guard, "ガードを中間・出口に再利用しない");
                assert_ne!(hop.node_id, me);
            }
        }
    }

    #[test]
    fn circuit_hops_honour_avoid_exit() {
        // 回路分離：他の回路の出口は出口に選ばない（中間には使ってよい）
        let dir = directory(4);
        let guard = NodeId([1u8; 32]);
        let other_exit = NodeId([3u8; 32]);
        for _ in 0..50 {
            let (_, exit) = dir.circuit_hops(&guard, &[], &[], &[other_exit]).unwrap();
            assert_ne!(exit.node_id, other_exit);
        }
    }

    #[test]
    fn circuit_hops_fail_closed_when_too_few_relays() {
        // ガード以外に1台しか無ければ 3 ホップは組めない。短い回路に落とさない
        let dir = directory(2);
        assert!(dir.circuit_hops(&NodeId([1u8; 32]), &[], &[], &[]).is_none());
    }

    #[test]
    fn circuit_hops_skip_unreachable_relays() {
        let mut dir = directory(3);
        let mut hidden = descriptor(9);
        hidden.tier = crate::net::reachability::Tier::Reversed;
        dir.insert_unchecked(hidden);
        for _ in 0..50 {
            let (middle, exit) = dir.circuit_hops(&NodeId([1u8; 32]), &[], &[], &[]).unwrap();
            assert_ne!(middle.node_id, NodeId([9u8; 32]));
            assert_ne!(exit.node_id, NodeId([9u8; 32]));
        }
    }

    #[test]
    fn circuit_hops_come_from_different_networks() {
        // 同じ /16 に大量の偽リレーを並べても、1 本の回路の複数ホップは取れない
        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 0);
        for n in 1..=20u8 {
            let mut d = descriptor(n);
            d.addr = format!("198.51.{}.{}:9000", n % 2, n).parse().unwrap(); // 198.51/16 だけ
            dir.insert_unchecked(d);
        }
        let mut other = descriptor(100);
        other.addr = "203.0.113.9:9000".parse().unwrap();
        dir.insert_unchecked(other.clone());

        let guard_addr: SocketAddr = "192.0.2.1:9000".parse().unwrap();
        for _ in 0..30 {
            let (middle, exit) = dir.circuit_hops(&NodeId([0xEE; 32]), &[guard_addr], &[], &[]).unwrap();
            assert!(!same_subnet(&middle.addr, &exit.addr));
            assert!(middle.node_id == other.node_id || exit.node_id == other.node_id);
        }
        // ガードと同じネットワークのリレーも避ける
        let (m, e) = dir.circuit_hops(&NodeId([0xEE; 32]), &["203.0.113.200:1".parse().unwrap()], &[], &[]).map_or((None, None), |(m, e)| (Some(m), Some(e)));
        assert!(m.is_none() && e.is_none(), "ガードと同じ /16 のリレーを使った");
    }

    #[test]
    fn local_networks_are_not_restricted() {
        // テスト網（127.0.0.1・プライベート）は同じネットワークとみなさない
        let a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:2".parse().unwrap();
        assert!(!same_subnet(&a, &b));
        assert!(!same_subnet(&"10.0.0.1:1".parse().unwrap(), &"10.0.0.2:1".parse().unwrap()));
        assert!(same_subnet(&"8.8.4.4:1".parse().unwrap(), &"8.8.8.8:1".parse().unwrap()));
        assert!(same_subnet(&"[2001:db8::1]:1".parse().unwrap(), &"[2001:db8:0:1::9]:1".parse().unwrap()));
    }

    #[test]
    fn guard_candidates_ignore_self_reported_uptime() {
        // 自己申告を信じると、大きな値を書いた Sybil がガード枠を独占する
        let mut dir = directory(5);
        let mut liar = descriptor(6);
        liar.uptime_secs = u64::MAX;
        dir.insert_unchecked(liar);
        // 古参 1 台だけは、ずっと前から見えていたことにする
        dir.first_seen.insert(NodeId([1u8; 32]), 0);

        let candidates = dir.guard_candidates();
        assert_eq!(candidates.len(), 6);
        let liar_c = candidates.iter().find(|c| c.node_id == NodeId([6u8; 32])).unwrap();
        let old_c = candidates.iter().find(|c| c.node_id == NodeId([1u8; 32])).unwrap();
        assert!(liar_c.uptime_secs < 60, "自己申告が重みに漏れている");
        assert!(old_c.uptime_secs > liar_c.uptime_secs);
    }

    #[test]
    fn accepts_a_properly_signed_descriptor() {
        let id = crate::crypto::identity::Identity::generate();
        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 0);
        dir.insert(signed(&id, 9000)).unwrap();
        assert!(dir.get(&id.public_id()).is_some());
    }

    #[test]
    fn rejects_a_hijacked_address() {
        // 他人の NodeId・PoW を写し、アドレスだけ自分に書き換えた記述子
        let victim = crate::crypto::identity::Identity::generate();
        let mut forged = signed(&victim, 9000);
        forged.addr = "203.0.113.66:9000".parse().unwrap();

        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 0);
        assert!(dir.insert(forged).is_err());
        assert!(dir.is_empty());
    }

    #[test]
    fn rejects_a_substituted_onion_key() {
        // 署名し直せても（＝持ち主本人でも）NodeId 由来でない X25519 鍵は受けない。
        // 鍵を差し替えられると、そのノード宛ての Onion 層を別の誰かが開ける
        let id = crate::crypto::identity::Identity::generate();
        let mut d = signed(&id, 9000);
        d.x25519_pub = [0x42; 32];
        d.resign(&id);

        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 0);
        assert!(dir.insert(d).is_err());
    }

    #[test]
    fn stale_descriptor_does_not_roll_back_a_newer_one() {
        let id = crate::crypto::identity::Identity::generate();
        let old = signed(&id, 9000);
        let mut new = old.clone();
        new.addr = "10.0.0.1:9001".parse().unwrap();
        new.resign(&id);

        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 0);
        dir.insert(new.clone()).unwrap();
        dir.insert(old).unwrap(); // 古い方の再送は黙って無視
        assert_eq!(dir.get(&id.public_id()).unwrap().addr, new.addr);
    }

    #[test]
    fn rejects_future_dated_descriptor() {
        // 遠い未来の記述子を一度入れると、以後の正しい更新が全部「古い」扱いになる
        let id = crate::crypto::identity::Identity::generate();
        let mut d = signed(&id, 9000);
        d.issued_at = crate::protocol::hint::current_timestamp() + 10 * MAX_DESCRIPTOR_CLOCK_SKEW_SECS;
        d.signature = id.sign(&d.signing_bytes());

        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 0);
        assert!(dir.insert(d).is_err());
    }

    #[test]
    fn set_epoch_seed_rotates_node_positions() {
        // エポックシードを回すとノードのリング座標が動く（グラインド無効化の核 / 3-4）。
        // 位置は H(NodeId ‖ epoch_seed) なので、seed が変われば保持者集合も変わる。
        let mut dir = RelayDirectory::new([0u8; 32], 0);
        let d = descriptor(7);
        dir.insert_unchecked(d.clone());

        let before = dir.position_of(&d).value();
        dir.set_epoch_seed([9u8; 32]);
        let after = dir.position_of(&d).value();

        assert_ne!(before, after, "シード回転で座標が動く");
        assert_eq!(dir.epoch_seed(), [9u8; 32]);
    }
}
