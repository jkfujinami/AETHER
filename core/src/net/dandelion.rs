//! Dandelion++ — Hint 放流の発信元をさらに隠す (Phase 3-2)
//!
//! # 何を足すか
//!
//! Onion で発信者の IP は既に隠れているが、Hint は**出口リレー**で gossip に
//! 投入されるため、gossip を観測する敵は「この Hint は出口リレー X で最初に現れた」を
//! 学べる。Sybil で出口を多数握れば、放流の統計的な発生源に迫れる。
//!
//! Dandelion++ は投入を2相に分ける:
//!
//! - **stem（茎）相:** パケットを**単一のランダムな後継**へ数ホップ中継する（線状経路）。
//!   誰が最初に流したかが1本の線に埋もれる。
//! - **fluff（綿毛）相:** 各ホップが確率 `FLUFF_PROBABILITY` で通常の gossip
//!   ブロードキャストへ切り替える。期待ステム長 = `1 / FLUFF_PROBABILITY`。
//!
//! # Dandelion++ の勘所（参考: web-lite `DandelionRouter.ts` / 論文 §5）
//!
//! - **ステム後継はエポック内で固定**（毎回引き直すと交差攻撃で発信源が絞られる）。
//! - **送り主を次の候補から外す**（§5.2、経路が戻るのを防ぐ）。
//! - 候補が居なければ即 fluff。
//!
//! # このモジュールの範囲
//!
//! **中継判断（stem/fluff）とエポック固定のステム後継選択**という純粋なポリシーだけを持つ。
//! 実際の転送・ワイヤの stem パケット型・黒穴検出のエコー再送は配線側（node/server）で扱う。
//! 乱数は注入式にして決定論的にテストできるようにしている。

use crate::crypto::identity::NodeId;
use rand::Rng;
use std::time::{Duration, Instant};

/// 各ホップで fluff へ移行する確率。期待ステム長 = 1 / これ = 4 ホップ
pub const DEFAULT_FLUFF_PROBABILITY: f64 = 0.25;

/// ステム後継を固定するエポック長（10分）
pub const DEFAULT_EPOCH: Duration = Duration::from_secs(10 * 60);

/// 中継判断
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// stem 継続：この単一の後継へ転送する
    Forward(NodeId),
    /// fluff：通常の gossip ブロードキャストへ切り替える
    Fluff,
}

/// Dandelion++ の経路ポリシー（ノードごとに1つ）
pub struct DandelionRouter {
    fluff_probability: f64,
    epoch: Duration,
    /// エポック内で固定されるステム後継
    stem_target: Option<NodeId>,
    /// ステム後継の期限
    expiry: Option<Instant>,
}

impl Default for DandelionRouter {
    fn default() -> Self {
        Self::with_config(DEFAULT_FLUFF_PROBABILITY, DEFAULT_EPOCH)
    }
}

impl DandelionRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(fluff_probability: f64, epoch: Duration) -> Self {
        Self {
            fluff_probability: fluff_probability.clamp(0.0, 1.0),
            epoch,
            stem_target: None,
            expiry: None,
        }
    }

    /// エポック内で固定のステム後継を返す（`exclude` を除いた候補から）
    ///
    /// 期限切れ・候補に居ない・`exclude` と一致 のいずれかなら引き直す。
    fn stem_target<R: Rng>(
        &mut self,
        candidates: &[NodeId],
        exclude: Option<&NodeId>,
        now: Instant,
        rng: &mut R,
    ) -> Option<NodeId> {
        // 既存の後継がまだ有効なら再利用（エポック固定）
        if let (Some(t), Some(exp)) = (self.stem_target, self.expiry)
            && now < exp
            && candidates.contains(&t)
            && exclude != Some(&t)
        {
            return Some(t);
        }

        // 除外を反映した候補から新しく引く
        let pool: Vec<NodeId> = candidates
            .iter()
            .filter(|c| exclude != Some(*c))
            .copied()
            .collect();
        if pool.is_empty() {
            return None;
        }
        let chosen = pool[rng.gen_range(0..pool.len())];
        self.stem_target = Some(chosen);
        self.expiry = Some(now + self.epoch);
        Some(chosen)
    }

    /// 自己発信パケットのステム開始先を決める（全隣人から）
    ///
    /// 隣人が居なければ `None`（＝ステムできないので呼び出し側は通常 fluff）。
    pub fn stem_origin<R: Rng>(
        &mut self,
        neighbors: &[NodeId],
        now: Instant,
        rng: &mut R,
    ) -> Option<NodeId> {
        self.stem_target(neighbors, None, now, rng)
    }

    /// 受信したステムパケットをどう中継するか決める
    ///
    /// `sender`（送り主）は次の候補から外す（§5.2）。確率 `fluff_probability` で、
    /// あるいは候補が居なければ fluff。それ以外はエポック固定の後継へ forward。
    pub fn route<R: Rng>(
        &mut self,
        sender: &NodeId,
        neighbors: &[NodeId],
        now: Instant,
        rng: &mut R,
    ) -> Route {
        let has_candidate = neighbors.iter().any(|n| n != sender);
        if !has_candidate || rng.gen_range(0.0f64..1.0) < self.fluff_probability {
            return Route::Fluff;
        }
        match self.stem_target(neighbors, Some(sender), now, rng) {
            Some(target) => Route::Forward(target),
            None => Route::Fluff,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn node(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xD)
    }

    #[test]
    fn always_fluffs_when_probability_is_one() {
        let mut r = DandelionRouter::with_config(1.0, DEFAULT_EPOCH);
        let mut g = rng();
        let neighbors = [node(1), node(2), node(3)];
        for _ in 0..20 {
            assert_eq!(r.route(&node(9), &neighbors, Instant::now(), &mut g), Route::Fluff);
        }
    }

    #[test]
    fn always_forwards_when_probability_is_zero() {
        let mut r = DandelionRouter::with_config(0.0, DEFAULT_EPOCH);
        let mut g = rng();
        let neighbors = [node(1), node(2), node(3)];
        match r.route(&node(9), &neighbors, Instant::now(), &mut g) {
            Route::Forward(t) => assert!(neighbors.contains(&t)),
            Route::Fluff => panic!("確率0なら必ず stem 継続のはず"),
        }
    }

    #[test]
    fn never_forwards_back_to_the_sender() {
        // 送り主を候補から外す（§5.2）。隣人が送り主だけなら fluff
        let mut r = DandelionRouter::with_config(0.0, DEFAULT_EPOCH);
        let mut g = rng();

        // 送り主 = node(1)、候補は 1,2,3 → 転送先は 1 以外
        for _ in 0..20 {
            if let Route::Forward(t) = r.route(&node(1), &[node(1), node(2), node(3)], Instant::now(), &mut g) {
                assert_ne!(t, node(1), "送り主へは戻さない");
            }
        }
    }

    #[test]
    fn fluffs_when_only_the_sender_is_a_neighbor() {
        let mut r = DandelionRouter::with_config(0.0, DEFAULT_EPOCH); // 確率0でも
        let mut g = rng();
        // 隣人が送り主だけ → 候補ゼロ → fluff
        assert_eq!(r.route(&node(5), &[node(5)], Instant::now(), &mut g), Route::Fluff);
    }

    #[test]
    fn fluffs_when_no_neighbors() {
        let mut r = DandelionRouter::with_config(0.0, DEFAULT_EPOCH);
        let mut g = rng();
        assert_eq!(r.route(&node(5), &[], Instant::now(), &mut g), Route::Fluff);
        assert_eq!(r.stem_origin(&[], Instant::now(), &mut g), None);
    }

    #[test]
    fn stem_target_is_fixed_within_an_epoch() {
        // エポック内で後継が固定される（毎回引き直すと交差攻撃で発信源が絞られる）
        let mut r = DandelionRouter::with_config(0.0, Duration::from_secs(600));
        let mut g = rng();
        let neighbors = [node(1), node(2), node(3), node(4)];
        let now = Instant::now();

        let first = match r.route(&node(9), &neighbors, now, &mut g) {
            Route::Forward(t) => t,
            Route::Fluff => panic!("確率0なら forward"),
        };
        // 同一エポック内では同じ後継を返し続ける
        for i in 1..30 {
            let later = now + Duration::from_secs(i);
            match r.route(&node(9), &neighbors, later, &mut g) {
                Route::Forward(t) => assert_eq!(t, first, "エポック内は後継固定"),
                Route::Fluff => panic!("確率0なら forward"),
            }
        }
    }

    #[test]
    fn stem_target_can_rotate_after_the_epoch() {
        // 期限が切れたら引き直す（候補にまだ居ても、期限切れ後は再抽選する）
        let mut r = DandelionRouter::with_config(0.0, Duration::from_secs(1));
        let mut g = rng();
        let neighbors = [node(1), node(2), node(3), node(4)];
        let now = Instant::now();

        let _first = r.route(&node(9), &neighbors, now, &mut g);
        let expiry = r.expiry.unwrap();

        // 期限後は expiry が更新される（再抽選が走った証拠）
        let after = expiry + Duration::from_secs(1);
        let _second = r.route(&node(9), &neighbors, after, &mut g);
        assert!(r.expiry.unwrap() > expiry, "エポック満了で後継が引き直される");
    }

    #[test]
    fn expected_stem_length_matches_fluff_probability() {
        // 各ホップ独立に確率 0.25 で fluff → 期待ステム長 ≈ 4。統計的に確認する。
        let mut g = StdRng::seed_from_u64(1);
        let neighbors: Vec<NodeId> = (1..=8).map(node).collect();
        let trials = 4000;
        let mut total_hops = 0u64;

        for _ in 0..trials {
            let mut r = DandelionRouter::with_config(0.25, DEFAULT_EPOCH);
            let mut sender = node(0);
            let mut hops = 0u64;
            while let Route::Forward(t) = r.route(&sender, &neighbors, Instant::now(), &mut g) {
                hops += 1;
                sender = t;
                if hops > 1000 {
                    break; // 安全弁
                }
            }
            total_hops += hops;
        }

        let avg = total_hops as f64 / trials as f64;
        // 期待値 4（幾何分布）。乱数なので広めの許容
        assert!(avg > 3.0 && avg < 5.0, "期待ステム長が想定域を外れた: {:.2}", avg);
    }
}
