//! 入口リレー（ガード）の選択方針
//!
//! # なぜ固定ガードなのか
//!
//! 入口リレーを毎回ランダムに選ぶと、攻撃者のリレー占有率 f に対して
//! 「生涯に一度でも敵の入口を引く」確率は `1 - (1-f)^n` で **n とともに 1 に収束する**。
//! f=5% でも 100 回接続すれば 99.4%。長期運用では確実に引く。
//!
//! 一方、少数の入口を固定すると、危険度は最初の1回の抽選 f で固定され、
//! 時間とともに増えない。
//!
//! 日本の捜査モデルでは入口の露出は
//! 「IP 特定 → ISP 照会 → 押収」という**不可逆**な結果に直結する。
//! 最小化すべきは「各回の確率」ではなく **P(生涯に一度でも露出)** であり、
//! この目的関数では固定ガードが決定的に優る。Tor が 2014 年に
//! ガード方式へ移行したのと同じ理由。
//!
//! # 実装上の要点
//!
//! - **永続化が必須。** 起動のたびに選び直すと実質ランダム選択に戻り、
//!   この仕組み全体が無意味になる。よくある実装ミス。
//! - 少数（[`GUARD_SAMPLE_SIZE`]）を標本として保持し、実際に使うのは1本。
//!   失敗時は標本内の次を試し、すぐには再抽選しない。
//! - 稼働実績（node age）で重み付けし、新規ノードがガードになりにくくする。
//!   Sybil ガードに「長期間おとなしく稼働する」コストを課すため。

use crate::error::{AetherError, Result};
use crate::crypto::identity::NodeId;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// 標本として保持するガードの数。実際に使うのは先頭1本
pub const GUARD_SAMPLE_SIZE: usize = 3;

/// ガードを入れ替えるまでの期間（60日）
///
/// 短いほどランダム選択の性質に近づき、危険度が時間とともに上がる。
/// 長いほど「外れを引いた場合の被害期間」が延びる。Tor は 2〜3ヶ月。
pub const GUARD_ROTATION_SECS: u64 = 60 * 24 * 3600;

/// この回数連続で失敗したガードは標本内で降格させる
pub const MAX_CONSECUTIVE_FAILURES: u32 = 3;

/// ガード候補
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardCandidate {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    /// Onion 層の鍵導出に使う X25519 公開鍵
    pub x25519_pub: [u8; 32],
    /// 稼働実績（秒）。重み付け抽選に使う
    pub uptime_secs: u64,
}

/// 選択済みのガード
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guard {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    /// Onion の第1層を包む鍵
    ///
    /// ガードと一緒に永続化する。ディレクトリ任せにすると、起動直後で PEX が
    /// まだガードを運んできていない時に回路を組めず、別の入口へ逃げたくなる。
    pub x25519_pub: [u8; 32],
    /// 選択した時刻 (UNIX秒)
    pub selected_at: u64,
    /// 連続失敗回数
    pub consecutive_failures: u32,
}

impl Guard {
    fn from_candidate(c: &GuardCandidate, now: u64) -> Self {
        Self {
            node_id: c.node_id,
            addr: c.addr,
            x25519_pub: c.x25519_pub,
            selected_at: now,
            consecutive_failures: 0,
        }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.selected_at) >= GUARD_ROTATION_SECS
    }

    pub fn is_usable(&self) -> bool {
        self.consecutive_failures < MAX_CONSECUTIVE_FAILURES
    }
}

/// 永続化されるガード集合
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GuardSet {
    guards: Vec<Guard>,
}

impl GuardSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// ディスクから読み込む。ファイルが無ければ空集合
    ///
    /// **読み込みに失敗しても空集合を返して選び直すのではなく、
    /// 呼び出し側にエラーを返す。** 破損を黙って握りつぶすと
    /// 「起動のたびに再抽選」と同じ状態になり、ガードの意味が消える。
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => bincode::deserialize(&bytes)
                .map_err(|e| AetherError::Storage(format!("Corrupt guard file: {}", e))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(AetherError::Network(e)),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let bytes = bincode::serialize(self)
            .map_err(|e| AetherError::Serialization(e.to_string()))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(AetherError::Network)?;
        }

        // 書き込み途中で落ちても既存を壊さないよう、一時ファイル経由で置換する
        let tmp = PathBuf::from(format!("{}.tmp", path.display()));
        std::fs::write(&tmp, &bytes).map_err(AetherError::Network)?;
        std::fs::rename(&tmp, path).map_err(AetherError::Network)?;
        Ok(())
    }

    /// 現在使うべきガードを返す
    ///
    /// 標本のうち、期限内かつ連続失敗が上限未満の先頭のものを使う。
    pub fn current(&self, now: u64) -> Option<&Guard> {
        self.guards
            .iter()
            .find(|g| g.is_usable() && !g.is_expired(now))
    }

    /// 標本が足りなければ候補から補充する
    ///
    /// 稼働実績で重み付けした抽選を行い、新規ノードがガードになりにくくする。
    /// 既存のガードは**期限切れか失敗上限に達するまで維持する**。
    pub fn replenish(&mut self, candidates: &[GuardCandidate], now: u64) -> usize {
        // 期限切れ・失敗上限のものを落とす
        self.guards.retain(|g| g.is_usable() && !g.is_expired(now));

        let existing: Vec<NodeId> = self.guards.iter().map(|g| g.node_id).collect();
        let mut pool: Vec<&GuardCandidate> = candidates
            .iter()
            .filter(|c| !existing.contains(&c.node_id))
            .collect();

        if pool.is_empty() {
            return 0;
        }

        // 稼働実績で重み付け（実績0でも最低1の重みは与える）
        // 同じ実績どうしは無作為に並べる（安定ソートなので先に混ぜておく）。
        // 起動直後は全員の観測在籍時間がほぼ同じで、並びがディレクトリの内部順に
        // 引きずられると、選ばれ方が偏る。
        let mut rng = rand::thread_rng();
        pool.shuffle(&mut rng);
        pool.sort_by_key(|c| std::cmp::Reverse(c.uptime_secs));

        let mut added = 0;
        while self.guards.len() < GUARD_SAMPLE_SIZE && !pool.is_empty() {
            // 上位側に偏らせつつ完全な決定論は避ける
            let window = pool.len().min(GUARD_SAMPLE_SIZE * 2);
            let idx = (0..window)
                .collect::<Vec<_>>()
                .choose(&mut rng)
                .copied()
                .unwrap_or(0);

            let chosen = pool.remove(idx);
            self.guards.push(Guard::from_candidate(chosen, now));
            added += 1;
        }

        added
    }

    /// 接続成功を記録する
    pub fn record_success(&mut self, node_id: &NodeId) {
        if let Some(g) = self.guards.iter_mut().find(|g| &g.node_id == node_id) {
            g.consecutive_failures = 0;
        }
    }

    /// 接続失敗を記録する
    ///
    /// 上限に達したガードは [`current`] から外れ、標本内の次が使われる。
    /// **すぐに再抽選はしない** — 一時的な障害で毎回引き直すと
    /// ランダム選択に退化するため。
    pub fn record_failure(&mut self, node_id: &NodeId) {
        if let Some(g) = self.guards.iter_mut().find(|g| &g.node_id == node_id) {
            g.consecutive_failures = g.consecutive_failures.saturating_add(1);
        }
    }

    pub fn len(&self) -> usize {
        self.guards.len()
    }

    pub fn is_empty(&self) -> bool {
        self.guards.is_empty()
    }

    pub fn all(&self) -> &[Guard] {
        &self.guards
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::hint::current_timestamp;

    fn candidate(n: u8, uptime_secs: u64) -> GuardCandidate {
        GuardCandidate {
            node_id: NodeId([n; 32]),
            addr: format!("127.0.0.{}:9000", n).parse().unwrap(),
            x25519_pub: [n; 32],
            uptime_secs,
        }
    }

    fn candidates() -> Vec<GuardCandidate> {
        (1..=10u8).map(|n| candidate(n, u64::from(n) * 86_400)).collect()
    }

    #[test]
    fn replenishes_up_to_sample_size() {
        let now = current_timestamp();
        let mut set = GuardSet::new();

        assert_eq!(set.replenish(&candidates(), now), GUARD_SAMPLE_SIZE);
        assert_eq!(set.len(), GUARD_SAMPLE_SIZE);
        assert!(set.current(now).is_some());
    }

    #[test]
    fn keeps_the_same_guard_across_replenish_calls() {
        // ここが崩れると「毎回選び直し」= 実質ランダム選択に退化する
        let now = current_timestamp();
        let mut set = GuardSet::new();
        set.replenish(&candidates(), now);

        let first = set.current(now).unwrap().node_id;

        for _ in 0..20 {
            set.replenish(&candidates(), now);
            assert_eq!(
                set.current(now).unwrap().node_id,
                first,
                "補充のたびにガードが変わってはならない"
            );
        }
    }

    #[test]
    fn survives_a_round_trip_through_disk() {
        // 永続化されないと起動のたびに再抽選され、ガード方式の意味が消える
        let now = current_timestamp();
        let mut set = GuardSet::new();
        set.replenish(&candidates(), now);
        let expected = set.current(now).unwrap().node_id;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guards.bin");
        set.save(&path).unwrap();

        let loaded = GuardSet::load(&path).unwrap();
        assert_eq!(
            loaded.current(now).unwrap().node_id,
            expected,
            "再起動でガードが変わってはならない"
        );
    }

    #[test]
    fn missing_file_yields_empty_set() {
        let dir = tempfile::tempdir().unwrap();
        let set = GuardSet::load(&dir.path().join("nope.bin")).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn corrupt_file_is_an_error_not_a_silent_reset() {
        // 黙って空集合に戻すと「起動のたびに再抽選」と同じ状態になる
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guards.bin");
        std::fs::write(&path, b"garbage").unwrap();

        assert!(GuardSet::load(&path).is_err());
    }

    #[test]
    fn failing_guard_is_demoted_after_threshold() {
        let now = current_timestamp();
        let mut set = GuardSet::new();
        set.replenish(&candidates(), now);

        let first = set.current(now).unwrap().node_id;

        // 上限未満なら使い続ける（一時的な障害で乗り換えない）
        for _ in 0..(MAX_CONSECUTIVE_FAILURES - 1) {
            set.record_failure(&first);
            assert_eq!(set.current(now).unwrap().node_id, first);
        }

        set.record_failure(&first);
        assert_ne!(
            set.current(now).unwrap().node_id,
            first,
            "失敗が上限に達したら標本内の次へ移る"
        );
    }

    #[test]
    fn success_resets_the_failure_counter() {
        let now = current_timestamp();
        let mut set = GuardSet::new();
        set.replenish(&candidates(), now);
        let first = set.current(now).unwrap().node_id;

        set.record_failure(&first);
        set.record_failure(&first);
        set.record_success(&first);
        set.record_failure(&first);

        assert_eq!(
            set.current(now).unwrap().node_id,
            first,
            "成功で失敗カウンタが戻らなければ、断続的な障害で降格してしまう"
        );
    }

    #[test]
    fn expired_guard_is_replaced() {
        let now = current_timestamp();
        let mut set = GuardSet::new();
        set.replenish(&candidates(), now);
        let first = set.current(now).unwrap().node_id;

        let later = now + GUARD_ROTATION_SECS + 1;
        assert!(set.current(later).is_none(), "期限切れは使われない");

        set.replenish(&candidates(), later);

        // 補充後のガードは「選び直された」ものであること。
        // 同じノードを引き当てることもあるので node_id の変化は主張できない
        // （候補が少ないと必然的に同じものが選ばれる）。
        let replacement = set.current(later).expect("補充されるべき");
        assert_eq!(
            replacement.selected_at, later,
            "期限切れのガードが選択時刻ごと居座っている"
        );
        let _ = first;
    }

    #[test]
    fn prefers_long_running_candidates() {
        // 新規ノードがすぐガードになれると、Sybil ガードのコストが下がる
        let now = current_timestamp();
        let pool: Vec<GuardCandidate> = (1..=20u8)
            .map(|n| candidate(n, if n > 15 { 200 * 86_400 } else { 0 }))
            .collect();

        let mut long_running_picked = 0;
        for _ in 0..50 {
            let mut set = GuardSet::new();
            set.replenish(&pool, now);
            for g in set.all() {
                if pool
                    .iter()
                    .any(|c| c.node_id == g.node_id && c.uptime_secs > 0)
                {
                    long_running_picked += 1;
                }
            }
        }

        // 実績上位5/20 が一様抽選なら期待値は 50*3*0.25 = 37.5 程度。
        // 重み付けが効いていればこれを明確に上回る
        assert!(
            long_running_picked > 60,
            "稼働実績の重み付けが効いていない (picked={})",
            long_running_picked
        );
    }
}
