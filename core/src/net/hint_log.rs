//! 分散 Hint backlog — オフライン受信のための窓つき保持 (19.1.3)
//!
//! Broadcast Veil で全 Hint を受け取っても、gossip の窓（数秒）を逃すと二度と来ない。
//! そこで各 Hint を `H(hint_id)` の K=5 最近接だけが [`RETENTION_WINDOW_SECS`] 保持し、
//! 復帰したノードが**差分同期**で取りこぼしを埋める。
//!
//! # live dedup とは別物
//!
//! `SeenCache`（15分・拡散ループ防止）とは役割が違う。こちらは 24h 保持で、
//! 目的は「オフラインだったノードの追いつき」。両者を混同しないこと。
//!
//! # なぜ Hint を割らないか
//!
//! Hint は 26〜90B と小さい。RS 誤り訂正は符号ヘッダが節約分を食うので、
//! **丸ごと K 複製**が最安（本体シャードとの違い）。
//!
//! # 差分同期
//!
//! 「自分が窓内に持つ id 集合(digest)」を相手へ送り、相手が**欠けている分の
//! Hint 本体**を返す。id しか送らないので受信者匿名性には触れない
//! （どの Hint が自分宛てかは手元でしか判定しない）。
//! MVP は id をそのまま並べる。窓内件数が [`RECONCILE_CAP`] を超えると部分同期に
//! なるが、複数ラウンド・複数ピアで収束する。スケールするなら minisketch/IBLT に差し替える。

use crate::protocol::hint::{current_timestamp, HintPacket};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// backlog の保持窓（＝オフライン耐性の長さ）
pub const RETENTION_WINDOW_SECS: u64 = 24 * 3600;

/// 1回の digest / 応答に載せる上限
///
/// digest は 32B×N、応答は Hint×N。両方をこの数で頭打ちにして増幅を防ぐ。
pub const RECONCILE_CAP: usize = 256;

/// 保持中の1件（本体＋保存時刻）
///
/// 窓判定には Hint 自身の timestamp ではなく**受信時刻**を使う。
/// timestamp は暗号化ペイロードの中にあり保持者は読めないため。
struct Stored {
    hint: HintPacket,
    stored_at: u64,
}

/// 差分同期の要求。「自分が窓内に持つ id 集合」
///
/// 受け取った側は、これに含まれない自分の Hint を返す。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintDigest {
    pub ids: Vec<[u8; 32]>,
}

impl HintDigest {
    pub fn encode(&self) -> crate::error::Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| crate::error::AetherError::Serialization(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> crate::error::Result<Self> {
        let d: Self = bincode::deserialize(bytes)
            .map_err(|e| crate::error::AetherError::Protocol(format!("Invalid HintDigest: {}", e)))?;
        if d.ids.len() > RECONCILE_CAP {
            return Err(crate::error::AetherError::Protocol(format!(
                "HintDigest too large: {} (max {})",
                d.ids.len(),
                RECONCILE_CAP
            )));
        }
        Ok(d)
    }
}

/// 窓つき Hint 保持ストア
pub struct HintLog {
    entries: HashMap<[u8; 32], Stored>,
    window_secs: u64,
}

impl Default for HintLog {
    fn default() -> Self {
        Self::with_window(RETENTION_WINDOW_SECS)
    }
}

impl HintLog {
    pub fn with_window(window_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            window_secs,
        }
    }

    /// Hint を取り込む。戻り値は「新規に保存したか」
    ///
    /// 既知は false。取り込み時に窓外の古いエントリも掃除する。
    pub fn insert(&mut self, hint: HintPacket) -> bool {
        let now = current_timestamp();
        self.prune(now);

        let id = hint.id();
        if self.entries.contains_key(&id) {
            return false;
        }
        self.entries.insert(id, Stored { hint, stored_at: now });
        true
    }

    /// 窓外（保存から `window_secs` 超過）のエントリを捨てる
    pub fn prune(&mut self, now: u64) {
        let window = self.window_secs;
        self.entries
            .retain(|_, s| now.saturating_sub(s.stored_at) <= window);
    }

    /// 自分が窓内に持つ id 集合（同期要求用、上限あり）
    ///
    /// 上限を超える場合は**新しい順**に載せる（古いものは相手も持っている公算が高い）。
    pub fn digest(&self) -> HintDigest {
        let mut items: Vec<(&[u8; 32], u64)> =
            self.entries.iter().map(|(id, s)| (id, s.stored_at)).collect();
        // 新しい順
        items.sort_by(|a, b| b.1.cmp(&a.1));
        items.truncate(RECONCILE_CAP);

        HintDigest {
            ids: items.into_iter().map(|(id, _)| *id).collect(),
        }
    }

    /// 相手の digest に**含まれていない**自分の Hint を返す（応答用、上限あり）
    ///
    /// これを相手へ送ると、相手は取りこぼしを埋められる。
    pub fn diff(&self, their: &HintDigest) -> Vec<HintPacket> {
        let have: std::collections::HashSet<&[u8; 32]> = their.ids.iter().collect();

        let mut missing: Vec<(&HintPacket, u64)> = self
            .entries
            .iter()
            .filter(|(id, _)| !have.contains(id))
            .map(|(_, s)| (&s.hint, s.stored_at))
            .collect();

        // 新しい順に、上限まで
        missing.sort_by(|a, b| b.1.cmp(&a.1));
        missing.truncate(RECONCILE_CAP);
        missing.into_iter().map(|(h, _)| h.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint(tag: u8) -> HintPacket {
        HintPacket::new([tag; 4], [tag; 12], vec![tag; 48], 5)
    }

    #[test]
    fn insert_is_idempotent_by_id() {
        let mut log = HintLog::default();
        assert!(log.insert(hint(1)), "新規は true");
        assert!(!log.insert(hint(1)), "既知は false");
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn prune_drops_entries_past_the_window() {
        let mut log = HintLog::with_window(100);
        log.insert(hint(1));

        // 窓内は残る
        log.prune(current_timestamp() + 50);
        assert_eq!(log.len(), 1);

        // 窓を超えたら消える
        log.prune(current_timestamp() + 200);
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn diff_returns_only_what_the_peer_lacks() {
        // A は 1,2,3 を持ち、B は 1 だけ持つ → A が B へ渡すのは 2,3
        let mut a = HintLog::default();
        for t in [1, 2, 3] {
            a.insert(hint(t));
        }
        let mut b = HintLog::default();
        b.insert(hint(1));

        let to_send = a.diff(&b.digest());
        let mut got: Vec<[u8; 32]> = to_send.iter().map(|h| h.id()).collect();
        got.sort();

        let mut want: Vec<[u8; 32]> = [hint(2), hint(3)].iter().map(|h| h.id()).collect();
        want.sort();

        assert_eq!(got, want, "相手が欠けている 2,3 だけを返す");
    }

    #[test]
    fn reconciliation_makes_two_logs_converge() {
        // A: {1,2,3}, B: {3,4,5} を双方向同期すると両方 {1..5} になる
        let mut a = HintLog::default();
        let mut b = HintLog::default();
        for t in [1, 2, 3] {
            a.insert(hint(t));
        }
        for t in [3, 4, 5] {
            b.insert(hint(t));
        }

        // A ← B が持つ差分
        for h in b.diff(&a.digest()) {
            a.insert(h);
        }
        // B ← A が持つ差分
        for h in a.diff(&b.digest()) {
            b.insert(h);
        }

        assert_eq!(a.len(), 5);
        assert_eq!(b.len(), 5);
    }

    #[test]
    fn digest_and_response_are_capped() {
        let mut log = HintLog::default();
        for t in 0..=255u8 {
            log.insert(hint(t));
        }
        // 256 件ちょうど
        assert!(log.digest().ids.len() <= RECONCILE_CAP);

        let empty = HintDigest { ids: vec![] };
        assert!(log.diff(&empty).len() <= RECONCILE_CAP, "応答も上限で頭打ち");
    }
}
