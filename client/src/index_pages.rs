//! 板の索引を日ごとのページに分けて引く・上げる（Part 25 の P13）
//!
//! 1 つの索引は 256 件までで、賑わう板では 1 日で埋まる。そこで索引を UTC の日ごとの
//! ページに分け、読者は今日から [`SEARCH_DAYS`] 日分を並行に引く。担当 5 台の全員に聞くと
//! 全員が最大 512KiB を返すので、まず近い 2 台に聞き、返事が無いページだけ残りにも聞く。
//! 古い日に立ったスレは、レスが付いたとき根の記録を今日のページへ置き直して見える状態に保つ。

use crate::boards::BoardId;
use crate::events;
use crate::Result;
use crate::AetherClient;
use aether_core::mailbox::index::{self, IndexDescriptor, IndexRecord};
use aether_core::protocol::hint::current_timestamp;
use std::collections::{HashMap, VecDeque};
use std::time::Duration;

/// 読者が遡るページの日数（今日を含む）
pub(crate) const SEARCH_DAYS: u32 = 7;
/// 近い担当だけに聞いてから、返事の無いページの残りの担当にも聞くまでの待ち
pub(crate) const INDEX_HEDGE: Duration = Duration::from_secs(2);
/// 最初に聞く担当の数（近い順）
const INDEX_FIRST_WAVE: usize = 2;
/// 手元に覚えておく根の記録の上限（メモリだけ。ディスクには書かない）
pub(crate) const REMEMBER_MAX: usize = 256;

/// 読むページの日。今日が先頭で、過去へ [`SEARCH_DAYS`] 日分
pub(crate) fn search_days(now: u64) -> Vec<u32> {
    let today = index::page_day(now);
    (0..SEARCH_DAYS).filter_map(|i| today.checked_sub(i)).collect()
}

/// あるページに、いま近い順で何台まで聞いているべきか
///
/// 最初は近い 2 台。`INDEX_HEDGE` 経っても 1 件も返事が無ければ全員。返事が来たページは
/// 増やさない。単調ではないので、呼び出し側は「すでに聞いた台数」より増える分だけ送る。
pub(crate) fn index_ask_count(elapsed: Duration, got_reply: bool, total: usize) -> usize {
    if !got_reply && elapsed >= INDEX_HEDGE {
        total
    } else {
        total.min(INDEX_FIRST_WAVE)
    }
}

/// 手元に覚えた根の記録
struct Remembered {
    /// 記録の元のバイト列
    record: Vec<u8>,
    /// この記録がいつかのページで見つかった（置いた）日。今日なら置き直さない
    seen_day: u32,
}

/// 見た根の索引の記録を、上限つきで覚えておく表（メモリだけ）
///
/// 置き直しは PoW を解き直さないために元のバイト列が要る。古いものから捨てる。
#[derive(Default)]
pub(crate) struct RecordMemory {
    map: HashMap<([u8; 32], [u8; 32]), Remembered>,
    order: VecDeque<([u8; 32], [u8; 32])>,
}

impl RecordMemory {
    /// 板 `k_pub` の根 `content_ref` の記録を覚える。`day` はそれを見つけた（置いた）ページの日
    pub(crate) fn remember(&mut self, k_pub: &[u8; 32], content_ref: &[u8; 32], record: &[u8], day: u32) {
        let key = (*k_pub, *content_ref);
        if let Some(e) = self.map.get_mut(&key) {
            // 今日のページで見たなら、それを優先して覚える（置き直し済みの印になる）
            e.seen_day = e.seen_day.max(day);
            return;
        }
        if self.map.len() >= REMEMBER_MAX
            && let Some(old) = self.order.pop_front()
        {
            self.map.remove(&old);
        }
        self.order.push_back(key);
        self.map.insert(key, Remembered { record: record.to_vec(), seen_day: day });
    }

    fn get(&self, k_pub: &[u8; 32], content_ref: &[u8; 32]) -> Option<&Remembered> {
        self.map.get(&(*k_pub, *content_ref))
    }

    /// 置き直したので、今日のページにあるものとして印を付ける
    fn mark_aged(&mut self, k_pub: &[u8; 32], content_ref: &[u8; 32], day: u32) {
        if let Some(e) = self.map.get_mut(&(*k_pub, *content_ref)) {
            e.seen_day = e.seen_day.max(day);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

/// 根を今日のページへ置き直すべきなら、置く記録のバイト列を返す（純粋な判断）
///
/// 覚えていなければ `None`（スレを開かずに書いた等）。今日のページにあるなら `None`。
pub(crate) fn reage_record(
    memory: &RecordMemory,
    k_pub: &[u8; 32],
    root: &[u8; 32],
    today: u32,
) -> Option<Vec<u8>> {
    let e = memory.get(k_pub, root)?;
    if e.seen_day == today {
        return None;
    }
    // 元の記述子の日がすでに今日なら、そもそも今日のページにある
    let d = IndexRecord::decode(&e.record).ok()?.open(k_pub)?;
    if index::page_day(d.timestamp) == today {
        return None;
    }
    Some(e.record.clone())
}

/// 親が見つからない投稿のために、覚えている根の記述子を足す
///
/// 根のページ（7 日より前）を引いていなくても、開いたことのあるスレの根は表示できる。
/// 足したものの PoW ビットは記録から計算する。
pub(crate) fn fill_known_roots(
    found: &mut Vec<IndexDescriptor>,
    pow: &mut Vec<u32>,
    memory: &RecordMemory,
    k_pub: &[u8; 32],
) {
    let have: std::collections::HashSet<[u8; 32]> = found.iter().map(|d| d.content_ref).collect();
    let mut wanted: Vec<[u8; 32]> = found
        .iter()
        .flat_map(|d| d.parents.iter().copied())
        .filter(|p| !have.contains(p))
        .collect();
    wanted.sort();
    wanted.dedup();
    for p in wanted {
        let Some(e) = memory.get(k_pub, &p) else { continue };
        let Ok(rec) = IndexRecord::decode(&e.record) else { continue };
        if let Some(d) = rec.open(k_pub) {
            pow.push(rec.pow_bits());
            found.push(d);
        }
    }
}

impl AetherClient {
    /// 発行した（または見た）根の記録を手元に覚える
    pub(crate) fn remember_root(&self, k_pub: &[u8; 32], content_ref: &[u8; 32], record: &[u8], day: u32) {
        self.index_memory.lock().unwrap().remember(k_pub, content_ref, record, day);
    }

    /// レスが付いたスレの根が今日のページに無ければ、根の記録を今日のページへ置き直す
    ///
    /// 元のバイト列をそのまま置くので PoW は解き直さない。根を覚えていなければ何もしない。
    /// 失敗してもレスの書き込みは成功扱い（上げられないだけ）。
    /// 保持者から見えるのは「根の記録が今日のページに置かれた」ことだけで、誰がかは割れない。
    pub(crate) async fn reage_root(&self, board: &BoardId, root: &[u8; 32]) -> Result<()> {
        let k_pub = board.key();
        let today = index::page_day(current_timestamp());
        let record = {
            let memory = self.index_memory.lock().unwrap();
            reage_record(&memory, &k_pub, root, today)
        };
        let Some(record) = record else { return Ok(()) };

        let session = self.open_pull_session(HashMap::new()).await?;
        session.mailbox.put_index_record(&k_pub, today, &record).await?;
        self.index_memory.lock().unwrap().mark_aged(&k_pub, root, today);
        events::progress(&self.events, "スレを今日の索引に上げました");
        self.flush_in_background(session.mailbox);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; 32] = [3; 32];
    const DAY: u64 = 86_400;

    fn desc(n: u8, parents: &[u8], ts: u64) -> IndexDescriptor {
        IndexDescriptor {
            content_ref: [n; 32],
            name: format!("p{}", n),
            size: 1,
            timestamp: ts,
            chunked: false,
            parents: parents.iter().map(|p| [*p; 32]).collect(),
        }
    }

    fn record_of(d: &IndexDescriptor) -> Vec<u8> {
        IndexRecord::create(&K, d, 0).unwrap().encode().unwrap()
    }

    #[test]
    fn search_days_cover_today_and_the_past_week() {
        let days = search_days(20_000 * DAY + 5);
        assert_eq!(days.len(), SEARCH_DAYS as usize);
        assert_eq!(days[0], 20_000);
        assert_eq!(*days.last().unwrap(), 20_000 - (SEARCH_DAYS - 1));
    }

    #[test]
    fn query_plan_asks_two_then_the_rest_only_for_silent_pages() {
        let s = Duration::from_secs;
        assert_eq!(index_ask_count(s(0), false, 5), 2, "最初は近い 2 台");
        assert_eq!(index_ask_count(s(1), false, 5), 2);
        assert_eq!(index_ask_count(INDEX_HEDGE, false, 5), 5, "HEDGE を過ぎて無言なら全員");
        assert_eq!(index_ask_count(s(5), true, 5), 2, "返事のあったページは増やさない");
        assert_eq!(index_ask_count(s(0), false, 1), 1, "担当が 2 台未満ならある分だけ");
    }

    #[test]
    fn reage_puts_the_root_back_when_it_is_not_in_todays_page() {
        let today = 20_000u32;
        let root = desc(1, &[], (today as u64 - 3) * DAY + 10);
        let rec = record_of(&root);
        let mut mem = RecordMemory::default();
        mem.remember(&K, &root.content_ref, &rec, today - 3);
        assert_eq!(reage_record(&mem, &K, &root.content_ref, today), Some(rec), "古いページにあるので置き直す");
    }

    #[test]
    fn reage_skips_a_root_already_in_todays_page() {
        let today = 20_000u32;
        let old = desc(1, &[], (today as u64 - 3) * DAY);
        let mut mem = RecordMemory::default();
        mem.remember(&K, &old.content_ref, &record_of(&old), today);
        assert_eq!(reage_record(&mem, &K, &old.content_ref, today), None, "今日のページで見たなら置かない");

        let fresh = desc(2, &[], today as u64 * DAY + 1);
        mem.remember(&K, &fresh.content_ref, &record_of(&fresh), today - 1);
        assert_eq!(reage_record(&mem, &K, &fresh.content_ref, today), None, "記述子が今日のものなら置かない");
    }

    #[test]
    fn reage_does_nothing_when_the_root_is_not_remembered() {
        let mem = RecordMemory::default();
        assert_eq!(reage_record(&mem, &K, &[9; 32], 20_000), None);
    }

    #[test]
    fn memory_is_bounded() {
        let mut mem = RecordMemory::default();
        for i in 0..(REMEMBER_MAX as u32 + 50) {
            let mut r = [0u8; 32];
            r[..4].copy_from_slice(&i.to_be_bytes());
            mem.remember(&K, &r, b"rec", 1);
        }
        assert_eq!(mem.len(), REMEMBER_MAX);
        assert!(mem.get(&K, &[0; 32]).is_none(), "古いものから捨てる");
    }

    #[test]
    fn known_roots_fill_in_for_replies_whose_page_was_not_read() {
        let root = desc(1, &[], 1_000);
        let mut mem = RecordMemory::default();
        mem.remember(&K, &root.content_ref, &record_of(&root), 0);

        let mut found = vec![desc(2, &[1], 2_000)];
        let mut pow = vec![5];
        fill_known_roots(&mut found, &mut pow, &mem, &K);
        assert_eq!(found.len(), 2);
        assert_eq!(pow.len(), 2);
        assert_eq!(found[1].content_ref, [1; 32]);

        // 覚えていない根は足さない
        let mut found = vec![desc(3, &[7], 2_000)];
        let mut pow = vec![0];
        fill_known_roots(&mut found, &mut pow, &mem, &K);
        assert_eq!(found.len(), 1);
    }
}
