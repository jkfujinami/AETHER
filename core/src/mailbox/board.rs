//! 掲示板のスレッド DAG (Phase 2-5)
//!
//! 参考: aether-web-lite の `ThreadDAGManager` / `ThreadRanker`。
//!
//! - **スレッド = 投稿の DAG。** 各投稿は 1 つ以上の親（先端 = tips）を参照する。
//!   木ではなく DAG なのは、同時に書かれた複数の tips を後続がまとめて
//!   分岐を収束させられるため（IOTA tangle / git と同型）。
//! - **決定論的トポロジカル順序。** 全ノードが同じ DAG から同じ並びを再現できるよう、
//!   Kahn のアルゴリズムで因果順を保ちつつ、同時処理可能なものを
//!   `(timestamp 昇順 → content_ref 昇順)` で一意に並べる。
//! - **掲示板 = スレッド一覧。** スレッド（parents が空の根）を [`hn_score`] で
//!   ランク付けして並べる（Hacker News 流：熱量 ÷ 時間の重力）。
//!
//! 索引レコードは K_pub で封じられているので、保持者にはスレッド構造も見えない。

use crate::mailbox::index::IndexDescriptor;
use std::collections::{HashMap, HashSet};

/// 投稿の識別子（= その投稿の `content_ref`）
pub type PostId = [u8; 32];

/// content_ref → `descriptors` 内のインデックス
fn index_of(descriptors: &[IndexDescriptor]) -> HashMap<PostId, usize> {
    descriptors
        .iter()
        .enumerate()
        .map(|(i, d)| (d.content_ref, i))
        .collect()
}

/// 並び替えのタイブレーク鍵：(timestamp 昇順, content_ref 昇順)
fn tiebreak(d: &IndexDescriptor) -> (u64, PostId) {
    (d.timestamp, d.content_ref)
}

/// DAG を決定論的トポロジカル順に並べる（戻り値は `descriptors` へのインデックス列）
///
/// 親が先に来る。DAG に**存在しない**親参照は無視する（まだ取得できていない親は
/// 数えず、その投稿を根として扱って迷子にしない）。万一循環があっても、
/// 残りを末尾に足して全件返す（黙って落とさない）。
pub fn topological_order(descriptors: &[IndexDescriptor]) -> Vec<usize> {
    let idx = index_of(descriptors);
    let n = descriptors.len();

    let mut in_degree = vec![0usize; n];
    let mut children: HashMap<usize, Vec<usize>> = HashMap::new();

    for (i, d) in descriptors.iter().enumerate() {
        for parent in &d.parents {
            if let Some(&pi) = idx.get(parent) {
                in_degree[i] += 1;
                children.entry(pi).or_default().push(i);
            }
        }
    }

    // ready を (timestamp, id) 昇順に保つ
    let mut ready: Vec<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
    ready.sort_by(|&a, &b| tiebreak(&descriptors[a]).cmp(&tiebreak(&descriptors[b])));

    let mut order = Vec::with_capacity(n);
    while !ready.is_empty() {
        let next = ready.remove(0);
        order.push(next);

        if let Some(kids) = children.get(&next) {
            for &c in kids {
                in_degree[c] -= 1;
                if in_degree[c] == 0 {
                    let key = tiebreak(&descriptors[c]);
                    let pos = ready
                        .binary_search_by(|&x| tiebreak(&descriptors[x]).cmp(&key))
                        .unwrap_or_else(|e| e);
                    ready.insert(pos, c);
                }
            }
        }
    }

    // 循環に巻き込まれて処理されなかったものを末尾に（決定論のため id 順）
    if order.len() < n {
        let placed: HashSet<usize> = order.iter().copied().collect();
        let mut rest: Vec<usize> = (0..n).filter(|i| !placed.contains(i)).collect();
        rest.sort_by(|&a, &b| tiebreak(&descriptors[a]).cmp(&tiebreak(&descriptors[b])));
        order.extend(rest);
    }

    order
}

/// トポロジカル順を前提に、各投稿の表示深さ（親からの最長距離）を求める
///
/// `order` の順で処理すれば親の深さが先に確定する。根は 0。
pub fn depths(descriptors: &[IndexDescriptor], order: &[usize]) -> HashMap<usize, usize> {
    let idx = index_of(descriptors);
    let mut depth: HashMap<usize, usize> = HashMap::new();

    for &i in order {
        let d = descriptors[i]
            .parents
            .iter()
            .filter_map(|p| idx.get(p))
            .filter_map(|pi| depth.get(pi))
            .map(|&x| x + 1)
            .max()
            .unwrap_or(0);
        depth.insert(i, d);
    }
    depth
}

/// DAG の先端（子を持たない投稿）。新しい投稿はここへ親参照を張る
pub fn tips(descriptors: &[IndexDescriptor]) -> Vec<PostId> {
    let mut has_child: HashSet<PostId> = HashSet::new();
    for d in descriptors {
        for p in &d.parents {
            has_child.insert(*p);
        }
    }
    descriptors
        .iter()
        .map(|d| d.content_ref)
        .filter(|id| !has_child.contains(id))
        .collect()
}

/// スレッドの根（parents が空 = 新規スレッド）を `descriptors` のインデックスで返す
pub fn thread_roots(descriptors: &[IndexDescriptor]) -> Vec<usize> {
    descriptors
        .iter()
        .enumerate()
        .filter(|(_, d)| d.parents.is_empty())
        .map(|(i, _)| i)
        .collect()
}

/// 各投稿の**累積 PoW**（自分の達成ビット + 親の累積の最大）を求める (2-7)
///
/// `order` はトポロジカル順（親が先）、`pow_bits[i]` は投稿 i が実際に積んだ PoW ビット。
/// 累積 = 自分 + max(親の累積) なので、返信が伸びて PoW を積み重ねたスレッドほど
/// 大きくなる。スパムの単発投稿は基礎値のまま沈む。
pub fn cumulative_pow(
    descriptors: &[IndexDescriptor],
    order: &[usize],
    pow_bits: &[u32],
) -> Vec<u32> {
    let idx = index_of(descriptors);
    let mut cum = vec![0u32; descriptors.len()];

    for &i in order {
        let parent_max = descriptors[i]
            .parents
            .iter()
            .filter_map(|p| idx.get(p))
            .map(|&pi| cum[pi])
            .max()
            .unwrap_or(0);
        cum[i] = pow_bits.get(i).copied().unwrap_or(0).saturating_add(parent_max);
    }
    cum
}

/// Hacker News / Reddit 流のランキングスコア（掲示板のスレッド並び / 2-7 で使う）
///
/// `Score = (熱量 + BASE) / (経過時間[h] + OFFSET)^GRAVITY`。
/// 熱量（`max_pow` = スレッド内の最大累積 PoW）が高いほど上に、時間が経つほど沈む。
/// 新しいだけのスレッドが居座らず、PoW を積んだ議論が浮く。
pub fn hn_score(max_pow: f64, created_at_secs: u64, now_secs: u64) -> f64 {
    const GRAVITY: f64 = 1.8;
    const TIME_OFFSET_HOURS: f64 = 2.0;
    const BASE_SCORE: f64 = 16.0;

    let hours = now_secs.saturating_sub(created_at_secs) as f64 / 3600.0;
    let numerator = max_pow.max(0.0) + BASE_SCORE;
    let denominator = (hours.max(0.0) + TIME_OFFSET_HOURS).powf(GRAVITY);
    numerator / denominator
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(id: u8, ts: u64, parents: &[u8]) -> IndexDescriptor {
        IndexDescriptor {
            content_ref: [id; 32],
            name: format!("post-{}", id),
            size: 0,
            timestamp: ts,
            chunked: false,
            parents: parents.iter().map(|&p| [p; 32]).collect(),
        }
    }

    #[test]
    fn parents_come_before_children() {
        // 1 <- 2 <- 3 の鎖。順序は必ず 1,2,3
        let posts = vec![post(3, 30, &[2]), post(1, 10, &[]), post(2, 20, &[1])];
        let order = topological_order(&posts);
        let ids: Vec<u8> = order.iter().map(|&i| posts[i].content_ref[0]).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn concurrent_posts_break_ties_by_time_then_id() {
        // 根 1 に 3, 2 が同時返信（時刻同じ）→ id 昇順で 2,3
        let posts = vec![
            post(1, 10, &[]),
            post(3, 20, &[1]),
            post(2, 20, &[1]),
        ];
        let order = topological_order(&posts);
        let ids: Vec<u8> = order.iter().map(|&i| posts[i].content_ref[0]).collect();
        assert_eq!(ids, vec![1, 2, 3], "同時なら (時刻→id) の決定論順");
    }

    #[test]
    fn order_is_deterministic_regardless_of_input_order() {
        let a = vec![post(1, 10, &[]), post(2, 20, &[1]), post(3, 30, &[2])];
        let b = vec![post(3, 30, &[2]), post(2, 20, &[1]), post(1, 10, &[])];

        let ids_a: Vec<u8> = topological_order(&a).iter().map(|&i| a[i].content_ref[0]).collect();
        let ids_b: Vec<u8> = topological_order(&b).iter().map(|&i| b[i].content_ref[0]).collect();
        assert_eq!(ids_a, ids_b);
    }

    #[test]
    fn dag_merge_of_two_tips() {
        // 1 に 2,3 が分岐し、4 が 2 と 3 を both 参照して収束（DAG）
        let posts = vec![
            post(1, 10, &[]),
            post(2, 20, &[1]),
            post(3, 20, &[1]),
            post(4, 30, &[2, 3]),
        ];
        let order = topological_order(&posts);
        let pos: HashMap<u8, usize> = order
            .iter()
            .enumerate()
            .map(|(rank, &i)| (posts[i].content_ref[0], rank))
            .collect();
        // 4 は 2 と 3 の後
        assert!(pos[&4] > pos[&2] && pos[&4] > pos[&3]);
        // tips は収束後 4 だけ
        let tips: Vec<u8> = tips(&posts).iter().map(|t| t[0]).collect();
        assert_eq!(tips, vec![4]);
    }

    #[test]
    fn depth_is_longest_path_from_a_root() {
        let posts = vec![
            post(1, 10, &[]),
            post(2, 20, &[1]),
            post(3, 20, &[1]),
            post(4, 30, &[2, 3]),
        ];
        let order = topological_order(&posts);
        let depth = depths(&posts, &order);
        let by_id = |id: u8| depth[&posts.iter().position(|d| d.content_ref[0] == id).unwrap()];
        assert_eq!(by_id(1), 0);
        assert_eq!(by_id(2), 1);
        assert_eq!(by_id(4), 2, "2 と 3 の下なので深さ 2");
    }

    #[test]
    fn unknown_parent_is_treated_as_root() {
        // 親 99 は DAG に無い → 迷子にせず根として全件出す
        let posts = vec![post(2, 20, &[99]), post(1, 10, &[])];
        let order = topological_order(&posts);
        assert_eq!(order.len(), 2);
    }

    #[test]
    fn cycle_does_not_drop_posts() {
        // 1<->2 の循環（起きてはならないが防御）。全件返す
        let posts = vec![post(1, 10, &[2]), post(2, 20, &[1])];
        assert_eq!(topological_order(&posts).len(), 2);
    }

    #[test]
    fn thread_roots_are_parentless() {
        let posts = vec![post(1, 10, &[]), post(2, 20, &[1]), post(5, 15, &[])];
        let roots: Vec<u8> = thread_roots(&posts).iter().map(|&i| posts[i].content_ref[0]).collect();
        assert_eq!(roots, vec![1, 5]);
    }

    #[test]
    fn cumulative_pow_accumulates_down_the_chain() {
        // 1(5) <- 2(3) <- 4(2), and 1 <- 3(7)。累積は自分+親の最大
        let posts = vec![
            post(1, 10, &[]),
            post(2, 20, &[1]),
            post(3, 20, &[1]),
            post(4, 30, &[2]),
        ];
        let pow = vec![5u32, 3, 7, 2]; // index順に対応
        let order = topological_order(&posts);
        // order を posts の index に対応させて cumulative を引く
        let cum = cumulative_pow(&posts, &order, &pow);
        assert_eq!(cum[0], 5, "根は自分の PoW");
        assert_eq!(cum[1], 8, "2 = 3 + 親1(5)");
        assert_eq!(cum[2], 12, "3 = 7 + 親1(5)");
        assert_eq!(cum[3], 10, "4 = 2 + 親2(8)");
    }

    #[test]
    fn hn_score_decays_with_time_and_rises_with_pow() {
        let now = 1_000_000;
        // 同じ時刻なら PoW が高い方が上
        assert!(hn_score(30.0, now - 3600, now) > hn_score(10.0, now - 3600, now));
        // 同じ PoW なら新しい方が上
        assert!(hn_score(20.0, now - 3600, now) > hn_score(20.0, now - 100_000, now));
    }
}
