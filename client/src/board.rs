//! 索引の検索結果を掲示板（スレッドの並び）に組み立てる（2-5 / 2-7）
//!
//! 並びは決定論的トポロジカル順、スレッドは累積 PoW（熱量）の HN 式ランク順。
//! 表示（CLI の字下げ・GUI のツリー）は呼び出し側に任せ、ここはデータだけを返す。

use aether_core::mailbox::board;
use aether_core::mailbox::index::IndexDescriptor;
use serde::Serialize;
use std::collections::HashMap;

/// 掲示板（スレッドの並び）
#[derive(Debug, Clone, Serialize)]
pub struct Board {
    /// ランク順（熱量 ÷ 時間の重力が大きい順）
    pub threads: Vec<Thread>,
}

impl Board {
    pub fn post_count(&self) -> usize {
        self.threads.iter().map(|t| t.posts.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }
}

/// スレッド 1 本
#[derive(Debug, Clone, Serialize)]
pub struct Thread {
    /// スレッド内の最大累積 PoW
    pub heat: u32,
    /// トポロジカル順（親が先）。先頭が根
    pub posts: Vec<Post>,
}

/// 投稿 1 件
#[derive(Debug, Clone, Serialize)]
pub struct Post {
    /// 参照（`get` と返信に使う, hex）
    pub content_ref: String,
    pub name: String,
    pub size: u64,
    pub timestamp: u64,
    /// ファイル（チャンク化）か
    pub chunked: bool,
    /// 親投稿の参照（hex）
    pub parents: Vec<String>,
    /// スレッド内の深さ（根 = 0）
    pub depth: usize,
}

/// 記述子と PoW から掲示板を組み立てる
pub fn build_board(found: &[IndexDescriptor], pow: &[u32], now: u64) -> Board {
    let order = board::topological_order(found);
    let depth = board::depths(found, &order);
    let cum = board::cumulative_pow(found, &order, pow);

    let idx: HashMap<[u8; 32], usize> =
        found.iter().enumerate().map(|(i, d)| (d.content_ref, i)).collect();

    // 各投稿が属するスレッド（根）を、トポロジカル順に親から伝播して決める
    let mut thread_of: HashMap<usize, usize> = HashMap::new();
    for &i in &order {
        let root = found[i]
            .parents
            .iter()
            .filter_map(|p| idx.get(p))
            .filter_map(|pi| thread_of.get(pi).copied())
            .next()
            .unwrap_or(i);
        thread_of.insert(i, root);
    }

    // スレッドごとに投稿を集める（トポロジカル順を保つ）
    let mut members: HashMap<usize, Vec<usize>> = HashMap::new();
    for &i in &order {
        members.entry(thread_of[&i]).or_default().push(i);
    }

    let heat = |r: usize| -> u32 { members[&r].iter().map(|&i| cum[i]).max().unwrap_or(0) };

    let mut roots: Vec<usize> = members.keys().copied().collect();
    roots.sort_by(|&a, &b| {
        let sa = board::hn_score(heat(a) as f64, found[a].timestamp, now);
        let sb = board::hn_score(heat(b) as f64, found[b].timestamp, now);
        sb.partial_cmp(&sa)
            .unwrap_or(std::cmp::Ordering::Equal)
            // 同点は決定論的に（表示がちらつかないよう）
            .then(found[a].content_ref.cmp(&found[b].content_ref))
    });

    let threads = roots
        .into_iter()
        .map(|r| Thread {
            heat: heat(r),
            posts: members[&r]
                .iter()
                .map(|&i| {
                    let d = &found[i];
                    Post {
                        content_ref: hex::encode(d.content_ref),
                        name: d.name.clone(),
                        size: d.size,
                        timestamp: d.timestamp,
                        chunked: d.chunked,
                        parents: d.parents.iter().map(hex::encode).collect(),
                        depth: depth[&i],
                    }
                })
                .collect(),
        })
        .collect();

    Board { threads }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(n: u8, parents: &[u8], ts: u64) -> IndexDescriptor {
        IndexDescriptor {
            content_ref: [n; 32],
            name: format!("p{}", n),
            size: 1,
            timestamp: ts,
            chunked: false,
            parents: parents.iter().map(|p| [*p; 32]).collect(),
        }
    }

    #[test]
    fn replies_are_grouped_under_their_thread() {
        let found = vec![post(1, &[], 100), post(2, &[1], 110), post(3, &[], 105), post(4, &[2], 120)];
        let board = build_board(&found, &[0, 0, 0, 0], 200);

        assert_eq!(board.threads.len(), 2);
        assert_eq!(board.post_count(), 4);
        let t1 = board
            .threads
            .iter()
            .find(|t| t.posts[0].name == "p1")
            .unwrap();
        let names: Vec<_> = t1.posts.iter().map(|p| (p.name.as_str(), p.depth)).collect();
        assert_eq!(names, vec![("p1", 0), ("p2", 1), ("p4", 2)]);
    }

    #[test]
    fn heavier_threads_rank_first() {
        let found = vec![post(1, &[], 100), post(2, &[], 100)];
        let board = build_board(&found, &[0, 30], 200);
        assert_eq!(board.threads[0].posts[0].name, "p2");
        assert_eq!(board.threads[0].heat, 30);
    }
}
