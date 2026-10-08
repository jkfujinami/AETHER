//! 因果順の DAG（掲示板のスレッド・トーク）
//!
//! 各要素は「書いた時点で見ていた先端」を親として参照する。木ではなく DAG なのは、
//! 同時に書かれた複数の先端を後続がまとめて分岐を収束させられるため（git と同型）。
//!
//! - **決定論的トポロジカル順序。** 同じ集合からは誰でも同じ並びを再現できるよう、
//!   Kahn のアルゴリズムで因果順（親が先）を保ちつつ、親子関係で決まらないものを
//!   `(timestamp 昇順 → id 昇順)` で一意に並べる。
//! - **時刻は目安でしかない。** 書き手の時計なのでずれうる。並びはまず親子関係で決まり、
//!   時刻は同時に書かれたもの同士の順にだけ効く。
//! - **手元に無い親は数えない。** まだ届いていない親を待って迷子にせず、根として扱う
//!   （[`missing_parents`] で「この前に欠けがある」ことは分かる）。

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// DAG の 1 要素
pub trait DagNode {
    type Id: Copy + Eq + Hash + Ord;
    fn id(&self) -> Self::Id;
    fn parents(&self) -> &[Self::Id];
    /// 親子関係で決まらないときの並びの目安（同じ種類の要素の間で単位が揃っていればよい）
    fn timestamp(&self) -> u64;
}

/// id → `nodes` 内のインデックス
fn index_of<T: DagNode>(nodes: &[T]) -> HashMap<T::Id, usize> {
    nodes.iter().enumerate().map(|(i, n)| (n.id(), i)).collect()
}

/// 並び替えのタイブレーク鍵：(timestamp 昇順, id 昇順)
fn tiebreak<T: DagNode>(n: &T) -> (u64, T::Id) {
    (n.timestamp(), n.id())
}

/// DAG を決定論的トポロジカル順に並べる（戻り値は `nodes` へのインデックス列）
///
/// 親が先に来る。DAG に**存在しない**親参照は無視する（まだ取得できていない親は
/// 数えず、その要素を根として扱って迷子にしない）。万一循環があっても、
/// 残りを末尾に足して全件返す（黙って落とさない）。
pub fn topological_order<T: DagNode>(nodes: &[T]) -> Vec<usize> {
    let idx = index_of(nodes);
    let n = nodes.len();

    let mut in_degree = vec![0usize; n];
    let mut children: HashMap<usize, Vec<usize>> = HashMap::new();

    for (i, node) in nodes.iter().enumerate() {
        for parent in node.parents() {
            if let Some(&pi) = idx.get(parent) {
                in_degree[i] += 1;
                children.entry(pi).or_default().push(i);
            }
        }
    }

    // ready を (timestamp, id) 昇順に保つ
    let mut ready: Vec<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
    ready.sort_by(|&a, &b| tiebreak(&nodes[a]).cmp(&tiebreak(&nodes[b])));

    let mut order = Vec::with_capacity(n);
    while !ready.is_empty() {
        let next = ready.remove(0);
        order.push(next);

        if let Some(kids) = children.get(&next) {
            for &c in kids {
                in_degree[c] -= 1;
                if in_degree[c] == 0 {
                    let key = tiebreak(&nodes[c]);
                    let pos = ready
                        .binary_search_by(|&x| tiebreak(&nodes[x]).cmp(&key))
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
        rest.sort_by(|&a, &b| tiebreak(&nodes[a]).cmp(&tiebreak(&nodes[b])));
        order.extend(rest);
    }

    order
}

/// トポロジカル順を前提に、各要素の表示深さ（親からの最長距離）を求める
///
/// `order` の順で処理すれば親の深さが先に確定する。根は 0。
pub fn depths<T: DagNode>(nodes: &[T], order: &[usize]) -> HashMap<usize, usize> {
    let idx = index_of(nodes);
    let mut depth: HashMap<usize, usize> = HashMap::new();

    for &i in order {
        let d = nodes[i]
            .parents()
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

/// DAG の先端（子を持たない要素）。新しい要素はここへ親参照を張る
pub fn tips<T: DagNode>(nodes: &[T]) -> Vec<T::Id> {
    let has_child: HashSet<T::Id> = nodes
        .iter()
        .flat_map(|n| n.parents().iter().copied())
        .collect();
    nodes
        .iter()
        .map(|n| n.id())
        .filter(|id| !has_child.contains(id))
        .collect()
}

/// 各要素について、親のうち手元に無いものの数（`nodes` と同じ並び）
///
/// 0 でなければ「この前に、まだ届いていない要素がある」。
pub fn missing_parents<T: DagNode>(nodes: &[T]) -> Vec<usize> {
    let ids: HashSet<T::Id> = nodes.iter().map(|n| n.id()).collect();
    nodes
        .iter()
        .map(|n| n.parents().iter().filter(|p| !ids.contains(p)).count())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct N {
        id: u8,
        parents: Vec<u8>,
        ts: u64,
    }

    impl DagNode for N {
        type Id = u8;
        fn id(&self) -> u8 {
            self.id
        }
        fn parents(&self) -> &[u8] {
            &self.parents
        }
        fn timestamp(&self) -> u64 {
            self.ts
        }
    }

    fn n(id: u8, parents: &[u8], ts: u64) -> N {
        N { id, parents: parents.to_vec(), ts }
    }

    fn ids(nodes: &[N]) -> Vec<u8> {
        topological_order(nodes).into_iter().map(|i| nodes[i].id).collect()
    }

    /// 親子関係は時刻より優先する（遅れて届いた・時計のずれた親でも子より先）
    #[test]
    fn parents_come_first_even_with_a_later_timestamp() {
        let nodes = [n(2, &[1], 10), n(1, &[], 50)];
        assert_eq!(ids(&nodes), vec![1, 2]);
    }

    /// 同時に書かれたもの（同じ親）は時刻順、同時刻なら id 順
    #[test]
    fn concurrent_nodes_are_ordered_by_time_then_id() {
        let nodes = [n(1, &[], 0), n(4, &[1], 20), n(3, &[1], 10), n(2, &[1], 20), n(5, &[2, 3, 4], 30)];
        assert_eq!(ids(&nodes), vec![1, 3, 2, 4, 5]);
    }

    #[test]
    fn missing_parents_are_counted_and_do_not_hide_the_node() {
        let nodes = [n(2, &[1, 9], 10), n(1, &[], 0)];
        assert_eq!(missing_parents(&nodes), vec![1, 0]);
        assert_eq!(ids(&nodes), vec![1, 2], "欠けた親があっても並びに出る");
    }

    #[test]
    fn tips_are_nodes_without_children() {
        let nodes = [n(1, &[], 0), n(2, &[1], 1), n(3, &[1], 2)];
        let mut t = tips(&nodes);
        t.sort();
        assert_eq!(t, vec![2, 3]);
    }

    #[test]
    fn cycles_do_not_drop_nodes() {
        let nodes = [n(1, &[2], 0), n(2, &[1], 1), n(3, &[], 2)];
        assert_eq!(ids(&nodes).len(), 3);
    }
}
