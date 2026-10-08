//! トーク（私信）の本文形式と履歴
//!
//! # 発言の DAG
//!
//! 私信は届く順が書いた順と一致しない（相手がオフラインの間に送った発言は後から
//! まとめて届く・取り寄せ直しで追い越す）。届いた順に並べると会話の前後が入れ替わり、
//! 途中の発言が届いていないことにも気づけない。
//!
//! そこで各発言に「書いた時点で見ていた会話の先端（自分と相手の最新の発言）」を
//! 親として持たせ、掲示板のスレッドと同じ決定論的トポロジカル順（[`aether_core::dag`]）で
//! 並べる。親が手元に無い発言は「この前に届いていない発言がある」と分かる。
//!
//! 親・ID・書いた時刻は**ラチェットで封じた本文の中**に入る（[`TalkEnvelope`]）。
//! 網からは見えず、見えるのは相手だけ。
//!
//! # 履歴の保存
//!
//! 友だち一覧・お気に入りの板と同じく `write_secure` で保存する
//! （パスフレーズがあれば暗号化。押収されても、パスフレーズ無しには読めない）。
//! 保存するのは送り終えた発言と受け取った発言だけ（送信中・失敗した発言は保存しない。
//! 相手に届いていない発言を親にすると、相手の側で「欠けがある」と出続けるため）。

use crate::error::{ClientError, Result};
use crate::keys::KeyFiles;
use aether_core::crypto::identity::NodeId;
use aether_core::dag::{self, DagNode};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{HashMap, HashSet};

/// 相手ごとに保持する上限。これを超えたら古い方から捨てる
const MAX_MESSAGES_PER_PEER: usize = 500;

/// 本文の先頭の目印（これが無い本文は DAG 以前の古い形式として全体を本文とみなす）
const ENVELOPE_MAGIC: &[u8; 5] = b"AETK\x01";

/// 1 つの発言が参照する親の上限（先端はふつう 1〜2 個。多すぎる親は受け付けない）
const MAX_PARENTS: usize = 8;

/// 発言の ID（乱数 16 バイト）
pub type TalkId = [u8; 16];

/// 私信の平文（ラチェットで封じる中身）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TalkEnvelope {
    pub id: TalkId,
    /// 書いた時点で見ていた会話の先端
    pub parents: Vec<TalkId>,
    /// 書いた時刻（UNIX ミリ秒、書き手の時計）
    pub sent_at: u64,
    pub body: Vec<u8>,
}

impl TalkEnvelope {
    /// 新しい発言を作る（ID は乱数、時刻は今）
    pub fn new(mut parents: Vec<TalkId>, body: Vec<u8>) -> Self {
        parents.sort();
        parents.dedup();
        parents.truncate(MAX_PARENTS);
        Self {
            id: rand::random(),
            parents,
            sent_at: now_ms(),
            body,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = ENVELOPE_MAGIC.to_vec();
        out.extend(bincode::serialize(self).expect("TalkEnvelope は直列化できる"));
        out
    }

    /// 本文を読む。目印が無い・壊れている本文は古い形式として全体を本文にする
    /// （`None`。発言を落とさない）
    pub fn decode(plain: &[u8]) -> Option<Self> {
        let rest = plain.strip_prefix(ENVELOPE_MAGIC.as_slice())?;
        let env: Self = bincode::deserialize(rest).ok()?;
        (env.parents.len() <= MAX_PARENTS).then_some(env)
    }

    /// 履歴の 1 件にする
    pub fn to_message(&self, mine: bool) -> TalkMessage {
        TalkMessage {
            mine,
            text: String::from_utf8_lossy(&self.body).into_owned(),
            time: self.sent_at,
            id: Some(hex::encode(self.id)),
            parents: self.parents.iter().map(hex::encode).collect(),
            missing_before: false,
        }
    }
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 1件のトーク
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TalkMessage {
    /// 自分が送ったか（`false` なら相手からの受信）
    pub mine: bool,
    pub text: String,
    /// 書いた時刻（UNIX ミリ秒、書き手の時計）。DAG 以前の古い発言は送受信した時刻
    pub time: u64,
    /// 発言の ID（hex）。DAG 以前の古い発言は `None`
    #[serde(default)]
    pub id: Option<String>,
    /// 書いた時点で見ていた会話の先端（hex）
    #[serde(default)]
    pub parents: Vec<String>,
    /// この前に、まだ届いていない発言がある（親の一部が手元に無い）。読み出すときに求める
    #[serde(default)]
    pub missing_before: bool,
}

/// 並べるための DAG の要素
struct Node {
    id: TalkId,
    parents: Vec<TalkId>,
    time: u64,
}

impl DagNode for Node {
    type Id = TalkId;
    fn id(&self) -> TalkId {
        self.id
    }
    fn parents(&self) -> &[TalkId] {
        &self.parents
    }
    fn timestamp(&self) -> u64 {
        self.time
    }
}

fn parse_id(s: &str) -> Option<TalkId> {
    hex::decode(s).ok()?.try_into().ok()
}

/// 履歴の 1 件を DAG の要素にする（古い発言は内容から作った ID・親なし）
fn node_of(i: usize, m: &TalkMessage) -> Node {
    let id = m.id.as_deref().and_then(parse_id).unwrap_or_else(|| {
        let h = sha2::Sha256::new()
            .chain_update(b"aether_talk_legacy_v1")
            .chain_update((i as u64).to_be_bytes())
            .chain_update([m.mine as u8])
            .chain_update(m.time.to_be_bytes())
            .chain_update(m.text.as_bytes())
            .finalize();
        h[..16].try_into().expect("16 バイト")
    });
    Node {
        id,
        parents: m.parents.iter().filter_map(|p| parse_id(p)).collect(),
        time: m.time,
    }
}

/// DAG の順に並べ、欠けの印を付ける
fn arrange(list: Vec<TalkMessage>) -> Vec<TalkMessage> {
    let nodes: Vec<Node> = list.iter().enumerate().map(|(i, m)| node_of(i, m)).collect();
    let missing = dag::missing_parents(&nodes);
    let mut slots: Vec<Option<TalkMessage>> = list.into_iter().map(Some).collect();
    dag::topological_order(&nodes)
        .into_iter()
        .map(|i| {
            let mut m = slots[i].take().expect("並びは各要素を 1 度だけ返す");
            m.missing_before = missing[i] > 0;
            m
        })
        .collect()
}

impl KeyFiles {
    fn talks_path(&self) -> std::path::PathBuf {
        self.data_dir().join("talks.bin")
    }

    /// 保存したままの並び（DAG の順にはしていない）
    fn load_talks_raw(&self) -> Result<HashMap<String, Vec<TalkMessage>>> {
        match self.read_secure(&self.talks_path())? {
            Some(json) => serde_json::from_slice(&json)
                .map_err(|e| ClientError::invalid(format!("トーク履歴が壊れています: {}", e))),
            None => Ok(HashMap::new()),
        }
    }

    /// 全員分のトーク履歴を読む（相手の NodeId の hex がキー）。発言は DAG の順に並ぶ
    pub fn load_talks(&self) -> Result<HashMap<String, Vec<TalkMessage>>> {
        Ok(self
            .load_talks_raw()?
            .into_iter()
            .map(|(peer, list)| (peer, arrange(list)))
            .collect())
    }

    /// 1 人とのトーク履歴を読む。発言は DAG の順に並ぶ
    pub fn load_talk(&self, node_id: &NodeId) -> Result<Vec<TalkMessage>> {
        Ok(self
            .load_talks()?
            .remove(&hex::encode(node_id.as_bytes()))
            .unwrap_or_default())
    }

    fn save_talks(&self, talks: &HashMap<String, Vec<TalkMessage>>) -> Result<()> {
        let json = serde_json::to_vec(talks).expect("TalkMessage は直列化できる");
        self.write_secure(&self.talks_path(), &json)
    }

    /// 1件のトークを追記する
    ///
    /// 同じ ID の発言が既にあれば何もしない（再配送で 2 度届いても 1 つにまとめる）。
    /// 相手ごとに [`MAX_MESSAGES_PER_PEER`] 件を超えたら、DAG の順で古い方から捨てる。
    pub fn append_talk_message(&self, node_id: &NodeId, message: TalkMessage) -> Result<()> {
        let _lock = crate::keys::settings_lock();
        let hex_id = hex::encode(node_id.as_bytes());
        let mut talks = self.load_talks_raw()?;
        let list = talks.entry(hex_id).or_default();
        if message.id.is_some() && list.iter().any(|m| m.id == message.id) {
            return Ok(());
        }
        list.push(message);
        if list.len() > MAX_MESSAGES_PER_PEER {
            let mut arranged = arrange(std::mem::take(list));
            arranged.drain(0..arranged.len() - MAX_MESSAGES_PER_PEER);
            *list = arranged;
        }
        self.save_talks(&talks)
    }

    /// 次に書く発言の親（会話の先端）
    ///
    /// ID を持つ発言（DAG 以後）だけから選ぶ。古い発言の ID は内容から作った仮のもので、
    /// 相手の手元には無い（親にすると相手の側で欠けと出る）。
    pub fn talk_heads(&self, node_id: &NodeId) -> Result<Vec<TalkId>> {
        let list = self
            .load_talks_raw()?
            .remove(&hex::encode(node_id.as_bytes()))
            .unwrap_or_default();
        let nodes: Vec<Node> = list
            .iter()
            .enumerate()
            .filter(|(_, m)| m.id.as_deref().and_then(parse_id).is_some())
            .map(|(i, m)| node_of(i, m))
            .collect();
        let time: HashMap<TalkId, u64> = nodes.iter().map(|n| (n.id, n.time)).collect();
        let mut heads: Vec<TalkId> = dag::tips(&nodes)
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        // 多すぎるときは新しいものを残す
        heads.sort_by_key(|id| std::cmp::Reverse(time[id]));
        heads.truncate(MAX_PARENTS);
        Ok(heads)
    }

    /// 相手とのトーク履歴を消す
    ///
    /// 友だちを削除したときに呼ぶ（相手の情報が残っていると、削除した意味が薄れる）。
    pub fn delete_talk(&self, node_id: &NodeId) -> Result<()> {
        let _lock = crate::keys::settings_lock();
        let hex_id = hex::encode(node_id.as_bytes());
        let mut talks = self.load_talks_raw()?;
        if talks.remove(&hex_id).is_some() {
            self.save_talks(&talks)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy(mine: bool, text: &str, time: u64) -> TalkMessage {
        TalkMessage { mine, text: text.into(), time, id: None, parents: Vec::new(), missing_before: false }
    }

    fn texts(list: &[TalkMessage]) -> Vec<&str> {
        list.iter().map(|m| m.text.as_str()).collect()
    }

    #[test]
    fn talks_roundtrip_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), Some("pass".into()));
        let id = NodeId([3; 32]);
        keys.append_talk_message(&id, legacy(true, "やっほー", 1)).unwrap();
        keys.append_talk_message(&id, legacy(false, "おーい", 2)).unwrap();

        let raw = std::fs::read(dir.path().join("talks.bin")).unwrap();
        assert!(raw.starts_with(b"AESF"), "暗号化されていない");
        assert!(!String::from_utf8_lossy(&raw).contains("やっほー"));

        let talks = keys.load_talks().unwrap();
        let hex_id = hex::encode(id.as_bytes());
        assert_eq!(talks[&hex_id].len(), 2);
        assert_eq!(talks[&hex_id][0].text, "やっほー");
        assert!(KeyFiles::new(dir.path(), Some("wrong".into())).load_talks().is_err());
    }

    #[test]
    fn talks_trim_old_messages_per_peer() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        let id = NodeId([4; 32]);
        for i in 0..(MAX_MESSAGES_PER_PEER + 10) {
            keys.append_talk_message(&id, legacy(true, &format!("m{}", i), i as u64)).unwrap();
        }
        let list = keys.load_talk(&id).unwrap();
        assert_eq!(list.len(), MAX_MESSAGES_PER_PEER);
        // 古い方（0..10）が捨てられ、先頭は m10 になっている
        assert_eq!(list[0].text, "m10");
    }

    /// 同時に保存しても失敗せず、どの発言も消えない（GUI は保存を並行に呼ぶ）
    #[test]
    fn concurrent_appends_keep_every_message() {
        let dir = tempfile::tempdir().unwrap();
        let id = NodeId([6; 32]);
        std::thread::scope(|s| {
            for t in 0..8 {
                let path = dir.path();
                s.spawn(move || {
                    let keys = KeyFiles::new(path, None);
                    for i in 0..10 {
                        keys.append_talk_message(&id, legacy(true, &format!("{}-{}", t, i), i))
                            .expect("同時に保存しても失敗しない");
                    }
                });
            }
        });
        let talks = KeyFiles::new(dir.path(), None).load_talks().unwrap();
        assert_eq!(talks[&hex::encode(id.as_bytes())].len(), 80, "同時の保存で発言が消えた");
        let leftovers = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().contains("tmp-"))
            .count();
        assert_eq!(leftovers, 0, "一時ファイルが残っている");
    }

    #[test]
    fn delete_talk_removes_history() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        let id = NodeId([5; 32]);
        keys.append_talk_message(&id, legacy(true, "hi", 1)).unwrap();
        keys.delete_talk(&id).unwrap();
        assert!(keys.load_talks().unwrap().is_empty());
        // 存在しない相手を消してもエラーにしない
        keys.delete_talk(&id).unwrap();
    }

    #[test]
    fn envelope_roundtrip_and_legacy_fallback() {
        let env = TalkEnvelope::new(vec![[2; 16], [1; 16], [2; 16]], "やあ".as_bytes().to_vec());
        assert_eq!(env.parents, vec![[1; 16], [2; 16]], "親は整列・重複なし");
        assert_eq!(TalkEnvelope::decode(&env.encode()), Some(env));
        assert_eq!(TalkEnvelope::decode("ただの文".as_bytes()), None, "古い形式は本文そのもの");
        assert_eq!(TalkEnvelope::decode(b"AETK\x01broken"), None, "壊れていても落とさない");
    }

    /// オフラインの間に書かれた相手の発言は、遅れて届いても書かれた位置に並ぶ
    #[test]
    fn late_arrivals_are_placed_where_they_were_written() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        let peer = NodeId([7; 32]);

        // 自分「元気？」→ 相手はそれを見て「元気だよ」を書いた（が届くのが遅れた）
        let mine1 = TalkEnvelope::new(vec![], b"genki?".to_vec());
        keys.append_talk_message(&peer, mine1.to_message(true)).unwrap();
        let mut theirs = TalkEnvelope::new(vec![mine1.id], b"genki dayo".to_vec());
        theirs.sent_at = mine1.sent_at + 1_000;

        // 返事が届く前に、自分はもう 1 通送った（親は自分の 1 通目だけ）
        let mut mine2 = TalkEnvelope::new(keys.talk_heads(&peer).unwrap(), b"oi".to_vec());
        mine2.sent_at = mine1.sent_at + 60_000;
        assert_eq!(mine2.parents, vec![mine1.id]);
        keys.append_talk_message(&peer, mine2.to_message(true)).unwrap();

        // 返事が届く。届いた順（最後）ではなく、書かれた時刻の位置に入る
        keys.append_talk_message(&peer, theirs.to_message(false)).unwrap();
        let list = keys.load_talk(&peer).unwrap();
        assert_eq!(texts(&list), vec!["genki?", "genki dayo", "oi"]);

        // 次の発言は両方の先端を親にする（分岐が収束する）
        let mut heads = keys.talk_heads(&peer).unwrap();
        heads.sort();
        let mut want = vec![theirs.id, mine2.id];
        want.sort();
        assert_eq!(heads, want);
    }

    #[test]
    fn a_reply_whose_parent_has_not_arrived_is_marked_and_duplicates_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        let peer = NodeId([8; 32]);

        let first = TalkEnvelope::new(vec![], b"1".to_vec());
        let second = TalkEnvelope::new(vec![first.id], b"2".to_vec());
        keys.append_talk_message(&peer, second.to_message(false)).unwrap();
        keys.append_talk_message(&peer, second.to_message(false)).unwrap();

        let list = keys.load_talk(&peer).unwrap();
        assert_eq!(list.len(), 1, "同じ発言は 1 つにまとめる");
        assert!(list[0].missing_before, "親が届いていない");

        keys.append_talk_message(&peer, first.to_message(false)).unwrap();
        let list = keys.load_talk(&peer).unwrap();
        assert_eq!(texts(&list), vec!["1", "2"]);
        assert!(list.iter().all(|m| !m.missing_before), "親が届けば欠けは消える");
    }

    #[test]
    fn legacy_messages_are_not_used_as_parents() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        let peer = NodeId([9; 32]);
        keys.append_talk_message(&peer, legacy(false, "old", 1)).unwrap();
        assert!(keys.talk_heads(&peer).unwrap().is_empty(), "相手の手元に無い仮の ID を親にしない");
    }
}
