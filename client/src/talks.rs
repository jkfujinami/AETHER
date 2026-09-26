//! トーク履歴の保存
//!
//! 今までは画面（GUI の JS）のメモリ上にしか無く、再起動のたびに消えていた。
//! 友だち一覧・お気に入りの板と同じく `write_secure` で保存する
//! （パスフレーズがあれば暗号化。押収されても、パスフレーズ無しには読めない）。
//!
//! **送信状態（送信中・送信済み等）は保存しない。** 再起動をまたぐと
//! 「今まさに放流待ち」といった状態の意味が失われる。画面側は、保存された
//! 自分の発言を「送信済み」または「不明」として出す。

use crate::error::{ClientError, Result};
use crate::keys::KeyFiles;
use aether_core::crypto::identity::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 相手ごとに保持する上限。これを超えたら古い方から捨てる
const MAX_MESSAGES_PER_PEER: usize = 500;

/// 1件のトーク
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TalkMessage {
    /// 自分が送ったか（`false` なら相手からの受信）
    pub mine: bool,
    pub text: String,
    /// 送受信した時刻（画面がそのまま表示に使う。単位は画面側に合わせて ms）
    pub time: u64,
}

impl KeyFiles {
    fn talks_path(&self) -> std::path::PathBuf {
        self.data_dir().join("talks.bin")
    }

    /// 全員分のトーク履歴を読む（相手の NodeId の hex がキー）
    pub fn load_talks(&self) -> Result<HashMap<String, Vec<TalkMessage>>> {
        match self.read_secure(&self.talks_path())? {
            Some(json) => serde_json::from_slice(&json)
                .map_err(|e| ClientError::invalid(format!("トーク履歴が壊れています: {}", e))),
            None => Ok(HashMap::new()),
        }
    }

    fn save_talks(&self, talks: &HashMap<String, Vec<TalkMessage>>) -> Result<()> {
        let json = serde_json::to_vec(talks).expect("TalkMessage は直列化できる");
        self.write_secure(&self.talks_path(), &json)
    }

    /// 1件のトークを追記する
    ///
    /// 相手ごとに [`MAX_MESSAGES_PER_PEER`] 件を超えたら、古い方から捨てる。
    pub fn append_talk_message(&self, node_id: &NodeId, message: TalkMessage) -> Result<()> {
        let hex_id = hex::encode(node_id.as_bytes());
        let mut talks = self.load_talks()?;
        let list = talks.entry(hex_id).or_default();
        list.push(message);
        if list.len() > MAX_MESSAGES_PER_PEER {
            let drop_count = list.len() - MAX_MESSAGES_PER_PEER;
            list.drain(0..drop_count);
        }
        self.save_talks(&talks)
    }

    /// 相手とのトーク履歴を消す
    ///
    /// 友だちを削除したときに呼ぶ（相手の情報が残っていると、削除した意味が薄れる）。
    pub fn delete_talk(&self, node_id: &NodeId) -> Result<()> {
        let hex_id = hex::encode(node_id.as_bytes());
        let mut talks = self.load_talks()?;
        if talks.remove(&hex_id).is_some() {
            self.save_talks(&talks)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn talks_roundtrip_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), Some("pass".into()));
        let id = NodeId([3; 32]);
        keys.append_talk_message(&id, TalkMessage { mine: true, text: "やっほー".into(), time: 1 })
            .unwrap();
        keys.append_talk_message(&id, TalkMessage { mine: false, text: "おーい".into(), time: 2 })
            .unwrap();

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
            keys.append_talk_message(&id, TalkMessage { mine: true, text: format!("m{}", i), time: i as u64 })
                .unwrap();
        }
        let talks = keys.load_talks().unwrap();
        let hex_id = hex::encode(id.as_bytes());
        let list = &talks[&hex_id];
        assert_eq!(list.len(), MAX_MESSAGES_PER_PEER);
        // 古い方（0..10）が捨てられ、先頭は m10 になっている
        assert_eq!(list[0].text, "m10");
    }

    #[test]
    fn delete_talk_removes_history() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        let id = NodeId([5; 32]);
        keys.append_talk_message(&id, TalkMessage { mine: true, text: "hi".into(), time: 1 })
            .unwrap();
        keys.delete_talk(&id).unwrap();
        assert!(keys.load_talks().unwrap().is_empty());
        // 存在しない相手を消してもエラーにしない
        keys.delete_talk(&id).unwrap();
    }
}
