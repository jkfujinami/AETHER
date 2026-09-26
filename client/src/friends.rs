//! 友だち（私信の相手）の一覧
//!
//! 表示名（あだ名）は**自分の端末にだけ**置く。網には出さない。
//! パスフレーズがあれば暗号化して保存する（押収されても誰と繋がっているか読めない）。

use crate::error::{ClientError, Result};
use crate::keys::KeyFiles;
use aether_core::crypto::identity::NodeId;
use serde::{Deserialize, Serialize};

/// 友だちの共有用 URI の接頭辞（QR にもこの形で入れる）
pub const FRIEND_URI_PREFIX: &str = "aether:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Friend {
    /// 相手の NodeId（hex）
    pub node_id: String,
    /// 自分だけが見る表示名
    pub nickname: String,
    pub added_at: u64,
}

impl Friend {
    pub fn node_id(&self) -> Result<NodeId> {
        Ok(NodeId(crate::parse_hex32(&self.node_id, "友だちの NodeId")?))
    }
}

/// 自分の宛先を共有する文字列（QR の中身）
pub fn friend_uri(node_id: &NodeId) -> String {
    format!("{}{}", FRIEND_URI_PREFIX, hex::encode(node_id.as_bytes()))
}

/// 貼り付けられた宛先（`aether:<hex>` または hex）を NodeId にする
pub fn parse_friend_id(input: &str) -> Result<NodeId> {
    let s = input.trim();
    let hex_part = s.strip_prefix(FRIEND_URI_PREFIX).unwrap_or(s);
    Ok(NodeId(crate::parse_hex32(hex_part, "友だちの ID")?))
}

impl KeyFiles {
    fn friends_path(&self) -> std::path::PathBuf {
        self.data_dir().join("friends.bin")
    }

    /// 友だち一覧を読む（無ければ空）
    pub fn load_friends(&self) -> Result<Vec<Friend>> {
        match self.read_secure(&self.friends_path())? {
            Some(json) => serde_json::from_slice(&json)
                .map_err(|e| ClientError::invalid(format!("友だち一覧が壊れています: {}", e))),
            None => Ok(Vec::new()),
        }
    }

    fn save_friends(&self, friends: &[Friend]) -> Result<()> {
        let json = serde_json::to_vec(friends).expect("Friend は直列化できる");
        self.write_secure(&self.friends_path(), &json)
    }

    /// 友だちを追加する（同じ相手なら表示名を上書き）
    pub fn add_friend(&self, node_id: &NodeId, nickname: &str) -> Result<Friend> {
        let nickname = nickname.trim();
        if nickname.is_empty() {
            return Err(ClientError::invalid("表示名を入れてください"));
        }
        let hex_id = hex::encode(node_id.as_bytes());
        let mut friends = self.load_friends()?;
        friends.retain(|f| f.node_id != hex_id);
        let friend = Friend {
            node_id: hex_id,
            nickname: nickname.to_string(),
            added_at: aether_core::protocol::hint::current_timestamp(),
        };
        friends.push(friend.clone());
        self.save_friends(&friends)?;
        Ok(friend)
    }

    /// 友だちを削除する
    ///
    /// トーク履歴も一緒に消す（相手の記録だけ残っていると、削除した意味が薄れる）。
    /// 受信中の購読から即座に外す API は無いので、実際に受信対象から外れるのは
    /// 次回の接続から（呼び出し側の画面でその旨を示すこと）。
    pub fn remove_friend(&self, node_id: &NodeId) -> Result<()> {
        let hex_id = hex::encode(node_id.as_bytes());
        let mut friends = self.load_friends()?;
        let before = friends.len();
        friends.retain(|f| f.node_id != hex_id);
        if friends.len() == before {
            return Err(ClientError::invalid("その友だちは登録されていません"));
        }
        self.save_friends(&friends)?;
        self.delete_talk(node_id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn friends_roundtrip_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), Some("pass".into()));
        let id = NodeId([7; 32]);
        keys.add_friend(&id, "たろう").unwrap();

        let raw = std::fs::read(dir.path().join("friends.bin")).unwrap();
        assert!(raw.starts_with(b"AESF"), "暗号化されていない");
        assert!(!String::from_utf8_lossy(&raw).contains("たろう"));

        let friends = keys.load_friends().unwrap();
        assert_eq!(friends.len(), 1);
        assert_eq!(friends[0].nickname, "たろう");
        assert!(KeyFiles::new(dir.path(), Some("wrong".into())).load_friends().is_err());
    }

    #[test]
    fn remove_friend_deletes_friend_and_talk_history() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        let id = NodeId([8; 32]);
        keys.add_friend(&id, "たろう").unwrap();
        keys.append_talk_message(&id, crate::talks::TalkMessage { mine: true, text: "hi".into(), time: 1 })
            .unwrap();

        keys.remove_friend(&id).unwrap();

        assert!(keys.load_friends().unwrap().is_empty());
        assert!(keys.load_talks().unwrap().is_empty());
    }

    #[test]
    fn remove_friend_errs_if_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        assert!(keys.remove_friend(&NodeId([1; 32])).is_err());
    }

    #[test]
    fn friend_uri_roundtrip() {
        let id = NodeId([9; 32]);
        assert_eq!(parse_friend_id(&friend_uri(&id)).unwrap(), id);
        assert_eq!(parse_friend_id(&hex::encode(id.as_bytes())).unwrap(), id);
    }
}
