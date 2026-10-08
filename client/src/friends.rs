//! 友だち（私信の相手）の一覧
//!
//! 表示名（あだ名）は**自分の端末にだけ**置く。網には出さない。
//! パスフレーズがあれば暗号化して保存する（押収されても誰と繋がっているか読めない）。

use crate::error::{ClientError, Result};
use crate::keys::KeyFiles;
use aether_core::crypto::identity::{Identity, NodeId};
use aether_core::crypto::x3dh::Invite;
use aether_core::storage::keystore::KeyStore;
use serde::{Deserialize, Serialize};

/// 友だちコードの接頭辞（QR にもこの形で入れる）
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

/// 貼り付けられた友だちコード（または ID だけ）を読んだもの
#[derive(Debug, Clone)]
pub struct FriendCode {
    pub node_id: NodeId,
    /// 招待。ID だけのときは `None`（こちらからは会話を始められず、相手から始めてもらう）
    pub invite: Option<Invite>,
}

/// 招待を友だちコードにする: `aether:<base64url>`
///
/// コードには相手がこちらへ初回の 1 通を送るための鍵（招待）が入る。招待は網に置かず、
/// このコードだけで手渡す（置いた時刻から在席を知られないため / [`aether_core::crypto::x3dh`]）。
/// 招待は使い捨てなので、**1 人に 1 つ**渡す。
pub fn friend_code(invite: &Invite) -> String {
    use base64::Engine;
    format!(
        "{}{}",
        FRIEND_URI_PREFIX,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(invite.to_bytes())
    )
}

/// 友だちコード（`aether:<base64url>`）か ID（`aether:<hex>` / hex）を読む
///
/// 招待の署名と期限はここでは確かめない（[`crate::AetherClient::accept_friend_code`] が確かめる）。
/// 貼り付けで改行や空白が混ざっても読めるよう、空白は取り除く。
pub fn parse_friend_code(input: &str) -> Result<FriendCode> {
    use base64::Engine;
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let body = compact.strip_prefix(FRIEND_URI_PREFIX).unwrap_or(&compact);
    if body.len() == 64 {
        return Ok(FriendCode {
            node_id: NodeId(crate::parse_hex32(body, "友だちの ID")?),
            invite: None,
        });
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| ClientError::invalid("友だちコードを読めません（途中で切れていないか確かめてください）"))?;
    let invite = Invite::from_bytes(&bytes)
        .map_err(|_| ClientError::invalid("友だちコードを読めません（途中で切れていないか確かめてください）"))?;
    Ok(FriendCode {
        node_id: invite.node_id,
        invite: Some(invite),
    })
}

/// 友だちコードの有効期間（30 日）。過ぎたコードでは会話を始められない
pub const FRIEND_CODE_TTL_SECS: u64 = 30 * 24 * 3600;

/// 新しい友だちコードを作る（招待の秘密は KeyStore に置き、相手から初回の 1 通が届いたら消す）
///
/// 網には何も出さない。呼ぶたびに別の招待になる。
pub fn create_friend_code(identity: &Identity, keystore: &KeyStore) -> Result<String> {
    let now = aether_core::protocol::hint::current_timestamp();
    // ついでに期限の切れた招待を片付ける
    keystore.prune_invites(now)?;
    let (invite, secrets) = aether_core::crypto::x3dh::create_invite(identity, now + FRIEND_CODE_TTL_SECS);
    keystore.save_invite_secrets(&invite.signed_prekey, &secrets)?;
    Ok(friend_code(&invite))
}

/// 相手の友だちコードを受け取る：招待を確かめて保存し、読んだコードを返す
///
/// ID だけのコードも受け付ける（その相手とは、相手から始めてもらう）。
pub fn accept_friend_code(keystore: &KeyStore, me: &NodeId, input: &str) -> Result<FriendCode> {
    let code = parse_friend_code(input)?;
    if code.node_id == *me {
        return Err(ClientError::invalid("自分自身は追加できません"));
    }
    if let Some(invite) = &code.invite {
        let now = aether_core::protocol::hint::current_timestamp();
        if now >= invite.expires_at {
            return Err(ClientError::invalid(
                "この友だちコードは期限が切れています（相手に新しいコードを作ってもらってください）",
            ));
        }
        invite.verify(&code.node_id, now).map_err(|_| {
            ClientError::invalid("友だちコードの署名が合いません（途中で書き換えられた可能性があります）")
        })?;
        keystore.save_peer_invite(&code.node_id, invite)?;
    }
    Ok(code)
}

/// 貼り付けられた宛先（`aether:<hex>` または hex）を NodeId にする
///
/// 友だちコード（招待入り）も受け付け、中の NodeId を返す。
pub fn parse_friend_id(input: &str) -> Result<NodeId> {
    Ok(parse_friend_code(input)?.node_id)
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
        let _lock = crate::keys::settings_lock();
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
        {
            let _lock = crate::keys::settings_lock();
            let hex_id = hex::encode(node_id.as_bytes());
            let mut friends = self.load_friends()?;
            let before = friends.len();
            friends.retain(|f| f.node_id != hex_id);
            if friends.len() == before {
                return Err(ClientError::invalid("その友だちは登録されていません"));
            }
            self.save_friends(&friends)?;
        }
        // delete_talk は自分でロックを取るので、ここでは外してから呼ぶ
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
        keys.append_talk_message(&id, crate::talks::TalkEnvelope::new(Vec::new(), b"hi".to_vec()).to_message(true))
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
    fn accepting_a_code_stores_the_invite_and_creating_one_stores_the_secret() {
        use aether_core::crypto::identity::Identity;
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(dir.path()).unwrap();
        let me = Identity::generate();
        let friend = Identity::generate();

        // 相手のコードを受け取る → 招待が保存され、次の送信で会話を始められる
        let friend_ks_dir = tempfile::tempdir().unwrap();
        let friend_ks = KeyStore::open(friend_ks_dir.path()).unwrap();
        let code = create_friend_code(&friend, &friend_ks).unwrap();
        let parsed = parse_friend_code(&code).unwrap();
        let invite = parsed.invite.clone().unwrap();
        assert!(
            friend_ks.load_invite_secrets(&invite.signed_prekey).unwrap().is_some(),
            "作った側は招待の秘密を持つ"
        );

        let accepted = accept_friend_code(&ks, &me.public_id(), &code).unwrap();
        assert_eq!(accepted.node_id, friend.public_id());
        assert_eq!(ks.load_peer_invite(&friend.public_id()).unwrap(), Some(invite));

        // 自分のコードは追加できない
        let mine = create_friend_code(&me, &ks).unwrap();
        assert!(accept_friend_code(&ks, &me.public_id(), &mine).is_err());
    }

    #[test]
    fn tampered_or_expired_codes_are_refused() {
        use aether_core::crypto::identity::Identity;
        use aether_core::crypto::x3dh::create_invite;
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(dir.path()).unwrap();
        let me = Identity::generate();
        let friend = Identity::generate();

        let (expired, _) = create_invite(&friend, 1_000);
        assert!(accept_friend_code(&ks, &me.public_id(), &friend_code(&expired)).is_err());

        let (mut forged, _) = create_invite(&friend, u64::MAX);
        forged.signed_prekey = [7; 32];
        assert!(accept_friend_code(&ks, &me.public_id(), &friend_code(&forged)).is_err());
        assert!(ks.load_peer_invite(&friend.public_id()).unwrap().is_none());
    }

    #[test]
    fn friend_code_roundtrips_and_tolerates_line_breaks() {
        let me = aether_core::crypto::identity::Identity::generate();
        let (invite, _) = aether_core::crypto::x3dh::create_invite(&me, 2_000_000_000);
        let code = friend_code(&invite);
        assert!(code.starts_with(FRIEND_URI_PREFIX));
        assert!(code.len() < 1800, "{} 文字", code.len());

        let parsed = parse_friend_code(&code).unwrap();
        assert_eq!(parsed.node_id, me.public_id());
        assert_eq!(parsed.invite, Some(invite.clone()));

        // メールやチャットで折り返されても読める
        let wrapped: String = code
            .as_bytes()
            .chunks(70)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n  ");
        assert_eq!(parse_friend_code(&wrapped).unwrap().invite, Some(invite));

        // 途中で切れたコードは読めない（黙って ID だけにしない）
        assert!(parse_friend_code(&code[..code.len() - 10]).is_err());
    }

    #[test]
    fn bare_ids_are_still_accepted_without_an_invite() {
        let hex_id = "ab".repeat(32);
        for input in [hex_id.clone(), format!("{}{}", FRIEND_URI_PREFIX, hex_id)] {
            let parsed = parse_friend_code(&input).unwrap();
            assert_eq!(parsed.node_id, NodeId([0xab; 32]));
            assert!(parsed.invite.is_none());
            assert_eq!(parse_friend_id(&input).unwrap(), NodeId([0xab; 32]));
        }
    }
}
