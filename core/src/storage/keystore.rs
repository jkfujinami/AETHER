//! KeyStore — 連絡先ごとの Double Ratchet 状態を永続化する (Phase 3-1)
//!
//! ラチェットは**状態を持つ**：送受信チェーン鍵、DH 鍵ペア、取りこぼし鍵。
//! プロセスをまたいで会話を続けるには、これを連絡先ごとにディスクへ保存する。
//!
//! # 押収との関係
//!
//! KeyStore はディスクに残るので、**押収時点の状態は読まれうる**。
//! Double Ratchet の前方秘匿が守るのは「過去に**送受信し終えた**メッセージ」で、
//! それらの鍵は使用後に破棄され KeyStore には残らない。KeyStore に残るのは
//! 「これから使う鍵（現在のチェーン鍵）」だけ。値はパスフレーズ由来鍵で暗号化できる
//! （[`KeyStore::open_encrypted`]）。
//!
//! # sled のキーも隠す
//!
//! 値を暗号化しても、**sled のキーは平文のまま**ディスクに残る。キーに連絡先の NodeId を
//! そのまま使うと、パスフレーズ無しで友だちの一覧が読めてしまう。そこでキーは
//! `HMAC(blind_key, 用途 ‖ ID)` にする（[`KeyStore::slot`]）。`blind_key` は暗号化時は
//! 暗号鍵から導き、平文時は乱数をメタツリーに置く。

use crate::crypto::identity::NodeId;
use crate::crypto::session::Session;
use crate::crypto::x3dh::{Invite, InviteSecrets};
use crate::error::{AetherError, Result};
use crate::storage::at_rest;
use sled::Db;
use std::path::Path;

/// メタ情報（ソルト・カナリア）を置く別ツリー。main ツリーの `len()` に混ざらない
const META_TREE: &str = "aether_keystore_meta";
const CANARY_PLAINTEXT: &[u8] = b"aether-keystore-canary-v1";

/// 自分が渡した招待の秘密（X3DH の Bob 役）を置く別ツリー
const INVITE_TREE: &str = "aether_keystore_invites";
/// 受け取った相手の招待（初回接触に使う）を置く別ツリー
const PEER_INVITE_TREE: &str = "aether_keystore_peer_invites";
/// 以前の、網に置いていたプレキー束の秘密。開くときに消す
const LEGACY_PREKEY_TREE: &str = "aether_keystore_prekeys";

/// 招待の期限を過ぎても秘密を残す期間（期限の前に送られ、遅れて届いた初回メッセージのため）。
/// 本体の TTL（既定 1 週間）より長くする
pub const INVITE_GRACE_SECS: u64 = 8 * 24 * 3600;

/// 処理済みメッセージの目印を置く別ツリー（再配送・リプレイで同じ私信を二度開かないため）
const SEEN_TREE: &str = "aether_keystore_seen";

/// 平文モードの blind_key をメタツリーに置くときのキー
const BLIND_KEY_NAME: &[u8] = b"blind";

/// 処理済みの目印を残す期間。本体の TTL（既定 1 週間）より長くする。
/// これより古い本体は保持者から消えているので、再配送されても取り寄せられない。
pub const SEEN_RETENTION_SECS: u64 = 8 * 24 * 3600;

/// 連絡先 NodeId → 前方秘匿セッション（方向別 Double Ratchet）
///
/// `cipher_key` があれば保存時に値を暗号化する（押収対策 / 保存時暗号化）。
pub struct KeyStore {
    db: Db,
    cipher_key: Option<[u8; 32]>,
    /// sled のキーを隠す HMAC 鍵（モジュール先頭の説明を参照）
    blind_key: [u8; 32],
}

impl KeyStore {
    /// 指定パスに KeyStore を開く（**平文**・テストや暗号化しない場合）
    pub fn open(path: &Path) -> Result<Self> {
        let db = sled::open(path).map_err(|e| AetherError::Storage(e.to_string()))?;
        drop_legacy_trees(&db)?;
        let blind_key = Self::plaintext_blind_key(&db)?;
        Ok(Self { db, cipher_key: None, blind_key })
    }

    /// パスフレーズで**保存時暗号化**した KeyStore を開く（3-1・押収対策）
    ///
    /// 値は全て ChaCha20-Poly1305 で暗号化して保存する。鍵はパスフレーズを
    /// Argon2id で伸ばして作る（ソルトは初回に生成して保持）。押収されても
    /// パスフレーズ無しには連絡先のラチェット状態を読めない。
    /// カナリアで**誤ったパスフレーズを検出**して拒否する。
    pub fn open_encrypted(path: &Path, passphrase: &str) -> Result<Self> {
        let db = sled::open(path).map_err(|e| AetherError::Storage(e.to_string()))?;
        let key = at_rest::unlock_db(&db, passphrase, META_TREE, CANARY_PLAINTEXT)?;
        drop_legacy_trees(&db)?;
        let blind_key = derive_blind_key(&key);
        Ok(Self {
            db,
            cipher_key: Some(key),
            blind_key,
        })
    }

    /// 平文モードの blind_key（初回に乱数を作ってメタツリーに置く）
    ///
    /// 平文モードは押収に耐えないが、キーの形を暗号化モードと揃えておく。
    fn plaintext_blind_key(db: &Db) -> Result<[u8; 32]> {
        let meta = db
            .open_tree(META_TREE)
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        if let Some(v) = meta
            .get(BLIND_KEY_NAME)
            .map_err(|e| AetherError::Storage(e.to_string()))?
            && let Ok(k) = <[u8; 32]>::try_from(v.as_ref())
        {
            return Ok(k);
        }
        let k: [u8; 32] = rand::random();
        meta.insert(BLIND_KEY_NAME, &k[..])
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(k)
    }

    /// 用途 `domain` の ID `id` を置く sled のキー（平文の ID をディスクに残さない）
    fn slot(&self, domain: &[u8], id: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&self.blind_key)
            .expect("HMAC は任意長の鍵を取れる");
        mac.update(domain);
        mac.update(id);
        mac.finalize().into_bytes().into()
    }

    fn session_slot(&self, contact: &NodeId) -> [u8; 32] {
        self.slot(b"aether_keystore_session_v1", contact.as_bytes())
    }

    /// 保存時暗号化が有効か
    pub fn is_encrypted(&self) -> bool {
        self.cipher_key.is_some()
    }

    fn encode(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match &self.cipher_key {
            Some(k) => at_rest::encrypt_value(k, plaintext),
            None => Ok(plaintext.to_vec()),
        }
    }

    fn decode(&self, raw: &[u8]) -> Result<Vec<u8>> {
        match &self.cipher_key {
            Some(k) => at_rest::decrypt_value(k, raw),
            None => Ok(raw.to_vec()),
        }
    }

    /// 連絡先のセッション状態を保存する（上書き・暗号化有効なら暗号化して保存）
    pub fn save(&self, contact: &NodeId, session: &Session) -> Result<()> {
        let bytes = bincode::serialize(session)
            .map_err(|e| AetherError::Serialization(e.to_string()))?;
        let stored = self.encode(&bytes)?;
        self.db
            .insert(self.session_slot(contact), stored)
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        // 旧形式（NodeId をそのままキーにしていた頃）の残りを消す
        let _ = self.db.remove(contact.as_bytes());
        Ok(())
    }

    /// 連絡先のセッション状態を読む。無ければ `None`
    pub fn load(&self, contact: &NodeId) -> Result<Option<Session>> {
        let slot = self.session_slot(contact);
        let (raw, legacy) = match self
            .db
            .get(slot)
            .map_err(|e| AetherError::Storage(e.to_string()))?
        {
            Some(raw) => (raw, false),
            // 旧形式のキーで保存されたものは読んでから新形式へ移す
            None => match self
                .db
                .get(contact.as_bytes())
                .map_err(|e| AetherError::Storage(e.to_string()))?
            {
                Some(raw) => (raw, true),
                None => return Ok(None),
            },
        };
        let bytes = self.decode(&raw)?;
        // 形式の違う古いセッション（方向別 2 本のラチェットだった頃）は読めない。
        // 捨てて「セッション無し」とし、次の送信で X3DH からやり直させる
        let Ok(session) = bincode::deserialize::<Session>(&bytes) else {
            self.remove(contact)?;
            return Ok(None);
        };
        if legacy {
            self.save(contact, &session)?;
        }
        Ok(Some(session))
    }

    fn tree(&self, name: &str) -> Result<sled::Tree> {
        self.db
            .open_tree(name)
            .map_err(|e| AetherError::Storage(e.to_string()))
    }

    fn invite_slot(&self, invite_key: &[u8; 32]) -> [u8; 32] {
        self.slot(b"aether_keystore_invite_v1", invite_key)
    }

    fn peer_invite_slot(&self, peer: &NodeId) -> [u8; 32] {
        self.slot(b"aether_keystore_peer_invite_v1", peer.as_bytes())
    }

    /// 自分が作った招待の秘密を保存する（X3DH の Bob 役）
    ///
    /// `invite_key` は招待の署名付きプレキー（公開）。相手の初回メッセージが
    /// [`InitialMessage::invite_key`] でどの招待を使ったかを示すので、それで引く。
    ///
    /// [`InitialMessage::invite_key`]: crate::crypto::x3dh::InitialMessage::invite_key
    pub fn save_invite_secrets(&self, invite_key: &[u8; 32], secrets: &InviteSecrets) -> Result<()> {
        let bytes = bincode::serialize(secrets)
            .map_err(|e| AetherError::Serialization(e.to_string()))?;
        self.tree(INVITE_TREE)?
            .insert(self.invite_slot(invite_key), self.encode(&bytes)?)
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(())
    }

    /// 招待の秘密を読む。使い終えて消した・作っていない招待なら `None`
    pub fn load_invite_secrets(&self, invite_key: &[u8; 32]) -> Result<Option<InviteSecrets>> {
        let Some(raw) = self
            .tree(INVITE_TREE)?
            .get(self.invite_slot(invite_key))
            .map_err(|e| AetherError::Storage(e.to_string()))?
        else {
            return Ok(None);
        };
        let secrets = bincode::deserialize(&self.decode(&raw)?)
            .map_err(|e| AetherError::Storage(format!("Corrupt invite secrets: {}", e)))?;
        Ok(Some(secrets))
    }

    /// 招待の秘密を消す（初回接触を受けてセッションを立てたら呼ぶ。以後その初回秘密は
    /// 誰にも復元できない ＝ 初回メッセージの前方秘匿）
    pub fn remove_invite_secrets(&self, invite_key: &[u8; 32]) -> Result<()> {
        self.tree(INVITE_TREE)?
            .remove(self.invite_slot(invite_key))
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(())
    }

    /// 受け取った相手の招待を保存する（同じ相手なら新しいもので上書き）
    pub fn save_peer_invite(&self, peer: &NodeId, invite: &Invite) -> Result<()> {
        self.tree(PEER_INVITE_TREE)?
            .insert(self.peer_invite_slot(peer), self.encode(&invite.to_bytes())?)
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(())
    }

    /// 相手の招待を読む。受け取っていない・使い終えたなら `None`
    pub fn load_peer_invite(&self, peer: &NodeId) -> Result<Option<Invite>> {
        let Some(raw) = self
            .tree(PEER_INVITE_TREE)?
            .get(self.peer_invite_slot(peer))
            .map_err(|e| AetherError::Storage(e.to_string()))?
        else {
            return Ok(None);
        };
        Ok(Some(Invite::from_bytes(&self.decode(&raw)?)?))
    }

    /// 相手の招待を消す（その招待でセッションを立てたら要らない）
    pub fn remove_peer_invite(&self, peer: &NodeId) -> Result<()> {
        self.tree(PEER_INVITE_TREE)?
            .remove(self.peer_invite_slot(peer))
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(())
    }

    /// 期限の切れた招待を消す。消した件数を返す
    ///
    /// 自分の招待の秘密は期限から [`INVITE_GRACE_SECS`] 後、相手の招待は期限で消す。
    pub fn prune_invites(&self, now: u64) -> Result<usize> {
        let mut removed = 0;
        let mine = self.tree(INVITE_TREE)?;
        for item in mine.iter() {
            let (k, v) = item.map_err(|e| AetherError::Storage(e.to_string()))?;
            let expires_at = self
                .decode(&v)
                .ok()
                .and_then(|b| bincode::deserialize::<InviteSecrets>(&b).ok())
                .map(|s| s.expires_at);
            if expires_at.is_none_or(|t| now > t.saturating_add(INVITE_GRACE_SECS)) {
                mine.remove(k).map_err(|e| AetherError::Storage(e.to_string()))?;
                removed += 1;
            }
        }
        let peers = self.tree(PEER_INVITE_TREE)?;
        for item in peers.iter() {
            let (k, v) = item.map_err(|e| AetherError::Storage(e.to_string()))?;
            let expires_at = self
                .decode(&v)
                .ok()
                .and_then(|b| Invite::from_bytes(&b).ok())
                .map(|i| i.expires_at);
            if expires_at.is_none_or(|t| now >= t) {
                peers.remove(k).map_err(|e| AetherError::Storage(e.to_string()))?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// 連絡先が登録済みか
    pub fn contains(&self, contact: &NodeId) -> bool {
        [self.session_slot(contact).to_vec(), contact.as_bytes().to_vec()]
            .iter()
            .any(|k| self.db.get(k).map(|v| v.is_some()).unwrap_or(false))
    }

    /// 連絡先のラチェット状態を消す
    pub fn remove(&self, contact: &NodeId) -> Result<()> {
        for key in [self.session_slot(contact).to_vec(), contact.as_bytes().to_vec()] {
            self.db
                .remove(key)
                .map_err(|e| AetherError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    fn seen_tree(&self) -> Result<sled::Tree> {
        self.db
            .open_tree(SEEN_TREE)
            .map_err(|e| AetherError::Storage(e.to_string()))
    }

    /// メッセージ `id`（Mailbox 鍵など）を処理済みにする。初めてなら true
    ///
    /// Hint は網内で再配送される（重複排除の窓が切れた後のバックログ同期、攻撃者の
    /// 再注入）。本体は no-burn で保持者に残っているので、再配送のたびに同じ私信を
    /// 開き直すことになる。初回フレームを開き直すとセッションが初期化され、以後その
    /// 相手との会話が壊れる。**開く前にここで弾く。**
    pub fn mark_seen(&self, id: &[u8; 32]) -> Result<bool> {
        let tree = self.seen_tree()?;
        let slot = self.slot(b"aether_keystore_seen_v1", id);
        if tree
            .contains_key(slot)
            .map_err(|e| AetherError::Storage(e.to_string()))?
        {
            return Ok(false);
        }
        let now = crate::protocol::hint::current_timestamp();
        tree.insert(slot, self.encode(&now.to_be_bytes())?)
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(true)
    }

    /// `id` が処理済みか
    pub fn is_seen(&self, id: &[u8; 32]) -> Result<bool> {
        let slot = self.slot(b"aether_keystore_seen_v1", id);
        self.seen_tree()?
            .contains_key(slot)
            .map_err(|e| AetherError::Storage(e.to_string()))
    }

    /// [`SEEN_RETENTION_SECS`] より古い処理済みの目印を消す。消した件数を返す
    pub fn prune_seen(&self) -> Result<usize> {
        let tree = self.seen_tree()?;
        let now = crate::protocol::hint::current_timestamp();
        let mut removed = 0;
        for item in tree.iter() {
            let (k, v) = item.map_err(|e| AetherError::Storage(e.to_string()))?;
            let stamp = self
                .decode(&v)
                .ok()
                .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok());
            let stale = match stamp {
                Some(ts) => now.saturating_sub(u64::from_be_bytes(ts)) > SEEN_RETENTION_SECS,
                None => true,
            };
            if stale {
                tree.remove(k).map_err(|e| AetherError::Storage(e.to_string()))?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// 登録済みの連絡先数
    pub fn len(&self) -> usize {
        self.db.len()
    }

    pub fn is_empty(&self) -> bool {
        self.db.is_empty()
    }
}

/// 以前の形式の残りを消す
///
/// 網に置いていたプレキー束の秘密は、もう使わない。残しておくと、押収されたときに
/// その鍵で受け取った初回メッセージを復元される（前方秘匿が効かない）。
fn drop_legacy_trees(db: &Db) -> Result<()> {
    db.drop_tree(LEGACY_PREKEY_TREE)
        .map_err(|e| AetherError::Storage(e.to_string()))?;
    Ok(())
}

/// 暗号鍵から sled キー用の HMAC 鍵を導く（暗号鍵そのものは使い回さない）
fn derive_blind_key(cipher_key: &[u8; 32]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, cipher_key);
    let mut out = [0u8; 32];
    hk.expand(b"aether_keystore_blind_v1", &mut out)
        .expect("32 バイトは HKDF の上限内");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (KeyStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (KeyStore::open(dir.path()).unwrap(), dir)
    }

    /// 会話中のセッションを保存 → 別インスタンスで読み直して会話を続けられる
    #[test]
    fn session_survives_process_restart() {
        let bob_id = NodeId([2; 32]);
        let (mut alice, mut bob) = crate::crypto::session::test_pair();

        // 最初の1通で会話を開始
        let body1 = alice.seal(b"first", b"").unwrap();
        assert_eq!(bob.open(&body1, b"").unwrap(), b"first");

        // Bob 側の状態を保存（プロセス終了の想定）
        let (ks, _dir) = store();
        ks.save(&bob_id, &bob).unwrap();
        assert!(ks.contains(&bob_id));

        // 別インスタンスとして読み直す（再起動の想定）
        let mut restored = ks.load(&bob_id).unwrap().expect("saved session exists");

        // 復元したセッションで会話を続けられる
        let body2 = alice.seal(b"second", b"").unwrap();
        assert_eq!(restored.open(&body2, b"").unwrap(), b"second");
    }

    #[test]
    fn missing_contact_is_none() {
        let (ks, _dir) = store();
        assert!(ks.load(&NodeId([1; 32])).unwrap().is_none());
        assert!(!ks.contains(&NodeId([1; 32])));
    }

    #[test]
    fn invite_secrets_persist_until_removed() {
        use crate::crypto::identity::Identity;
        use crate::crypto::x3dh;

        let bob = Identity::generate();
        let (invite, secrets) = x3dh::create_invite(&bob, 2_000_000_000);
        let key = invite.signed_prekey;

        let dir = tempfile::tempdir().unwrap();
        {
            let ks = KeyStore::open_encrypted(dir.path(), "pass").unwrap();
            assert!(ks.load_invite_secrets(&key).unwrap().is_none());
            ks.save_invite_secrets(&key, &secrets).unwrap();
        }

        // 再起動して読み直す
        let ks = KeyStore::open_encrypted(dir.path(), "pass").unwrap();
        let got = ks.load_invite_secrets(&key).unwrap().expect("保存した招待の秘密が読める");
        assert_eq!(got.signed_prekey_secret, secrets.signed_prekey_secret);
        assert_eq!(got.kem_secret, secrets.kem_secret);

        // 使ったら消す（以後その初回秘密は復元できない）
        ks.remove_invite_secrets(&key).unwrap();
        assert!(ks.load_invite_secrets(&key).unwrap().is_none());
        assert!(ks.is_empty(), "招待は会話の数に数えない");
    }

    #[test]
    fn peer_invites_roundtrip_and_hide_the_peer_on_disk() {
        use crate::crypto::identity::Identity;
        use crate::crypto::x3dh;

        let bob = Identity::generate();
        let (invite, _) = x3dh::create_invite(&bob, 2_000_000_000);
        let (ks, dir) = store();
        ks.save_peer_invite(&bob.public_id(), &invite).unwrap();
        assert_eq!(ks.load_peer_invite(&bob.public_id()).unwrap(), Some(invite));
        drop(ks);

        // sled のキーに相手の NodeId がそのまま残らない
        {
            let raw = sled::open(dir.path()).unwrap();
            let tree = raw.open_tree(PEER_INVITE_TREE).unwrap();
            assert!(tree.iter().keys().all(|k| k.unwrap().as_ref() != bob.public_id().as_bytes()));
        }

        let ks = KeyStore::open(dir.path()).unwrap();
        ks.remove_peer_invite(&bob.public_id()).unwrap();
        assert!(ks.load_peer_invite(&bob.public_id()).unwrap().is_none());
    }

    #[test]
    fn prune_invites_drops_expired_ones() {
        use crate::crypto::identity::Identity;
        use crate::crypto::x3dh;

        let me = Identity::generate();
        let friend = Identity::generate();
        let now = 1_900_000_000;
        let (ks, _dir) = store();

        let (old, old_secrets) = x3dh::create_invite(&me, now - INVITE_GRACE_SECS - 1);
        let (late, late_secrets) = x3dh::create_invite(&me, now - 10);
        let (fresh, fresh_secrets) = x3dh::create_invite(&me, now + 3600);
        for (i, s) in [(&old, &old_secrets), (&late, &late_secrets), (&fresh, &fresh_secrets)] {
            ks.save_invite_secrets(&i.signed_prekey, s).unwrap();
        }
        let (expired_peer, _) = x3dh::create_invite(&friend, now - 1);
        ks.save_peer_invite(&friend.public_id(), &expired_peer).unwrap();

        assert_eq!(ks.prune_invites(now).unwrap(), 2);
        assert!(ks.load_invite_secrets(&old.signed_prekey).unwrap().is_none(), "猶予も過ぎた");
        assert!(ks.load_invite_secrets(&late.signed_prekey).unwrap().is_some(), "遅れて届く初回のため残す");
        assert!(ks.load_invite_secrets(&fresh.signed_prekey).unwrap().is_some());
        assert!(ks.load_peer_invite(&friend.public_id()).unwrap().is_none(), "期限切れの招待では送れない");
    }

    #[test]
    fn opening_drops_the_legacy_prekey_tree() {
        let dir = tempfile::tempdir().unwrap();
        {
            let raw = sled::open(dir.path()).unwrap();
            raw.open_tree(LEGACY_PREKEY_TREE).unwrap().insert(b"self", &b"old secret"[..]).unwrap();
        }
        let ks = KeyStore::open(dir.path()).unwrap();
        assert!(!ks.db.tree_names().iter().any(|n| n.as_ref() == LEGACY_PREKEY_TREE.as_bytes()));
    }

    #[test]
    fn encrypted_store_encrypts_values_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let contact = NodeId([0x88; 32]);
        let session = crate::crypto::session::test_pair().0;
        let plaintext_bincode = bincode::serialize(&session).unwrap();

        {
            let ks = KeyStore::open_encrypted(dir.path(), "correct horse battery").unwrap();
            assert!(ks.is_encrypted());
            ks.save(&contact, &session).unwrap();
        }

        // ディスク上の生バイトは平文 bincode と異なり、nonce+tag ぶん長い（＝暗号化）
        {
            let raw_db = sled::open(dir.path()).unwrap();
            assert!(raw_db.get(contact.as_bytes()).unwrap().is_none(), "キーに NodeId を残さない");
            let (_, on_disk) = raw_db.iter().next().unwrap().unwrap();
            assert_ne!(&on_disk[..], &plaintext_bincode[..], "ディスク上は平文ではない");
            assert_eq!(
                on_disk.len(),
                plaintext_bincode.len() + 12 + 16,
                "nonce(12)+tag(16) ぶん長い"
            );
        }

        // 同じパスフレーズで開けば復元できる
        let ks = KeyStore::open_encrypted(dir.path(), "correct horse battery").unwrap();
        assert!(ks.load(&contact).unwrap().is_some());
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        {
            let ks = KeyStore::open_encrypted(dir.path(), "right").unwrap();
            let s = crate::crypto::session::test_pair().0;
            ks.save(&NodeId([2; 32]), &s).unwrap();
        }
        // 誤ったパスフレーズはカナリアで弾く
        assert!(
            KeyStore::open_encrypted(dir.path(), "wrong").is_err(),
            "誤ったパスフレーズは拒否する"
        );
        // 正しければ開ける
        assert!(KeyStore::open_encrypted(dir.path(), "right").is_ok());
    }

    #[test]
    fn remove_deletes_the_state() {
        let contact = NodeId([0x7; 32]);
        let session = crate::crypto::session::test_pair().0;

        let (ks, _dir) = store();
        ks.save(&contact, &session).unwrap();
        assert_eq!(ks.len(), 1);

        ks.remove(&contact).unwrap();
        assert!(!ks.contains(&contact));
        assert!(ks.is_empty());
    }

    #[test]
    fn contact_node_id_is_not_stored_as_a_plain_key() {
        let (ks, _dir) = store();
        let contact = NodeId([7; 32]);
        ks.save(&contact, &crate::crypto::session::test_pair().0)
            .unwrap();
        assert!(ks.db.get(contact.as_bytes()).unwrap().is_none(), "NodeId がキーに残っている");
        assert!(ks.contains(&contact));
        assert!(ks.load(&contact).unwrap().is_some());
    }

    #[test]
    fn legacy_plain_key_session_is_migrated_on_load() {
        let (ks, _dir) = store();
        let contact = NodeId([9; 32]);
        let session = crate::crypto::session::test_pair().0;
        let bytes = bincode::serialize(&session).unwrap();
        ks.db.insert(contact.as_bytes(), bytes).unwrap();

        assert!(ks.load(&contact).unwrap().is_some(), "旧形式でも読める");
        assert!(ks.db.get(contact.as_bytes()).unwrap().is_none(), "読んだら新形式へ移す");
        assert!(ks.load(&contact).unwrap().is_some());
    }

    #[test]
    fn mark_seen_reports_only_the_first_time_and_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        {
            let ks = KeyStore::open(dir.path()).unwrap();
            assert!(ks.mark_seen(&[3; 32]).unwrap());
            assert!(!ks.mark_seen(&[3; 32]).unwrap(), "二度目は false");
        }
        let ks = KeyStore::open(dir.path()).unwrap();
        assert!(ks.is_seen(&[3; 32]).unwrap(), "再起動をまたいで覚えている");
        assert!(!ks.is_seen(&[4; 32]).unwrap());
        assert_eq!(ks.prune_seen().unwrap(), 0, "新しい目印は消さない");
    }
}
