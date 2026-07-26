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
//! 「これから使う鍵（現在のチェーン鍵）」だけ。将来的にはこの DB 自体を
//! パスフレーズ由来鍵で暗号化する（未実装）。

use crate::crypto::identity::NodeId;
use crate::crypto::session::Session;
use crate::crypto::x3dh::{PreKeyBundle, PreKeySecrets};
use crate::error::{AetherError, Result};
use crate::storage::at_rest;
use sled::Db;
use std::path::Path;

/// メタ情報（ソルト・カナリア）を置く別ツリー。main ツリーの `len()` に混ざらない
const META_TREE: &str = "aether_keystore_meta";
const CANARY_PLAINTEXT: &[u8] = b"aether-keystore-canary-v1";

/// 自分のプレキー秘密（X3DH の Bob 役）を置く別ツリー
const PREKEY_TREE: &str = "aether_keystore_prekeys";
const PREKEY_SELF_KEY: &[u8] = b"self";

/// 連絡先 NodeId → 前方秘匿セッション（方向別 Double Ratchet）
///
/// `cipher_key` があれば保存時に値を暗号化する（押収対策 / 保存時暗号化）。
pub struct KeyStore {
    db: Db,
    cipher_key: Option<[u8; 32]>,
}

impl KeyStore {
    /// 指定パスに KeyStore を開く（**平文**・テストや暗号化しない場合）
    pub fn open(path: &Path) -> Result<Self> {
        let db = sled::open(path).map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(Self { db, cipher_key: None })
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
        Ok(Self {
            db,
            cipher_key: Some(key),
        })
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
            .insert(contact.as_bytes(), stored)
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(())
    }

    /// 連絡先のセッション状態を読む。無ければ `None`
    pub fn load(&self, contact: &NodeId) -> Result<Option<Session>> {
        let Some(raw) = self
            .db
            .get(contact.as_bytes())
            .map_err(|e| AetherError::Storage(e.to_string()))?
        else {
            return Ok(None);
        };
        let bytes = self.decode(&raw)?;
        let session = bincode::deserialize(&bytes)
            .map_err(|e| AetherError::Storage(format!("Corrupt session state: {}", e)))?;
        Ok(Some(session))
    }

    /// 自分のプレキー束と秘密（X3DH の Bob 役）を保存する（暗号化有効なら暗号化して保存）
    ///
    /// Bob は `start` 時に1回だけ生成し、これを**永続化して再起動を跨いで再利用**する。
    /// 束（公開部）も一緒に持つ ── Kyber 公開鍵は秘密鍵から再導出できないため、再公開に要る。
    /// 鍵を毎回作り直すと、束を取得済みの initiator の初回メッセージが復元できなくなる。
    /// initiator が初回メッセージに添える [`InitialMessage`] をこの秘密で開いて同じ `SK` を得る。
    ///
    /// [`InitialMessage`]: crate::crypto::x3dh::InitialMessage
    pub fn save_prekeys(&self, bundle: &PreKeyBundle, secrets: &PreKeySecrets) -> Result<()> {
        let tree = self
            .db
            .open_tree(PREKEY_TREE)
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        let bytes = bincode::serialize(&(bundle, secrets))
            .map_err(|e| AetherError::Serialization(e.to_string()))?;
        let stored = self.encode(&bytes)?;
        tree.insert(PREKEY_SELF_KEY, stored)
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(())
    }

    /// 自分のプレキー束と秘密を読む。無ければ `None`（初回生成が必要）
    pub fn load_prekeys(&self) -> Result<Option<(PreKeyBundle, PreKeySecrets)>> {
        let tree = self
            .db
            .open_tree(PREKEY_TREE)
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        let Some(raw) = tree
            .get(PREKEY_SELF_KEY)
            .map_err(|e| AetherError::Storage(e.to_string()))?
        else {
            return Ok(None);
        };
        let bytes = self.decode(&raw)?;
        let pair = bincode::deserialize(&bytes)
            .map_err(|e| AetherError::Storage(format!("Corrupt prekey state: {}", e)))?;
        Ok(Some(pair))
    }

    /// 連絡先が登録済みか
    pub fn contains(&self, contact: &NodeId) -> bool {
        self.db
            .get(contact.as_bytes())
            .map(|v| v.is_some())
            .unwrap_or(false)
    }

    /// 連絡先のラチェット状態を消す
    pub fn remove(&self, contact: &NodeId) -> Result<()> {
        self.db
            .remove(contact.as_bytes())
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(())
    }

    /// 登録済みの連絡先数
    pub fn len(&self) -> usize {
        self.db.len()
    }

    pub fn is_empty(&self) -> bool {
        self.db.is_empty()
    }
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
        let secret = [0x24u8; 32];
        let alice_id = NodeId([1; 32]);
        let bob_id = NodeId([2; 32]);
        let mut alice = Session::bootstrap(&secret, &alice_id, &bob_id);
        let mut bob = Session::bootstrap(&secret, &bob_id, &alice_id);

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
    fn prekeys_persist_and_survive_restart() {
        use crate::crypto::identity::Identity;
        use crate::crypto::x3dh;

        let bob = Identity::generate();
        let (bundle, secrets) = x3dh::generate_prekeys(&bob, false);

        let dir = tempfile::tempdir().unwrap();
        {
            let ks = KeyStore::open(dir.path()).unwrap();
            assert!(ks.load_prekeys().unwrap().is_none(), "初回は未設定");
            ks.save_prekeys(&bundle, &secrets).unwrap();
        }

        // 再起動して読み直す（束＋秘密の両方）
        let ks = KeyStore::open(dir.path()).unwrap();
        let (rb, rs) = ks.load_prekeys().unwrap().expect("保存したプレキーが読める");
        assert_eq!(rs.signed_prekey_secret, secrets.signed_prekey_secret);
        assert_eq!(rs.kem_secret, secrets.kem_secret);
        assert_eq!(rb.signed_prekey, bundle.signed_prekey);
        assert_eq!(rb.kem_public, bundle.kem_public);
    }

    #[test]
    fn encrypted_store_encrypts_values_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let secret = [0x24u8; 32];
        let contact = NodeId([0x88; 32]);
        let session = Session::bootstrap(&secret, &NodeId([1; 32]), &contact);
        let plaintext_bincode = bincode::serialize(&session).unwrap();

        {
            let ks = KeyStore::open_encrypted(dir.path(), "correct horse battery").unwrap();
            assert!(ks.is_encrypted());
            ks.save(&contact, &session).unwrap();
        }

        // ディスク上の生バイトは平文 bincode と異なり、nonce+tag ぶん長い（＝暗号化）
        {
            let raw_db = sled::open(dir.path()).unwrap();
            let on_disk = raw_db.get(contact.as_bytes()).unwrap().unwrap();
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
            let s = Session::bootstrap(&[1u8; 32], &NodeId([1; 32]), &NodeId([2; 32]));
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
        let secret = [0x11u8; 32];
        let contact = NodeId([0x7; 32]);
        let session = Session::bootstrap(&secret, &NodeId([9; 32]), &contact);

        let (ks, _dir) = store();
        ks.save(&contact, &session).unwrap();
        assert_eq!(ks.len(), 1);

        ks.remove(&contact).unwrap();
        assert!(!ks.contains(&contact));
        assert!(ks.is_empty());
    }
}
