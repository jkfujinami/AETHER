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

use crate::crypto::cipher;
use crate::crypto::identity::NodeId;
use crate::crypto::session::Session;
use crate::error::{AetherError, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use sled::Db;
use std::path::Path;

/// メタ情報（ソルト・カナリア）を置く別ツリー。main ツリーの `len()` に混ざらない
const META_TREE: &str = "aether_keystore_meta";
const SALT_KEY: &[u8] = b"salt";
const CANARY_KEY: &[u8] = b"canary";
const CANARY_PLAINTEXT: &[u8] = b"aether-keystore-canary-v1";

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
        let meta = db
            .open_tree(META_TREE)
            .map_err(|e| AetherError::Storage(e.to_string()))?;

        // ソルト（初回生成・以降は再利用）
        let salt = match meta.get(SALT_KEY).map_err(|e| AetherError::Storage(e.to_string()))? {
            Some(s) => s.to_vec(),
            None => {
                let mut s = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut s);
                meta.insert(SALT_KEY, &s[..])
                    .map_err(|e| AetherError::Storage(e.to_string()))?;
                s.to_vec()
            }
        };

        let key = derive_key(passphrase, &salt)?;

        // カナリアでパスフレーズを検証する
        match meta.get(CANARY_KEY).map_err(|e| AetherError::Storage(e.to_string()))? {
            Some(enc) => {
                let dec = decrypt_value(&key, &enc)
                    .map_err(|_| AetherError::Crypto("KeyStore: 誤ったパスフレーズです".into()))?;
                if dec != CANARY_PLAINTEXT {
                    return Err(AetherError::Crypto("KeyStore: 誤ったパスフレーズです".into()));
                }
            }
            None => {
                let enc = encrypt_value(&key, CANARY_PLAINTEXT)?;
                meta.insert(CANARY_KEY, enc)
                    .map_err(|e| AetherError::Storage(e.to_string()))?;
            }
        }

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
            Some(k) => encrypt_value(k, plaintext),
            None => Ok(plaintext.to_vec()),
        }
    }

    fn decode(&self, raw: &[u8]) -> Result<Vec<u8>> {
        match &self.cipher_key {
            Some(k) => decrypt_value(k, raw),
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

/// パスフレーズ + ソルトから 32B 鍵を導出する（Argon2id）
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    // 32MiB / 3 パス。起動時に1回だけ払う。
    let params = Params::new(32 * 1024, 3, 1, Some(32))
        .map_err(|e| AetherError::Crypto(format!("Invalid Argon2 params: {}", e)))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| AetherError::Crypto(format!("Argon2 failed: {}", e)))?;
    Ok(key)
}

/// 値を暗号化して `[nonce(12)][ciphertext]` にする
fn encrypt_value(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let (ciphertext, nonce) = cipher::encrypt(key, plaintext)?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// `[nonce(12)][ciphertext]` を復号する
fn decrypt_value(key: &[u8; 32], raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < 12 {
        return Err(AetherError::Crypto("KeyStore value too short".into()));
    }
    let nonce: [u8; 12] = raw[0..12].try_into().expect("長さ確認済み");
    cipher::decrypt(key, &nonce, &raw[12..])
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
