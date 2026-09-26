//! 鍵ファイルとローカル DB の置き場所
//!
//! # 鍵は 2 本
//!
//! - **identity.key** ── 私信の身元。NodeId が私信の宛先そのもの。網には出さない
//! - **relay.key** ── 常駐リレーとして網に配る記述子の鍵
//!
//! リレーの記述子は NodeId と IP を網全体へ配る。そこに私信の宛先を載せると、
//! 宛先を知る誰もがディレクトリを引くだけで受信者の IP を得られる。だから分ける。
//! 一回限りのクライアントのノード鍵はどちらでもなく、起動のたびに使い捨てる。

use crate::error::{ClientError, Result};
use aether_core::crypto::identity::Identity;
use aether_core::storage::keystore::KeyStore;
use std::path::{Path, PathBuf};

/// 暗号化した設定ファイルの先頭（平文と区別する）
const SECURE_MAGIC: &[u8; 4] = b"AESF";

/// データディレクトリ内の鍵・DB へのアクセス
#[derive(Debug, Clone)]
pub struct KeyFiles {
    data_dir: PathBuf,
    passphrase: Option<String>,
}

impl KeyFiles {
    pub fn new(data_dir: impl Into<PathBuf>, passphrase: Option<String>) -> Self {
        Self {
            data_dir: data_dir.into(),
            passphrase: passphrase.filter(|p| !p.is_empty()),
        }
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn passphrase(&self) -> Option<&str> {
        self.passphrase.as_deref()
    }

    /// 平文保存になる場合の注意文
    pub fn plaintext_warning(&self) -> Option<String> {
        self.passphrase.is_none().then(|| {
            "パスフレーズ未設定 ── 鍵・連絡先・Mailbox を平文で保存します（押収対策には設定推奨）"
                .to_string()
        })
    }

    pub fn identity_path(&self) -> PathBuf {
        self.data_dir.join("identity.key")
    }

    pub fn relay_key_path(&self) -> PathBuf {
        self.data_dir.join("relay.key")
    }

    pub fn mailbox_db_path(&self) -> PathBuf {
        self.data_dir.join("mailbox.db")
    }

    pub fn keystore_path(&self) -> PathBuf {
        self.data_dir.join("keystore.db")
    }

    /// 固定ガードの記録
    ///
    /// ノード鍵ではなくデータディレクトリ（＝利用者の端末）に紐付ける。
    /// 一回限りのクライアントもノード鍵は使い捨てだが、ガードは使い続ける。
    pub fn guard_path(&self) -> PathBuf {
        self.data_dir.join("guards.bin")
    }

    /// リレー鍵の NodeId PoW の解（キャッシュ）
    pub fn relay_pow_path(&self) -> PathBuf {
        self.data_dir.join("relay.pow")
    }

    /// 保存済みの PoW の解を読む（無い・壊れていれば `None`。検証はノード側で行う）
    pub fn load_relay_pow(&self) -> Option<u64> {
        std::fs::read_to_string(self.relay_pow_path())
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// PoW の解を保存する
    ///
    /// 解は NodeId から誰でも検証できる公開情報（記述子に載って網へ配られる）なので平文でよい。
    pub fn save_relay_pow(&self, nonce: u64) -> Result<()> {
        std::fs::write(self.relay_pow_path(), nonce.to_string())?;
        Ok(())
    }

    pub fn has_identity(&self) -> bool {
        self.identity_path().exists()
    }

    /// 私信の身元を新しく作って保存する
    ///
    /// `force` なしで既存の鍵を上書きしない（NodeId が変わると連絡先から届かなくなる）。
    pub fn create_identity(&self, force: bool) -> Result<Identity> {
        let path = self.identity_path();
        if path.exists() && !force {
            return Err(ClientError::invalid(format!(
                "鍵が既に存在します: {}（上書きすると NodeId が変わり、連絡先から届かなくなります）",
                path.display()
            )));
        }
        let identity = Identity::generate();
        self.write_key(&path, &identity)?;
        Ok(identity)
    }

    /// 私信の身元を読む
    pub fn load_identity(&self) -> Result<Identity> {
        let path = self.identity_path();
        if !path.exists() {
            return Err(ClientError::invalid(format!(
                "鍵がありません: {}（先に鍵を生成してください）",
                path.display()
            )));
        }
        self.read_key(&path)
    }

    /// リレー用の鍵を読む。無ければ作って保存する
    ///
    /// 使い捨てにはしない。NodeId が変わるとガードに選ばれる実績も PoW もやり直しになる。
    pub fn load_or_create_relay_identity(&self) -> Result<Identity> {
        let path = self.relay_key_path();
        if path.exists() {
            return self.read_key(&path);
        }
        let identity = Identity::generate();
        self.write_key(&path, &identity)?;
        Ok(identity)
    }

    /// 私信の前方秘匿セッションを保存する KeyStore を開く
    ///
    /// **1 プロセスに 1 ハンドルだけ。** sled は DB ディレクトリを排他ロックする。
    pub fn open_keystore(&self) -> Result<KeyStore> {
        let path = self.keystore_path();
        Ok(match self.passphrase() {
            Some(pass) => KeyStore::open_encrypted(&path, pass)?,
            None => KeyStore::open(&path)?,
        })
    }

    /// 小さな設定ファイルを読む（パスフレーズがあれば暗号化されている）
    ///
    /// 友だち一覧・お気に入りの板など、「誰と・どこで」を示すものに使う。
    /// 押収されても、パスフレーズ無しには読めない。無ければ `None`。
    pub(crate) fn read_secure(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read(path)?;
        let Some(rest) = raw.strip_prefix(SECURE_MAGIC.as_slice()) else {
            return Ok(Some(raw));
        };
        let pass = self.passphrase().ok_or_else(|| {
            ClientError::invalid(format!(
                "{} は暗号化されています。パスフレーズを指定してください",
                path.display()
            ))
        })?;
        if rest.len() < 16 {
            return Err(ClientError::invalid(format!("{} が壊れています", path.display())));
        }
        let (salt, body) = rest.split_at(16);
        let key = aether_core::storage::at_rest::derive_key(pass, salt)?;
        let plain = aether_core::storage::at_rest::decrypt_value(&key, body)
            .map_err(|_| ClientError::invalid(format!("{}: パスフレーズが違います", path.display())))?;
        Ok(Some(plain))
    }

    /// 小さな設定ファイルを書く（パスフレーズがあれば暗号化、所有者だけが読める権限）
    pub(crate) fn write_secure(&self, path: &Path, plain: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        let bytes = match self.passphrase() {
            Some(pass) => {
                let salt: [u8; 16] = rand::random();
                let key = aether_core::storage::at_rest::derive_key(pass, &salt)?;
                let mut out = SECURE_MAGIC.to_vec();
                out.extend_from_slice(&salt);
                out.extend_from_slice(&aether_core::storage::at_rest::encrypt_value(&key, plain)?);
                out
            }
            None => plain.to_vec(),
        };
        std::fs::write(path, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub(crate) fn read_key(&self, path: &Path) -> Result<Identity> {
        let bytes = std::fs::read(path)?;
        // 暗号化された鍵（マジック付き）はパスフレーズが要る。平文はそのまま。
        if Identity::is_encrypted_bytes(&bytes) {
            let pass = self.passphrase().ok_or_else(|| {
                ClientError::invalid(format!(
                    "{} は暗号化されています。パスフレーズを指定してください",
                    path.display()
                ))
            })?;
            Ok(Identity::from_encrypted_bytes(&bytes, pass)?)
        } else {
            Ok(Identity::from_bytes(&bytes)?)
        }
    }

    /// 鍵を書く（パスフレーズがあれば暗号化、所有者だけが読める権限）
    pub(crate) fn write_key(&self, path: &Path, identity: &Identity) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;

        let bytes = match self.passphrase() {
            Some(pass) => identity.to_encrypted_bytes(pass)?,
            None => identity.to_bytes().to_vec(),
        };
        std::fs::write(path, bytes)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_and_relay_keys_are_distinct() {
        // 私信の宛先とリレーの NodeId が同じだと、宛先から IP を引ける
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        let id = keys.create_identity(false).unwrap();
        let relay = keys.load_or_create_relay_identity().unwrap();
        assert_ne!(id.public_id(), relay.public_id());

        // 2 回目は同じ鍵を読む（ガードの実績・PoW をやり直さない）
        let again = keys.load_or_create_relay_identity().unwrap();
        assert_eq!(relay.public_id(), again.public_id());
    }

    #[test]
    fn create_identity_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        keys.create_identity(false).unwrap();
        assert!(keys.create_identity(false).is_err());
    }

    #[test]
    fn encrypted_key_needs_the_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let locked = KeyFiles::new(dir.path(), Some("correct horse".into()));
        let id = locked.create_identity(false).unwrap();

        assert!(KeyFiles::new(dir.path(), None).load_identity().is_err());
        assert_eq!(locked.load_identity().unwrap().public_id(), id.public_id());
    }
}
