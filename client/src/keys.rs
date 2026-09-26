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
    ///
    /// **パスフレーズが設定されているのに平文（magic なし）のファイルを読んだ場合、
    /// 読んだ後に暗号化して書き直す。** 後からパスフレーズを設定した人の
    /// 古い平文ファイルが、以後もずっと平文のまま残ってしまう問題への対処。
    /// 書き直しに失敗しても読み出し自体は成功させる（鍵を読めないよりまし）。
    pub(crate) fn read_secure(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read(path)?;
        let Some(rest) = raw.strip_prefix(SECURE_MAGIC.as_slice()) else {
            if self.passphrase().is_some() {
                let _ = self.write_secure(path, &raw);
            }
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
        write_private_atomic(&self.data_dir, path, &bytes)
    }

    /// 鍵ファイルを読む。**パスフレーズが設定されているのに平文だった場合は
    /// 読んだ後に暗号化して書き直す**（[`read_secure`](Self::read_secure) と同じ理由）。
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
            let identity = Identity::from_bytes(&bytes)?;
            if self.passphrase().is_some() {
                let _ = self.write_key(path, &identity);
            }
            Ok(identity)
        }
    }

    /// 鍵を書く（パスフレーズがあれば暗号化、所有者だけが読める権限）
    pub(crate) fn write_key(&self, path: &Path, identity: &Identity) -> Result<()> {
        let bytes = match self.passphrase() {
            Some(pass) => identity.to_encrypted_bytes(pass)?,
            None => identity.to_bytes().to_vec(),
        };
        write_private_atomic(&self.data_dir, path, &bytes)
    }
}

/// `bytes` を `path` へ原子的に書く（unix では所有者だけが読める権限で）
///
/// 書いてから `chmod` すると、書き込みから権限変更までの一瞬 0644 (誰でも読める) の
/// 窓ができる。一時ファイルを最初から 0600 で作って書き、`rename` で置き換えれば
/// その窓が無い（rename は同一ファイルシステム内ではアトミック）。
fn write_private_atomic(data_dir: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::create_dir_all(data_dir)?;

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        // 同時に複数プロセスが書かないので固定名で十分。同じディレクトリに置いて
        // rename が同一ファイルシステム内で完結するようにする。
        let tmp_path = path.with_extension("tmp-write");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)?;
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

    /// パスフレーズ無しで作った鍵（平文）を、後からパスフレーズ付きで読むと
    /// 暗号化して書き直されること。古い平文ファイルが永遠に平文で残る問題への対処。
    #[test]
    fn reading_a_plaintext_key_with_a_passphrase_re_encrypts_it_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let plain = KeyFiles::new(dir.path(), None);
        let id = plain.create_identity(false).unwrap();
        let path = plain.identity_path();

        let raw_before = std::fs::read(&path).unwrap();
        assert!(!Identity::is_encrypted_bytes(&raw_before), "前提条件: 平文で保存されているはず");

        let locked = KeyFiles::new(dir.path(), Some("correct horse".into()));
        let read_back = locked.load_identity().unwrap();
        assert_eq!(read_back.public_id(), id.public_id(), "読み出し自体はパスフレーズ無しでも成功すること");

        let raw_after = std::fs::read(&path).unwrap();
        assert!(Identity::is_encrypted_bytes(&raw_after), "読んだ後、暗号化して書き直されているはず");

        // 書き直された後も同じパスフレーズで読める
        assert_eq!(locked.load_identity().unwrap().public_id(), id.public_id());
        // パスフレーズ無しではもう読めない
        assert!(plain.load_identity().is_err());
    }

    /// `read_secure` 側（friends.bin 等）でも同じ書き直しが起きること
    #[test]
    fn reading_a_plaintext_secure_file_with_a_passphrase_re_encrypts_it_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let plain = KeyFiles::new(dir.path(), None);
        let path = dir.path().join("friends.bin");
        plain.write_secure(&path, b"plain contents").unwrap();

        let raw_before = std::fs::read(&path).unwrap();
        assert!(!raw_before.starts_with(SECURE_MAGIC), "前提条件: 平文で保存されているはず");

        let locked = KeyFiles::new(dir.path(), Some("correct horse".into()));
        let read_back = locked.read_secure(&path).unwrap().unwrap();
        assert_eq!(read_back, b"plain contents");

        let raw_after = std::fs::read(&path).unwrap();
        assert!(raw_after.starts_with(SECURE_MAGIC), "読んだ後、暗号化して書き直されているはず");
        assert_eq!(locked.read_secure(&path).unwrap().unwrap(), b"plain contents");
    }

    /// 書いたファイルが所有者だけ読める権限（0600）で、しかも
    /// 書き込み中に緩い権限の窓ができないこと（rename による原子的な置き換え）
    #[cfg(unix)]
    #[test]
    fn written_files_are_owner_only_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        keys.create_identity(false).unwrap();

        let mode = std::fs::metadata(keys.identity_path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
