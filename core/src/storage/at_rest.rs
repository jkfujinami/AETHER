//! 保存時暗号化の共通部品 (3-1 押収対策)
//!
//! パスフレーズを Argon2id で伸ばして鍵を作り、値を ChaCha20-Poly1305 で暗号化する。
//! KeyStore・Mailbox・identity.key が同じ部品を共有する（同じ `AETHER_PASSPHRASE` で解錠）。
//!
//! # 何を守るか
//!
//! 押収されても、パスフレーズ無しにはディスク上の状態（連絡先のラチェット、保持中の
//! Mailbox エントリ、identity 秘密鍵）を読めない。**カナリア**で誤ったパスフレーズを
//! 検出して拒否する（＝間違った鍵で復号し続けて壊さない）。

use crate::crypto::cipher;
use crate::error::{AetherError, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use sled::Db;

/// メタ情報（ソルト・カナリア）のキー。呼び出し側が別ツリーに置く。
const SALT_KEY: &[u8] = b"salt";
const CANARY_KEY: &[u8] = b"canary";

/// パスフレーズ + ソルトから 32B 鍵を導出する（Argon2id・32MiB / 3 パス）
///
/// 起動時に1回だけ払う。GPU/ASIC でのパスフレーズ総当たりを重くする。
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
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
pub fn encrypt_value(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let (ciphertext, nonce) = cipher::encrypt(key, plaintext)?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// `[nonce(12)][ciphertext]` を復号する
pub fn decrypt_value(key: &[u8; 32], raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < 12 {
        return Err(AetherError::Crypto("at-rest value too short".into()));
    }
    let nonce: [u8; 12] = raw[0..12].try_into().expect("長さ確認済み");
    cipher::decrypt(key, &nonce, &raw[12..])
}

/// sled Db を保存時暗号化する鍵を用意する（ソルト生成 → 鍵導出 → カナリア検証）
///
/// `meta_tree` にソルトとカナリアを置く（本体ツリーの `len()` に混ざらない）。
/// 初回はソルトとカナリアを作り、以降は再利用する。カナリアが**同じパスフレーズで
/// 復号できかつ一致**しなければ誤ったパスフレーズとみなして拒否する。
///
/// `canary_plaintext` は用途ごとに変える（KeyStore と Mailbox で別の値）。
pub fn unlock_db(
    db: &Db,
    passphrase: &str,
    meta_tree: &str,
    canary_plaintext: &[u8],
) -> Result<[u8; 32]> {
    let meta = db
        .open_tree(meta_tree)
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
                .map_err(|_| AetherError::Crypto("誤ったパスフレーズです".into()))?;
            if dec != canary_plaintext {
                return Err(AetherError::Crypto("誤ったパスフレーズです".into()));
            }
        }
        None => {
            let enc = encrypt_value(&key, canary_plaintext)?;
            meta.insert(CANARY_KEY, enc)
                .map_err(|e| AetherError::Storage(e.to_string()))?;
        }
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_roundtrips() {
        let key = [0x42u8; 32];
        let enc = encrypt_value(&key, b"hello").unwrap();
        assert_ne!(&enc[..], b"hello", "平文が残ってはいけない");
        assert_eq!(enc.len(), 5 + 12 + 16, "nonce(12)+tag(16) ぶん長い");
        assert_eq!(decrypt_value(&key, &enc).unwrap(), b"hello");
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let enc = encrypt_value(&[1u8; 32], b"secret").unwrap();
        assert!(decrypt_value(&[2u8; 32], &enc).is_err());
    }

    #[test]
    fn unlock_derives_a_stable_key_and_rejects_wrong_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        let k1 = unlock_db(&db, "right", "meta", b"canary-v1").unwrap();
        // 同じパスフレーズなら同じ鍵（ソルト再利用）
        let k2 = unlock_db(&db, "right", "meta", b"canary-v1").unwrap();
        assert_eq!(k1, k2);

        // 誤ったパスフレーズはカナリアで弾く
        assert!(unlock_db(&db, "wrong", "meta", b"canary-v1").is_err());
    }
}
