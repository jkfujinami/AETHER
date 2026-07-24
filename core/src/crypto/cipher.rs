use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, AeadInPlace};
use crate::error::{Result, AetherError};
use rand::RngCore;
use rand::rngs::OsRng;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

/// 鍵生成（HKDFを使って共有シークレットから派生させるのが一般的だが、ここではランダム生成も提供）
pub fn generate_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    key
}

/// Nonce生成
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// メッセージを暗号化 (In-place)
/// buffer: データ + タグ用の余白
pub fn encrypt_in_place(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE], buffer: &mut Vec<u8>) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    cipher.encrypt_in_place(nonce, &[], buffer)
        .map_err(|e| AetherError::Crypto(format!("Encryption failed: {}", e)))?;

    Ok(())
}

/// メッセージを復号 (In-place)
pub fn decrypt_in_place(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE], buffer: &mut Vec<u8>) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    cipher.decrypt_in_place(nonce, &[], buffer)
        .map_err(|e| AetherError::Crypto(format!("Decryption failed: {}", e)))?;

    Ok(())
}

/// 単純な暗号化（新しいVecを返す）
pub fn encrypt(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_SIZE])> {
    let nonce = generate_nonce();
    let mut buffer = plaintext.to_vec();

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_obj = Nonce::from_slice(&nonce);

    cipher.encrypt_in_place(nonce_obj, &[], &mut buffer)
        .map_err(|e| AetherError::Crypto(format!("Encryption failed: {}", e)))?;

    Ok((buffer, nonce))
}

/// nonce と関連データ(AAD)を指定して暗号化する（Double Ratchet 等）
///
/// AAD は認証されるが暗号化されない。ヘッダを AAD に入れると、
/// ヘッダの改竄を復号時に検出できる。
pub fn encrypt_with_aad(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    let mut buffer = plaintext.to_vec();
    cipher
        .encrypt_in_place(nonce, aad, &mut buffer)
        .map_err(|e| AetherError::Crypto(format!("Encryption failed: {}", e)))?;
    Ok(buffer)
}

/// nonce と関連データ(AAD)を指定して復号する
pub fn decrypt_with_aad(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place(nonce, aad, &mut buffer)
        .map_err(|e| AetherError::Crypto(format!("Decryption failed: {}", e)))?;
    Ok(buffer)
}

/// nonce を指定して暗号化する（収束的暗号化など、決定論が要る場合）
///
/// **同じ (key, nonce) で異なる平文を暗号化してはならない**（ChaCha20 の要件）。
/// 呼び出し側が nonce を平文由来にする等で一意性を保証すること。
pub fn encrypt_with_nonce(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut buffer = plaintext.to_vec();
    encrypt_in_place(key, nonce, &mut buffer)?;
    Ok(buffer)
}

/// 単純な復号
pub fn decrypt(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut buffer = ciphertext.to_vec();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_obj = Nonce::from_slice(nonce);

    cipher.decrypt_in_place(nonce_obj, &[], &mut buffer)
        .map_err(|e| AetherError::Crypto(format!("Decryption failed: {}", e)))?;

    Ok(buffer)
}
