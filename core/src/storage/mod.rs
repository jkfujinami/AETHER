//! 永続化層
//!
//! 押収耐性のために**セッション状態をディスクに持つ**（Double Ratchet の KeyStore など）。

pub mod at_rest; // 保存時暗号化の共通部品（Argon2id + ChaCha20Poly1305・3-1）
pub mod keystore; // 連絡先ごとの Double Ratchet 状態（3-1）
