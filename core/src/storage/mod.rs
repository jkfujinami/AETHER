//! 永続化層
//!
//! 押収耐性のために**セッション状態をディスクに持つ**（Double Ratchet の KeyStore など）。

pub mod keystore; // 連絡先ごとの Double Ratchet 状態（3-1）
