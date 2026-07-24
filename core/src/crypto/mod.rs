pub mod identity;
pub mod cipher;
pub mod key_exchange;
pub mod keyword;
pub mod pow;
pub mod ratchet; // Double Ratchet（前方秘匿 / 3-1）
pub mod x3dh; // 非同期初期鍵合意（3-1）
pub mod session; // 連絡先ごとの方向別ラチェット（3-1 配線）

// 将来的にKyber (PQC) をここに追加
// pub mod kem;
