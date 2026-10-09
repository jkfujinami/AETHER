pub mod schrodinger;
// pub mod client; // 従来型クライアント（必要なら）
pub mod server; // Mailboxサーバーロジック
pub mod sharding;
pub mod sharding_v2; // 大容量ファイル用 RS(k+m)（Part 23 の 7 章）
pub mod hint_release;
pub mod index; // 索引層（キーワード → 記述子）
pub mod chunk; // チャンク化 + content-addressing（大容量ファイル / 2-4）
pub mod board; // 掲示板スレッド DAG（2-5）
