//! AETHER クライアント API
//!
//! CLI と GUI が共有する「送る・探す・取る・受ける」の手順。core は部品（回路・Mailbox・
//! トンネル）を提供し、ここがそれを匿名性を崩さない順序で組み立てる。
//!
//! # 守っていること
//!
//! - **Onion 回路は常に 3 ホップ**（固定ガード → 中間 → 出口）。足りなければ失敗し、
//!   短い回路へ黙って落とさない（[`circuit`]）。
//! - **返信も 3 ホップ**（gateway → 中間 → ガード → 自分）。gateway への構築指示は
//!   出口経由で届け、自分の IP を見せない（[`pull`]）。
//! - **本体と Hint は別の出口**（回路分離）。
//! - **ノードの鍵は私信の身元と別**。一回限りは使い捨て、常駐は relay.key（[`keys`]）。
//!
//! ```no_run
//! # async fn demo() -> aether_client::Result<()> {
//! use aether_client::{AetherClient, ClientConfig, NodeMode, event_channel};
//! let client = AetherClient::start(
//!     ClientConfig {
//!         data_dir: "./aether-data".into(),
//!         passphrase: None,
//!         port: 0,
//!         seed: Some("203.0.113.1:9000".parse().unwrap()),
//!         min_relays: 3,
//!         mode: NodeMode::Ephemeral,
//!         network: Default::default(),
//!     },
//!     event_channel(),
//! )
//! .await?;
//! let board = client.search(&aether_client::resolve_board("雑談")?).await?;
//! # Ok(()) }
//! ```

pub mod bbs;
pub mod boards;
pub mod board;
mod circuit;
mod client;
pub mod config;
pub mod error;
pub mod events;
mod fetch;
pub mod friends;
pub mod keys;
mod pull;
mod receive;
mod send;

pub use board::{Board, Post, Thread};
pub use boards::{BoardId, BoardInfo, builtin_boards, resolve_board};
pub use client::{AetherClient, Status};
pub use config::{ClientConfig, NetworkParams, NodeMode, RelayOptions};
pub use error::{ClientError, Result};
pub use events::{ClientEvent, EventSender, MessageSource, SendState, event_channel};
pub use fetch::Fetched;
pub use friends::{Friend, friend_uri, parse_friend_id};
pub use keys::KeyFiles;
pub use receive::Contact;
pub use send::{PublicPost, SendReport};

/// hex 64 文字を 32 バイトにする（NodeId・共有秘密・content_ref の入力用）
pub fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim())
        .map_err(|e| ClientError::Invalid(format!("{} が hex ではありません: {}", what, e)))?;
    bytes
        .try_into()
        .map_err(|_| ClientError::Invalid(format!("{} は 32 バイト (hex 64 文字) である必要があります", what)))
}
