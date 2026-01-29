## Part 2: core/src 基盤ファイル

### 2.1 `core/src/lib.rs` - ライブラリエントリポイント

**役割**: 全モジュールを公開し、外部クレート（cli, app）からアクセス可能にする

```rust
// 各サブモジュールを宣言・公開
pub mod error;
pub mod config;
pub mod net;
pub mod crypto;
pub mod mailbox;
pub mod dht;
pub mod storage;
pub mod protocol;

// よく使う型をre-export
pub use error::{AetherError, Result};
pub use config::Config;
```

---

### 2.2 `core/src/error.rs` - 共通エラー型

**役割**: プロジェクト全体で使う統一エラー型を定義

**内容**:
- `thiserror` を使って `AetherError` enumを定義
- 各モジュール固有のエラーを variant として持つ
  - `Network(NetworkError)` - QUIC接続失敗、タイムアウト等
  - `Crypto(CryptoError)` - 復号失敗、署名検証失敗等
  - `Mailbox(MailboxError)` - PUT/GET失敗、容量超過等
  - `Storage(StorageError)` - DB読み書きエラー等
  - `Protocol(ProtocolError)` - 不正なパケット形式等
- `type Result<T> = std::result::Result<T, AetherError>;` を定義

---

### 2.3 `core/src/config.rs` - 設定構造体

**役割**: アプリケーション全体の設定を一元管理

**内容**:
```rust
pub struct Config {
    // ネットワーク設定
    pub listen_port: u16,              // デフォルト: 0 (OS自動割当)
    pub stun_servers: Vec<String>,     // STUNサーバーリスト

    // Mailbox設定
    pub mailbox_capacity_mb: u64,      // ユーザーあたりの容量上限
    pub message_ttl_hours: u64,        // メッセージ保持期間

    // 暗号設定
    pub pow_difficulty: u8,            // Proof of Work難易度

    // Ghost Mode設定
    pub active_poll_interval_secs: u64,   // Active時のポーリング間隔
    pub ghost_poll_interval_secs: u64,    // Ghost時のポーリング間隔

    // Traffic Shaping
    pub enable_cover_traffic: bool,    // カバートラフィック有効化
    pub target_fps: u32,               // 偽装FPS (30 or 60)
}
```
- `Default` trait実装で合理的なデフォルト値を提供
- `serde` でシリアライズ可能にし、設定ファイル読み込みに対応

---

#### Step 3: cli クレートのセットアップ

**ファイル**: `/AETHER/cli/Cargo.toml`

```toml
[package]
name = "aether-cli"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
rust-version.workspace = true
description = "AETHER Protocol CLI Tool"

[dependencies]
aether-core = { path = "../core" }
tokio.workspace = true
clap.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
```

---

