## Part 1: プロジェクト構造と初期セットアップ

### 1.1 最終的なディレクトリ構成

```
AETHER/
├── Cargo.toml                    # ワークスペース定義
├── docs/
│   ├── doc.md                    # プロトコル仕様書
│   ├── implementation.md         # 実装計画概要
│   ├── detailed_implementation.md # 本ドキュメント
│   └── discovery_protocol_design.md # 発見プロトコル設計書
│
├── core/                         # コアライブラリ (全プラットフォーム共通)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                # ライブラリエントリポイント
│       ├── error.rs              # 共通エラー型定義
│       ├── config.rs             # 設定構造体
│       │
│       ├── net/                  # ネットワーク層
│       │   ├── mod.rs
│       │   ├── quic.rs           # QUIC接続管理
│       │   ├── stun.rs           # NAT越え (STUN)
│       │   ├── onion.rs          # 3-Hop Onion Routing
│       │   ├── shaper.rs         # Traffic Shaping
│       │   ├── relay.rs          # Relay Network クライアント ★新規
│       │   └── gossip.rs         # Gossip Protocol ★新規
│       │
│       ├── crypto/               # 暗号層
│       │   ├── mod.rs
│       │   ├── identity.rs       # Ed25519 ID管理
│       │   ├── kem.rs            # Kyber+X25519 ハイブリッドKEM
│       │   ├── ratchet.rs        # Double Ratchet
│       │   └── aead.rs           # ChaCha20-Poly1305
│       │
│       ├── mailbox/              # Mailbox層
│       │   ├── mod.rs
│       │   ├── sharding.rs       # Reed-Solomon 分割/復元
│       │   ├── client.rs         # Mailboxクライアント
│       │   ├── server.rs         # Mailboxサーバー
│       │   └── schrodinger.rs    # シュレーディンガーMailbox ★新規
│       │
│       ├── dht/                  # 分散ハッシュテーブル (フォールバック用)
│       │   ├── mod.rs
│       │   ├── kbucket.rs        # Kademlia k-bucket
│       │   └── rpc.rs            # DHT RPC
│       │
│       ├── storage/              # ローカルストレージ
│       │   ├── mod.rs
│       │   ├── local_db.rs       # 暗号化ローカルDB
│       │   └── keystore.rs       # 鍵管理
│       │
│       └── protocol/             # ワイヤープロトコル
│           ├── mod.rs
│           ├── wire.rs           # パケットシリアライズ
│           └── hint.rs           # Hint パケット構造 ★新規
│
├── cli/                          # 開発用CLIツール
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
│
└── app/                          # GUIアプリ (将来)
    ├── src-tauri/
    └── src/
```

---

### 1.2 初期セットアップ手順

#### Step 1: ワークスペースルートの Cargo.toml

**ファイル**: `/AETHER/Cargo.toml`

```toml
[workspace]
resolver = "2"
members = [
    "core",
    "cli",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
authors = ["AETHER Team"]
license = "MIT OR Apache-2.0"
rust-version = "1.83"

[workspace.dependencies]
# 非同期ランタイム
tokio = { version = "1.43", features = ["full"] }

# QUIC実装
quinn = "0.11"
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }
rcgen = "0.13"  # 自己署名証明書生成

# 暗号系
ed25519-dalek = { version = "2", features = ["rand_core"] }
x25519-dalek = { version = "2", features = ["static_secrets"] }
pqcrypto-kyber = "0.8"  # Kyber (ML-KEM)
chacha20poly1305 = "0.10"
argon2 = "0.5"
hkdf = "0.12"
hmac = "0.12"
sha2 = "0.10"
rand = "0.8"

# データ処理
reed-solomon-erasure = { version = "6", features = ["simd-accel"] }
zstd = "0.13"
bincode = "1"
serde = { version = "1", features = ["derive"] }

# ローカルDB
sled = "0.34"

# ユーティリティ
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
bytes = "1"
hex = "0.4"

# CLI用
clap = { version = "4", features = ["derive"] }
```

---

#### Step 2: core クレートのセットアップ

**ファイル**: `/AETHER/core/Cargo.toml`

```toml
[package]
name = "aether-core"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
rust-version.workspace = true
description = "AETHER Protocol Core Library"

[dependencies]
# 非同期
tokio.workspace = true

# ネットワーク
quinn.workspace = true
rustls.workspace = true
rcgen.workspace = true

# 暗号
ed25519-dalek.workspace = true
x25519-dalek.workspace = true
pqcrypto-kyber.workspace = true
chacha20poly1305.workspace = true
argon2.workspace = true
hkdf.workspace = true
hmac.workspace = true
sha2.workspace = true
rand.workspace = true

# データ処理
reed-solomon-erasure.workspace = true
zstd.workspace = true
bincode.workspace = true
serde.workspace = true

# ストレージ
sled.workspace = true

# ユーティリティ
thiserror.workspace = true
tracing.workspace = true
bytes.workspace = true
hex.workspace = true

[dev-dependencies]
tokio-test = "0.4"
```

---

