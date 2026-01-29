# Project AETHER 超詳細実装計画書

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

## Part 3: net/ モジュール（ネットワーク層）

### 3.1 `core/src/net/mod.rs`

**役割**: netモジュール配下のサブモジュールを公開

```rust
pub mod quic;
pub mod stun;
pub mod onion;
pub mod shaper;

pub use quic::{QuicClient, QuicServer};
pub use stun::StunResolver;
pub use onion::OnionRouter;
pub use shaper::TrafficShaper;
```

---

### 3.2 `core/src/net/quic.rs` - QUIC接続管理

**役割**: `quinn` を使ったQUIC通信の基盤

**主要な構造体・関数**:

#### `QuicServer`
- `new(config: &Config) -> Result<Self>`: サーバーインスタンス生成
- `start(&self) -> Result<()>`: 指定ポートでリッスン開始
- `accept(&self) -> Result<QuicConnection>`: 新規接続を受け入れ
- 内部で自己署名証明書を `rcgen` で生成

#### `QuicClient`
- `connect(addr: SocketAddr, server_name: &str) -> Result<QuicConnection>`: 接続確立
- 証明書検証をスキップする設定（P2Pなので自己署名OK）

#### `QuicConnection` (共通)
- `send(&self, data: &[u8]) -> Result<()>`: データ送信
- `recv(&self) -> Result<Vec<u8>>`: データ受信
- `open_bi_stream() -> Result<(SendStream, RecvStream)>`: 双方向ストリーム開設
- `close(&self)`: 接続クローズ

**処理フロー**:
1. サーバー/クライアント双方で `rustls` の設定を構築
2. `quinn::Endpoint` を作成
3. ハンドシェイク完了後、双方向ストリームでデータ送受信

---

### 3.3 `core/src/net/stun.rs` - NAT越え (STUN)

**役割**: STUNプロトコルで自分のグローバルIP/ポートを特定

**主要な構造体・関数**:

#### `StunResolver`
- `new(stun_servers: Vec<String>) -> Self`
- `resolve() -> Result<SocketAddr>`: 自分の外部アドレスを取得

**処理フロー**:
1. 複数のSTUNサーバー（Google, Cloudflare等）にBindingリクエストを送信
2. レスポンスから `XOR-MAPPED-ADDRESS` を抽出
3. 複数サーバーの結果を比較し、一致すれば信頼できる外部アドレスとして返す

**補足**:
- UDP Hole Punchingの前提条件として使用
- Symmetric NAT環境では機能しない可能性あり（将来的にTURNフォールバックを検討）

---

### 3.4 `core/src/net/onion.rs` - 3-Hop Onion Routing

**役割**: Tor風の多層暗号化で送信元IPを隠蔽

**主要な構造体**:

#### `OnionCircuit`
- 3つのHopノード情報と、各Hopとの共有秘密を保持

#### `OnionRouter`
- `build_circuit(dht: &Dht) -> Result<OnionCircuit>`:
  - DHTから3ノードを選択（異なるAS、高Node Age優先）
  - 各Hopと一時的なX25519鍵交換を実行
  - 共有秘密 `SS_1`, `SS_2`, `SS_3` を導出

- `send_through_circuit(circuit: &OnionCircuit, payload: &[u8], dest: SocketAddr) -> Result<()>`:
  1. Layer 3: `Enc(SS_3, payload)`
  2. Layer 2: `Enc(SS_2, [Hop3_addr | Layer3])`
  3. Layer 1: `Enc(SS_1, [Hop2_addr | Layer2])`
  4. Hop1に送信

#### `RelayNode` (リレーノード用)
- `handle_relay_packet(packet: &[u8]) -> Result<()>`:
  1. 自分の秘密鍵で最外層を復号
  2. 次のHopアドレスを取得
  3. 残りを次のHopに転送

---

### 3.5 `core/src/net/shaper.rs` - Traffic Shaping

**役割**: パケットをWebRTC/Zoomのビデオ通話に偽装

**主要な構造体**:

#### `TrafficShaper`
- `real_queue: mpsc::Sender<Vec<u8>>`: 実際に送りたいデータのキュー
- `conn: QuicConnection`: 送信先接続

#### `ShapingConfig`
```rust
struct ShapingConfig {
    fps: u32,                    // 30 or 60
    i_frame_interval_secs: f32,  // 2.0
    p_frame_avg_size: usize,     // 500 bytes
    p_frame_std_dev: usize,      // 200 bytes
    jitter_ms: u32,              // ±5ms
}
```

**処理フロー (`run()` ループ)**:
```
毎 33ms (30fps) ごとに:
  1. ジッター計算: 実際の待機時間 = 33ms ± rand(-5, +5)ms
  2. Iフレームタイミングか判定 (2秒ごと)
  3. if Iフレームタイミング:
       大きなパケット(5-15KB)を送信
     else if real_queueにデータあり:
       実データを送信（サイズがPフレームモデルより小さければパディング追加）
     else:
       ダミーパケット(Pフレームサイズ)を送信
```

**パケット構造**:
```
+--------+---------------+
| Flags  | Payload       |
| 1 byte | Variable      |
+--------+---------------+
Flags: 0x00=ダミー, 0x01=実データ
```
受信側はFlags=0x00のパケットを破棄

---

## Part 4: crypto/ モジュール（暗号層）

### 4.1 `core/src/crypto/mod.rs`

```rust
pub mod identity;
pub mod kem;
pub mod ratchet;
pub mod aead;

pub use identity::Identity;
pub use kem::HybridKem;
pub use ratchet::{DoubleRatchet, RatchetState};
pub use aead::Aead;
```

---

### 4.2 `core/src/crypto/identity.rs` - Ed25519 ID管理

**役割**: ユーザーのマスターIDとなるEd25519鍵ペアを管理

**主要な構造体**:

#### `Identity`
```rust
struct Identity {
    signing_key: ed25519_dalek::SigningKey,  // 秘密鍵
    verifying_key: ed25519_dalek::VerifyingKey,  // 公開鍵
}
```

**主要な関数**:
- `generate() -> Self`: 新規鍵ペア生成（`rand::rngs::OsRng`使用）
- `from_bytes(secret: [u8; 32]) -> Result<Self>`: 秘密鍵から復元
- `public_key_hash() -> [u8; 32]`: 公開鍵のSHA256ハッシュ（=ユーザーID）
- `sign(message: &[u8]) -> Signature`: メッセージ署名
- `verify(message: &[u8], signature: &Signature, pubkey: &VerifyingKey) -> Result<()>`: 署名検証

---

### 4.3 `core/src/crypto/kem.rs` - ハイブリッドKEM

**役割**: Kyber-768 + X25519 のハイブリッド鍵カプセル化

**なぜハイブリッド?**:
- X25519: 実績ある楕円曲線。現時点では安全
- Kyber: 耐量子暗号。将来の量子コンピュータに備える
- 両方を組み合わせることで「どちらかが破られても安全」を担保

**主要な構造体**:

#### `HybridKemKeyPair`
```rust
struct HybridKemKeyPair {
    x25519_secret: x25519_dalek::StaticSecret,
    x25519_public: x25519_dalek::PublicKey,
    kyber_secret: pqcrypto_kyber::SecretKey,
    kyber_public: pqcrypto_kyber::PublicKey,
}
```

**主要な関数**:
- `generate() -> Self`: 両方の鍵ペアを生成
- `encapsulate(recipient_public: &HybridKemPublicKey) -> (Ciphertext, SharedSecret)`:
  1. X25519: `DH(my_ephemeral, recipient_x25519_pk)` → `ss_x25519`
  2. Kyber: `Encaps(recipient_kyber_pk)` → `(ct_kyber, ss_kyber)`
  3. `SharedSecret = HKDF(ss_x25519 || ss_kyber)`
- `decapsulate(ciphertext: &Ciphertext) -> Result<SharedSecret>`:
  1. X25519とKyber両方のカプセルを復号
  2. 共有秘密を結合してHKDF

---

### 4.4 `core/src/crypto/ratchet.rs` - Double Ratchet

**役割**: Signalプロトコル互換のDouble Ratchet（メッセージ毎の鍵更新）

**主要な構造体**:

#### `RatchetState`
```rust
struct RatchetState {
    // DH Ratchet
    dh_keypair: x25519_dalek::StaticSecret,
    dh_remote_public: Option<x25519_dalek::PublicKey>,
    root_key: [u8; 32],

    // Symmetric Ratchet (送信用)
    sending_chain_key: [u8; 32],
    sending_message_number: u32,

    // Symmetric Ratchet (受信用)
    receiving_chain_key: [u8; 32],
    receiving_message_number: u32,

    // スキップされた鍵のキャッシュ（順序逆転対策）
    skipped_keys: HashMap<(u32, u32), [u8; 32]>,  // (chain_id, msg_num) -> message_key
}
```

#### `DoubleRatchet`
**初期化（X3DH後）**:
- `init_sender(shared_secret: [u8; 32], recipient_pubkey: PublicKey) -> Self`
- `init_receiver(shared_secret: [u8; 32], my_keypair: StaticSecret) -> Self`

**暗号化/復号**:
- `encrypt(plaintext: &[u8]) -> (RatchetHeader, Vec<u8>)`:
  1. Symmetric Ratchetを回してMessage Key導出
  2. Message KeyでAEAD暗号化
  3. ヘッダー（公開鍵、メッセージ番号）と暗号文を返す

- `decrypt(header: &RatchetHeader, ciphertext: &[u8]) -> Result<Vec<u8>>`:
  1. ヘッダーの公開鍵が新しければDH Ratchetを回す
  2. Symmetric Ratchetを回してMessage Key導出
  3. 復号

**順序逆転対策**:
- 相手のメッセージ番号が飛んでいたら、途中のMessage Keyを計算して`skipped_keys`に保存
- 後から届いたメッセージを`skipped_keys`から復号
- 1000件を超えたスキップ鍵は破棄

---

### 4.5 `core/src/crypto/aead.rs` - ChaCha20-Poly1305

**役割**: 認証付き暗号化のラッパー

**主要な関数**:
- `encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8>`:
  - ChaCha20-Poly1305で暗号化
  - 戻り値は `ciphertext || tag (16 bytes)`

- `decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>`:
  - タグ検証＋復号
  - 改竄検知時は `CryptoError::AuthenticationFailed` を返す

---

## Part 5: mailbox/ モジュール（分散ストレージ層）

### 5.1 `core/src/mailbox/mod.rs`

```rust
pub mod sharding;
pub mod client;
pub mod server;

pub use sharding::ShardingCodec;
pub use client::MailboxClient;
pub use server::MailboxServer;
```

---

### 5.2 `core/src/mailbox/sharding.rs` - Reed-Solomon分割/復元

**役割**: メッセージをErasure Codingで冗長化・分割

**主要な構造体**:

#### `ShardingCodec`
```rust
struct ShardingCodec {
    data_shards: usize,    // デフォルト: 3
    parity_shards: usize,  // デフォルト: 2
    // 合計5シャードのうち、任意の3つがあれば復元可能
}
```

**主要な関数**:
- `new(data: usize, parity: usize) -> Self`
- `encode(data: &[u8]) -> Result<Vec<Shard>>`:
  1. データを`data_shards`個に均等分割（パディングで揃える）
  2. `reed_solomon_erasure::ReedSolomon` で `parity_shards` 個のパリティを生成
  3. 各シャードに `shard_index` を付与して返す

- `decode(shards: Vec<Option<Shard>>) -> Result<Vec<u8>>`:
  1. `None` のシャードは欠損として扱う
  2. `data_shards` 個以上のシャードがあれば復元
  3. パディングを除去して元データを返す

#### `Shard`
```rust
struct Shard {
    index: u8,       // 0-4 (5シャードの場合)
    data: Vec<u8>,
}
```

---

### 5.3 `core/src/mailbox/client.rs` - Mailboxクライアント

**役割**: Mailboxノードへのデータ送受信を行うクライアント

**主要な構造体**:

#### `MailboxClient`
- 内部に `OnionRouter` を持ち、全通信は3-Hop経由

**主要な関数**:

- `put(receiver_id: &[u8; 32], message_id: &[u8; 16], shards: Vec<Shard>, mailbox_nodes: Vec<NodeInfo>) -> Result<()>`:
  1. 各シャードに対してPoWを計算（Argon2id）
  2. シャードを対応するMailboxノードに並列PUT
  3. `data_shards` 個以上成功したら完了

- `list(receiver_id: &[u8; 32], mailbox_nodes: Vec<NodeInfo>) -> Result<Vec<MessageId>>`:
  - 各Mailboxに `LIST` リクエストを送り、未読メッセージID一覧を取得
  - 重複除去して返す

- `get(receiver_id: &[u8; 32], message_id: &[u8; 16], mailbox_nodes: Vec<NodeInfo>) -> Result<Vec<Option<Shard>>>`:
  1. 各Mailboxに `GET` リクエスト
  2. `data_shards` 個集まった時点で打ち切り（帯域節約）
  3. 集まったシャードを返す

- `delete(receiver_id: &[u8; 32], message_id: &[u8; 16], signature: &Signature, mailbox_nodes: Vec<NodeInfo>) -> Result<()>`:
  - 署名付き `DELETE` リクエストを全Mailboxに送信
  - Burn-on-Read完了

---

### 5.4 `core/src/mailbox/server.rs` - Mailboxサーバー

**役割**: 暗号化シャードを保持する「見えない私書箱」

**主要な構造体**:

#### `MailboxServer`
```rust
struct MailboxServer {
    db: sled::Db,                    // ローカルKVS
    config: MailboxConfig,
    pow_verifier: PowVerifier,
}

struct MailboxConfig {
    capacity_per_user_mb: u64,       // 50MB
    ttl_hours: u64,                  // 48時間
    gc_interval_secs: u64,           // 300秒
}
```

**DBスキーマ (Key-Value)**:
```
Key:   [receiver_hash (32B)] | [message_id (16B)] | [shard_index (1B)]
Value: [timestamp (8B)] | [shard_data (variable)]
```

**主要な関数**:

- `handle_put(req: PutRequest) -> Result<PutResponse>`:
  1. PoW検証（Argon2idソリューションが難易度を満たすか）
  2. 容量チェック（ユーザー別の使用量を計算）
  3. 容量超過時はFIFOで古いデータを削除
  4. DBに書き込み

- `handle_list(req: ListRequest) -> Result<ListResponse>`:
  - `receiver_hash` プレフィックスでスキャン
  - ユニークな `message_id` を抽出して返す

- `handle_get(req: GetRequest) -> Result<GetResponse>`:
  - キーで検索してシャードを返す
  - 存在しなければ `NotFound`

- `handle_delete(req: DeleteRequest) -> Result<DeleteResponse>`:
  1. 署名検証（送信者が正当な受信者か）
  2. DBから物理削除

**バックグラウンドタスク**:

#### `GarbageCollector` (別タスク)
```
tokio::spawn で常駐:
  loop {
    sleep(gc_interval_secs)

    // TTL超過データの削除
    for (key, value) in db.iter() {
      if now - timestamp > ttl_hours {
        db.remove(key)
      }
    }
  }
```

---

## Part 6: dht/, storage/, protocol/ モジュール

### 6.1 `core/src/dht/mod.rs` - 分散ハッシュテーブル

```rust
pub mod kbucket;
pub mod rpc;

pub use kbucket::RoutingTable;
pub use rpc::DhtRpc;
```

---

### 6.2 `core/src/dht/kbucket.rs` - Kademlia k-bucket

**役割**: 分散ノード発見のためのKademliaルーティングテーブル

**主要な構造体**:

#### `RoutingTable`
```rust
struct RoutingTable {
    local_id: [u8; 32],           // 自分のNode ID
    buckets: [KBucket; 256],      // 256個のk-bucket
}

struct KBucket {
    nodes: VecDeque<NodeInfo>,    // 最大k個（通常k=20）
    last_updated: Instant,
}

struct NodeInfo {
    id: [u8; 32],
    addr: SocketAddr,
    age: u64,                     // 稼働時間（秒）
    last_seen: Instant,
}
```

**主要な関数**:

- `xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32]`: XOR距離計算
- `bucket_index(distance: &[u8; 32]) -> usize`: 距離からbucketインデックスを算出
- `insert(&mut self, node: NodeInfo)`:
  - 既存ノードなら末尾に移動
  - 新規でbucketが満杯なら、最も古いノードにPingして応答なければ置換
- `find_closest(&self, target: &[u8; 32], count: usize) -> Vec<NodeInfo>`:
  - XOR距離が近い順に`count`個のノードを返す

---

### 6.3 `core/src/dht/rpc.rs` - DHT RPC

**役割**: Kademliaの基本RPC（FIND_NODE, FIND_VALUE, STORE）を実装

**主要な関数**:

- `find_node(target: &[u8; 32]) -> Result<Vec<NodeInfo>>`:
  1. ローカルルーティングテーブルから近いノードを取得
  2. それらにFIND_NODEリクエストを並列送信
  3. 返ってきたノードに再帰的に問い合わせ
  4. ターゲットに最も近いk個を返す

- `find_value(key: &[u8; 32]) -> Result<Option<Vec<u8>>>`:
  - FIND_NODE同様に探索
  - 値を持つノードを見つけたら即返す

- `store(key: &[u8; 32], value: &[u8]) -> Result<()>`:
  - キーに最も近いk個のノードにSTOREリクエスト

**Bootstrap処理**:
```
1. ハードコードされたBootstrapノードに接続
2. 自分のNode IDで FIND_NODE を実行
3. 返ってきたノードをルーティングテーブルに追加
4. ルーティングテーブルが十分埋まるまで繰り返し
```

---

### 6.4 Lookup Token方式 - 秘匿DHT検索

**背景**:
通常のDHTでは `Key = Hash(UserID)` で検索するため、UserIDを知っていれば誰でも検索でき、
DHT参加ノードは「誰が誰を探しているか」を監視可能です。
これはAETHERの匿名性要件と相反するため、**Lookup Token方式**を採用します。

**設計原則**:
1. DHT上のキーは「Tokenを知る者だけが計算できる」形式にする
2. DHT上の値は暗号化し、共有秘密を持つ者だけが復号できる
3. Tokenは連絡先交換時にオフラインで共有する

---

#### 6.4.1 連絡先交換時のデータ構造

Bobが自分の連絡先をAliceに渡す際、以下の情報を含めます:

```rust
struct ContactBundle {
    /// 公開鍵 (Ed25519)
    pub pub_key: [u8; 32],

    /// DHT検索用トークン
    /// = HMAC-SHA256(user_secret, "aether_lookup_v1")
    pub lookup_token: [u8; 32],

    /// Prekey Bundle (X3DHの初期鍵交換用)
    pub prekey_bundle: PrekeyBundle,

    /// Mailbox Hint (オプション: 現在使用中のMailboxノード)
    pub mailbox_hint: Option<Vec<SocketAddr>>,

    /// 署名
    pub signature: [u8; 64],
}
```

---

#### 6.4.2 DHT登録 (Publish)

ユーザーが自分のMailbox情報をDHTに登録する際:

```
1. DHT Key の計算:
   dht_key = SHA256(lookup_token)

2. DHT Value の構築:
   plaintext = bincode::serialize(MailboxInfo)
   nonce = random 12 bytes
   derived_key = HKDF(user_secret, "aether_dht_value_v1")
   ciphertext = ChaCha20Poly1305.encrypt(derived_key, nonce, plaintext)

3. 署名:
   signature = Ed25519.sign(private_key, dht_key || ciphertext)

4. DHT STORE:
   Key:   dht_key (32 bytes)
   Value: nonce (12 bytes) || ciphertext || signature (64 bytes)
```

---

#### 6.4.3 DHT検索 (Lookup)

AliceがBobのMailboxを探す際:

```
1. Token から DHT Key を計算:
   dht_key = SHA256(bob_lookup_token)

2. DHT FIND_VALUE(dht_key) を実行
   → 暗号化された Value を取得

3. 復号:
   derived_key = HKDF(共有秘密 or Token派生鍵, "aether_dht_value_v1")
   plaintext = ChaCha20Poly1305.decrypt(derived_key, nonce, ciphertext)

4. 署名検証:
   Ed25519.verify(bob_public_key, dht_key || ciphertext, signature)

5. MailboxInfo をデシリアライズして使用
```

---

#### 6.4.4 セキュリティ特性

| 特性 | 説明 |
|:---|:---|
| **検索の秘匿性** | Lookup Tokenを知らないとdht_keyを計算できない。DHT参加者は「ランダムなハッシュ値の検索」としか認識できない。 |
| **内容の秘匿性** | Valueは暗号化されており、鍵を持たない者には復号不能。 |
| **Sybil耐性** | 攻撃者がDHTを監視しても、クエリの意味が分からないため、ターゲット特定が困難。 |
| **改ざん検知** | 全Valueに署名が付与されており、偽のMailbox情報を注入できない。 |

---

#### 6.4.5 Tokenのローテーション

長期間同じTokenを使用するとパターン分析される可能性があるため、
オプションで定期的なローテーションをサポートします:

```rust
/// 新しいLookup Tokenを生成し、古いエントリと並行して登録
fn rotate_lookup_token(&mut self) -> Result<()> {
    let old_token = self.current_token;
    let new_token = self.generate_token();

    // 新しいTokenでDHTに登録
    self.publish_to_dht(new_token)?;

    // 古いTokenはTTL経過後に自然消滅させる
    // （明示的な削除は不要、DHTのTTLに任せる）

    self.current_token = new_token;
    Ok(())
}
```

---

### 6.5 `core/src/storage/mod.rs` - ローカルストレージ

```rust
pub mod local_db;
pub mod keystore;

pub use local_db::LocalDb;
pub use keystore::KeyStore;
```

---

### 6.5 `core/src/storage/local_db.rs` - 暗号化ローカルDB

**役割**: ローカルに保存するデータ（連絡先、会話履歴等）を暗号化して管理

**主要な構造体**:

#### `LocalDb`
```rust
struct LocalDb {
    db: sled::Db,
    encryption_key: [u8; 32],  // Master Keyで暗号化
}
```

**ストレージ構造**:
```
contacts/[user_id]     -> ContactInfo (暗号化)
conversations/[conv_id] -> ConversationMeta
messages/[conv_id]/[msg_id] -> Message (暗号化)
ratchet_states/[user_id] -> RatchetState (暗号化)
```

**全データはAEADで暗号化してから保存**

---

### 6.6 `core/src/storage/keystore.rs` - 鍵管理

**役割**: Master Keyの生成・保護・復元

**Tier判定**:
```rust
enum SecurityTier {
    Tier1,  // Secure Enclave/StrongBox搭載
    Tier2,  // TPM/Keychain利用可能
    Tier3,  // ソフトウェアのみ
}
```

**処理フロー**:

#### Tier 1 (iOS/新しめのAndroid)
1. Secure Enclave内でMaster Keyを生成
2. PINはEnclaveに渡され、内部で検証
3. Master Keyは絶対に外部に出ない

#### Tier 2/3 (Desktop, 古いデバイス)
1. ユーザーのPIN/パスフレーズを入力
2. `Argon2id(PIN, salt, t=3, m=64MB, p=4)` でKey Encryption Key (KEK)を導出
3. Master KeyをKEKで暗号化してファイルに保存
4. Tier3では8文字以上のパスフレーズを強制

**Duress/Panic PIN**:
```rust
struct PinConfig {
    normal_pin_hash: [u8; 32],
    decoy_pin_hash: Option<[u8; 32]>,
    panic_pin_hash: Option<[u8; 32]>,
}

fn unlock(pin: &str) -> UnlockResult {
    if verify(pin, normal_pin_hash) {
        UnlockResult::Normal(master_key)
    } else if verify(pin, decoy_pin_hash) {
        UnlockResult::Decoy(dummy_key)
    } else if verify(pin, panic_pin_hash) {
        // Master Keyを物理削除
        secure_erase(master_key_file);
        UnlockResult::Panic
    } else {
        UnlockResult::Failed
    }
}
```

---

### 6.7 `core/src/protocol/mod.rs` - ワイヤープロトコル

```rust
pub mod wire;

pub use wire::{Packet, PacketType, serialize, deserialize};
```

---

### 6.8 `core/src/protocol/wire.rs` - パケットシリアライズ

**役割**: ネットワーク上のバイナリフォーマットを定義

**パケット構造**:
```
+--------+--------+------------------+-----------------+
| Type   | Flags  | Payload Length   | Payload         |
| 1 byte | 1 byte | 4 bytes (u32 BE) | Variable        |
+--------+--------+------------------+-----------------+
```

**PacketType enum**:
```rust
#[repr(u8)]
enum PacketType {
    // Onion Routing
    OnionRelay = 0x01,

    // Mailbox操作
    MailboxPut = 0x10,
    MailboxGet = 0x11,
    MailboxList = 0x12,
    MailboxDelete = 0x13,
    MailboxResponse = 0x1F,

    // DHT
    DhtFindNode = 0x20,
    DhtFindValue = 0x21,
    DhtStore = 0x22,
    DhtResponse = 0x2F,

    // E2EE メッセージ
    RatchetMessage = 0x30,

    // ハンドシェイク
    X3dhInit = 0x40,
    X3dhResponse = 0x41,
}
```

**主要な関数**:
- `serialize(packet: &Packet) -> Vec<u8>`: bincode + 手動ヘッダー構築
- `deserialize(data: &[u8]) -> Result<Packet>`: ヘッダー解析 + bincode

---

## Part 7: cli/ 実装

### 7.1 `cli/src/main.rs` - CLIエントリポイント

**役割**: 開発・検証用のコマンドラインツール

**CLIコマンド構成 (clap)**:

```rust
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 新しいIDを生成
    Init,

    /// ピアに直接接続してチャット (Step 1検証用)
    Chat {
        #[arg(short, long)]
        peer: String,  // "IP:PORT" or "PEER_ID"
    },

    /// Mailboxサーバーを起動
    Mailbox {
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },

    /// メッセージ送信
    Send {
        #[arg(short, long)]
        to: String,     // 受信者のUser ID (hex)
        #[arg(short, long)]
        message: String,
    },

    /// 新着メッセージを確認
    Recv,

    /// ネットワーク情報を表示
    Info,
}
```

**各コマンドの処理**:

#### `init`
1. `Identity::generate()` で新しいEd25519鍵ペアを生成
2. `~/.aether/identity.key` に秘密鍵を保存（Argon2で暗号化）
3. User ID（公開鍵ハッシュ）を表示

#### `chat`
1. STUNで自分の外部アドレスを取得
2. 指定されたピアにQUIC接続
3. REPLモードで入出力をやり取り
4. Traffic Shaping有効ならダミーパケットも送信

#### `mailbox`
1. `MailboxServer::new()` でサーバーインスタンス作成
2. 指定ポートでリッスン開始
3. PUT/GET/LIST/DELETEリクエストを処理

#### `send`
1. ローカルDBから受信者のPrekey Bundleを取得（なければDHTから）
2. X3DHハンドシェイク（初回のみ）
3. Double Ratchetでメッセージを暗号化
4. Reed-Solomonで5シャードに分割
5. 各シャードを受信者のMailboxにPUT

#### `recv`
1. 自分のMailboxリストを取得
2. 各MailboxにLIST→GETを実行
3. シャードを復元、Double Ratchetで復号
4. 成功したらDELETE（Burn-on-Read）

---

## Part 8: 開発順序（ステップバイステップ）

### Phase 1: 基盤構築 (Week 1-2)

```
Day 1-2: プロジェクト初期化
├── [ ] Cargo.toml (workspace)
├── [ ] core/Cargo.toml
├── [ ] cli/Cargo.toml
├── [ ] core/src/lib.rs (空のmod宣言)
└── [ ] core/src/error.rs

Day 3-4: QUIC基盤
├── [ ] core/src/net/mod.rs
├── [ ] core/src/net/quic.rs
│   ├── QuicServer (自己署名証明書生成、accept)
│   └── QuicClient (connect)
└── [ ] cli: `chat` コマンド (localhost同士でテスト)

Day 5-7: NAT越え
├── [ ] core/src/net/stun.rs
│   └── StunResolver (Google STUN使用)
└── [ ] cli: 異なるネットワーク間でchatテスト
```

### Phase 2: 暗号化 (Week 3-4)

```
Day 8-10: 基本暗号
├── [ ] core/src/crypto/mod.rs
├── [ ] core/src/crypto/identity.rs
├── [ ] core/src/crypto/aead.rs
└── [ ] テスト: Ed25519署名、ChaCha20暗号化

Day 11-14: ハイブリッドKEM & Double Ratchet
├── [ ] core/src/crypto/kem.rs
├── [ ] core/src/crypto/ratchet.rs
└── [ ] テスト: 2者間でDouble Ratchetメッセージ交換
```

### Phase 3: Mailbox (Week 5-6)

```
Day 15-17: シャーディング
├── [ ] core/src/mailbox/mod.rs
├── [ ] core/src/mailbox/sharding.rs
└── [ ] テスト: Reed-Solomon encode/decode

Day 18-21: Mailboxサーバー
├── [ ] core/src/mailbox/server.rs
├── [ ] cli: `mailbox` コマンド
└── [ ] テスト: PUT/GET/LIST/DELETE

Day 22-24: Mailboxクライアント
├── [ ] core/src/mailbox/client.rs
├── [ ] cli: `send` / `recv` コマンド
└── [ ] テスト: オフラインメッセージング
```

### Phase 4: 分散ネットワーク (Week 7-8)

```
Day 25-28: DHT
├── [ ] core/src/dht/mod.rs
├── [ ] core/src/dht/kbucket.rs
├── [ ] core/src/dht/rpc.rs
└── [ ] テスト: Bootstrap、FIND_NODE

Day 29-32: Onion Routing
├── [ ] core/src/net/onion.rs
└── [ ] テスト: 3-Hop経由での通信
```

### Phase 5: ステルス化 (Week 9-10)

```
Day 33-35: Traffic Shaping
├── [ ] core/src/net/shaper.rs
└── [ ] Wiresharkで検証

Day 36-38: ローカルストレージ
├── [ ] core/src/storage/local_db.rs
├── [ ] core/src/storage/keystore.rs
└── [ ] テスト: 暗号化DB、PIN管理
```

### Phase 6: 統合 (Week 11-12)

```
Day 39-42: 全コンポーネント統合
├── [ ] cli: 全コマンドの統合テスト
└── [ ] E2Eテスト: Alice → Mailbox → Bob

Day 43-45: ドキュメント & リファクタリング
├── [ ] READMEの整備
├── [ ] rustdocコメント追加
└── [ ] コード整理
```

---

## Part 9: データフロー図

### 9.1 メッセージ送信フロー

```
Alice                           DHT                    Mailbox Nodes (5個)                Bob
  |                              |                            |                            |
  |-- (1) FIND_VALUE(Bob_ID) --->|                            |                            |
  |<---- Bob's Prekey Bundle ----|                            |                            |
  |                              |                            |                            |
  |-- (2) X3DH Handshake --------|----------------------------|--------------------------->|
  |                              |                            |                     [Prekey消費]
  |                              |                            |                            |
  |-- (3) Double Ratchet暗号化 --|                            |                            |
  |      [plaintext → ciphertext]|                            |                            |
  |                              |                            |                            |
  |-- (4) Reed-Solomon分割 ------|                            |                            |
  |      [ciphertext → 5 shards] |                            |                            |
  |                              |                            |                            |
  |-- (5) Onion Routing ---------|                            |                            |
  |      [各shard を 3-Hop経由]   |                            |                            |
  |                              |                            |                            |
  |------------------------------------------PUT(shard_0) --->| M0                         |
  |------------------------------------------PUT(shard_1) --->| M1                         |
  |------------------------------------------PUT(shard_2) --->| M2                         |
  |------------------------------------------PUT(shard_3) --->| M3                         |
  |------------------------------------------PUT(shard_4) --->| M4                         |
  |                              |                            |                            |
  |                              |                            | [保存完了]                  |
```

### 9.2 メッセージ受信フロー

```
Bob                             Mailbox Nodes
  |                                  |
  |-- (1) LIST(Bob_ID) ------------->| M0, M1, M2, M3, M4
  |<---- [msg_id_1, msg_id_2, ...] --|
  |                                  |
  |-- (2) GET(msg_id_1) ------------>| M0
  |<---- shard_0 --------------------|
  |-- (2) GET(msg_id_1) ------------>| M1
  |<---- shard_1 --------------------|
  |-- (2) GET(msg_id_1) ------------>| M2
  |<---- shard_2 --------------------|
  |      [3シャード揃った！打ち切り]  |
  |                                  |
  |-- (3) Reed-Solomon復元 --------->|
  |      [3 shards → ciphertext]     |
  |                                  |
  |-- (4) Double Ratchet復号 ------->|
  |      [ciphertext → plaintext]    |
  |                                  |
  |-- (5) DELETE(msg_id_1, sig) ---->| M0, M1, M2, M3, M4
  |      [Burn-on-Read完了]          | [物理削除]
```

---

## Part 10: アーキテクチャ改訂 (2026-01-28)

### 10.1 設計変更の背景

従来のDHTベース設計には以下の根本的問題があることが判明：

| 問題 | 説明 |
|:---|:---|
| **IP露出** | DHTに参加した時点で自分のIPが全ノードに公開される |
| **検索の可視性** | 「誰が誰を探しているか」がDHTノードに分かる |
| **Mailbox受信者特定** | Mailbox Key = Hash(受信者ID) のため、誰宛てか分かる |

### 10.2 新アーキテクチャ概要

**解決策**: DHT-Free + Relay Network + シュレーディンガーMailbox

```
┌─────────────────────────────────────────────────────────────┐
│                AETHER v2 ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  [ユーザー]                                                 │
│      │                                                      │
│      │ Onion暗号化（3-Hop）                                │
│      ▼                                                      │
│  [Relay Network]                                            │
│      │                                                      │
│      ├── Gossip: Hint配信（誰宛てか暗号化）                │
│      │                                                      │
│      └── Mailbox: メッセージ保存（ランダムKey）            │
│                                                             │
│  特徴:                                                      │
│    ✅ IP は入口 Relay にしか見えない                       │
│    ✅ 「誰が誰に」は誰にも分からない                       │
│    ✅ Mailbox はランダムなキーのストレージとしか見えない   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Part 11: シュレーディンガーMailbox

### 11.1 コンセプト

**「受信者が取得するまで、誰宛てか確定しない」**

```
従来方式:
  Mailbox Key = Hash(受信者ID)
  → Mailboxノードは「誰宛て」か知っている

シュレーディンガー方式:
  Mailbox Key = Hash(ランダムNonce)
  → Mailboxノードは「意味不明なランダムキー」としか見えない
  → 誰宛てかは、受信者本人しか分からない
```

### 11.2 プロトコルフロー

```
┌─────────────────────────────────────────────────────────────────────┐
│                SCHRÖDINGER MAILBOX PROTOCOL                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  [SEND PHASE] Alice → Bob                                           │
│                                                                     │
│  1. Nonce = Random(32 bytes)                                        │
│  2. Mailbox_Key = SHA256(Nonce)                                     │
│  3. Message_Encrypted = ChaCha20Poly1305(SharedSecret, Message)     │
│  4. PUT(Mailbox_Key, Message_Encrypted) via Relay                   │
│  5. Hint = Enc(SharedSecret, Nonce || Message_ID || Timestamp)      │
│  6. Gossip broadcast(Hint)                                          │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  [RECEIVE PHASE] Bob                                                │
│                                                                     │
│  1. 全 Hint を受信（Gossip経由）                                    │
│  2. 各 Hint を全コンタクトの SharedSecret で復号を試す              │
│     → 復号成功 = 自分宛ての Hint                                   │
│  3. Hint から Nonce を取得                                          │
│  4. Mailbox_Key = SHA256(Nonce)                                     │
│  5. GET(Mailbox_Key) via Relay                                      │
│  6. Message を SharedSecret で復号                                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 11.3 ワイヤーフォーマット

#### Hint パケット (77 bytes)

```rust
struct HintPacket {
    version: u8,           // 1 byte - プロトコルバージョン (0x01)
    blind_tag: [u8; 4],    // 4 bytes - HMAC(SharedSecret, hint_nonce)[0:4]
    hint_nonce: [u8; 12],  // 12 bytes - 暗号化用 Nonce
    ciphertext: [u8; 48],  // 48 bytes - 暗号化された Hint 本体
    auth_tag: [u8; 16],    // 16 bytes - Poly1305 認証タグ
}

// Ciphertext の中身（復号後）
struct HintPayload {
    nonce: [u8; 32],       // Mailbox_Key 計算用
    message_id: u64,       // メッセージ識別子
    timestamp: u64,        // UNIX timestamp
}
```

#### Mailbox PUT 構造

```rust
struct MailboxEntry {
    mailbox_key: [u8; 32],  // SHA256(Nonce)
    message_nonce: [u8; 12],// 暗号化用 Nonce
    ciphertext: Vec<u8>,    // 暗号化されたメッセージ
    auth_tag: [u8; 16],     // Poly1305 認証タグ
    ttl: u32,               // 生存時間（秒）
    pow_proof: [u8; 8],     // スパム防止用 PoW
}
```

### 11.4 暗号構成

```rust
// 共有秘密の導出（X3DH後）
shared_secret = X3DH(Alice_Private, Bob_Public, ...)

// メッセージ暗号化
message_key = HKDF(shared_secret, "aether_message_v1")
message_nonce = random(12)
ciphertext = ChaCha20Poly1305::encrypt(message_key, message_nonce, message)

// Hint 暗号化
hint_key = HKDF(shared_secret, "aether_hint_v1")
hint_nonce = random(12)
blind_tag = HMAC(shared_secret, hint_nonce)[0:4]
hint_ciphertext = ChaCha20Poly1305::encrypt(hint_key, hint_nonce, hint_payload)
```

### 11.5 Blind Tag による高速フィルタリング

全 Hint を全コンタクトで復号するのは O(Hints × Contacts) で重い。
Blind Tag で事前フィルタリングすることで効率化。

```rust
impl SchrodingerMailbox {
    /// Hint を処理（高速フィルタリング付き）
    pub fn process_hint(&self, hint: &HintPacket) -> Option<Message> {
        // 1. Blind Tag でフィルタリング（O(1) ハッシュルックアップ）
        let expected_tags: HashMap<[u8; 4], &SharedSecret> = self.precompute_tags(&hint.hint_nonce);

        let shared_secret = expected_tags.get(&hint.blind_tag)?;

        // 2. 一致したら復号を試す
        let hint_key = hkdf(shared_secret, b"aether_hint_v1");
        let payload = decrypt(&hint_key, &hint.ciphertext)?;

        // 3. Mailbox から取得
        let mailbox_key = sha256(&payload.nonce);
        let encrypted_message = self.relay_client.get(&mailbox_key)?;

        // 4. メッセージ復号
        let message_key = hkdf(shared_secret, b"aether_message_v1");
        decrypt(&message_key, &encrypted_message).ok()
    }
}
```

### 11.6 セキュリティ特性

| 特性 | 説明 |
|:---|:---|
| **Mailbox匿名性** | Key はランダム。誰宛てか Mailbox には不明 |
| **Hint匿名性** | 暗号化済み。復号には SharedSecret 必要 |
| **送信者匿名性** | Relay + Onion 経由で送信。IP 不明 |
| **受信者匿名性** | Gossip で全員が受信。誰が Hint を使ったか不明 |
| **誤検知率** | Blind Tag 4バイト = 1/2^32 ≈ 0.00000002% |

---

## Part 12: Relay Network

### 12.1 概要

Relay = 中継ノード。ユーザーは直接通信せず、Relay を経由する。

```
[通常の通信]
Alice (IP: 1.1.1.1) ────────────────→ Bob (IP: 2.2.2.2)
                    → Bobは Aliceの IP を知る

[Relay経由の通信]
Alice ───→ Relay1 ───→ Relay2 ───→ Relay3 ───→ 宛先
      Onion暗号化で各Relayは前後しか分からない
```

### 12.2 Relay Network 構成

```
┌─────────────────────────────────────────────────────────────┐
│              AETHER PUBLIC RELAY NETWORK                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  [ユーザー層]                                               │
│      │                                                      │
│      │ IP見える（入口Relayのみ）                           │
│      ▼                                                      │
│  [入口 Relay]  ←─── ハードコードまたは紹介で取得           │
│      │                                                      │
│      │ Onion暗号化                                          │
│      ▼                                                      │
│  [中間 Relay]                                               │
│      │                                                      │
│      │ Onion暗号化                                          │
│      ▼                                                      │
│  [出口 Relay]                                               │
│      │                                                      │
│      │ 宛先へ転送（E2EE維持）                              │
│      ▼                                                      │
│  [Mailbox / 相手のRelay]                                    │
│                                                             │
│  各Relayが知っていること:                                   │
│    入口: ユーザーのIP、次のRelay                           │
│    中間: 前のRelay、次のRelay                               │
│    出口: 前のRelay、宛先                                    │
│                                                             │
│  → 誰も全体像を知らない                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 12.3 Relay クライアント実装

```rust
// core/src/net/relay.rs

pub struct RelayClient {
    entry_relay: SocketAddr,
    circuit: Option<OnionCircuit>,
    quic_client: QuicClient,
}

impl RelayClient {
    /// 3-Hop回路を構築
    pub async fn build_circuit(&mut self) -> Result<()> {
        // 1. 入口Relayに接続
        let entry_conn = self.quic_client.connect(self.entry_relay).await?;

        // 2. 入口Relayから中間Relayリストを取得
        let middle_relays = self.fetch_relay_list(&entry_conn).await?;

        // 3. ランダムに中間・出口Relayを選択
        let middle = middle_relays.choose(&mut rand::thread_rng())?;
        let exit = middle_relays.choose(&mut rand::thread_rng())?;

        // 4. Onion回路を構築
        self.circuit = Some(OnionCircuit::new(
            self.entry_relay,
            *middle,
            *exit,
        ));

        Ok(())
    }

    /// Mailbox に PUT（Onion経由）
    pub async fn put(&self, key: &[u8; 32], value: &[u8]) -> Result<()> {
        let circuit = self.circuit.as_ref().ok_or(Error::NoCircuit)?;
        let onion_packet = circuit.wrap(b"PUT", key, value)?;
        self.send_onion(onion_packet).await
    }

    /// Mailbox から GET（Onion経由）
    pub async fn get(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        let circuit = self.circuit.as_ref().ok_or(Error::NoCircuit)?;
        let onion_packet = circuit.wrap(b"GET", key, &[])?;
        self.send_onion_and_receive(onion_packet).await
    }
}
```

### 12.4 Gossip Protocol

```rust
// core/src/net/gossip.rs

pub struct GossipClient {
    relay_client: RelayClient,
    seen_hints: LruCache<[u8; 32], ()>,  // 重複排除用
}

impl GossipClient {
    /// Hint をネットワークにブロードキャスト
    pub async fn broadcast(&self, hint: &HintPacket) -> Result<()> {
        // Relay 経由で送信（送信元IP秘匿）
        let packet = GossipPacket {
            ttl: 5,  // 最大5ホップまで伝播
            hint: hint.clone(),
        };
        self.relay_client.gossip_send(&packet).await
    }

    /// Hint を受信（Relay経由）
    pub async fn receive(&mut self) -> Result<HintPacket> {
        loop {
            let packet = self.relay_client.gossip_receive().await?;

            // 重複チェック
            let hint_hash = sha256(&packet.hint.to_bytes());
            if self.seen_hints.contains(&hint_hash) {
                continue;
            }
            self.seen_hints.put(hint_hash, ());

            return Ok(packet.hint);
        }
    }
}
```

### 12.5 Bootstrap（初回接続）

```rust
// 初回起動時のRelay発見

const BOOTSTRAP_RELAYS: &[&str] = &[
    "relay1.aether.network:8443",
    "relay2.aether.network:8443",
    "relay3.aether.network:8443",
];

impl RelayClient {
    pub async fn bootstrap() -> Result<Self> {
        // 1. ハードコードされたRelayに接続を試みる
        for relay_addr in BOOTSTRAP_RELAYS {
            if let Ok(client) = Self::connect(relay_addr).await {
                return Ok(client);
            }
        }

        // 2. 全て失敗した場合はエラー
        Err(Error::BootstrapFailed)
    }
}
```

---

## Part 13: 遅延分析

### 13.1 3-Hop Onion の遅延見積もり

```
各Hop の遅延（片道）:
  - 同一国内: 10-30ms
  - 近い大陸間: 50-80ms
  - 遠い大陸間: 100-150ms

3-Hop 片道:
  最良（国内）: 3 × 20ms = 60ms
  平均:         3 × 40ms = 120ms
  最悪（世界中）: 3 × 100ms = 300ms
```

### 13.2 パターン別遅延

| パターン | 構成 | 遅延 |
|:---|:---|:---|
| 直接配信 | 送信Onion(120ms) + Mailbox(10ms) + 受信Onion(120ms) | **約250ms** |
| Gossip配信 | 送信Onion(120ms) + Gossip(100ms) + 受信Onion(120ms) | **約340ms** |
| 最適化版 | 双方向Onion(240ms) | **約240ms** |

### 13.3 既存技術との比較

| 技術 | 遅延 | 備考 |
|:---|:---|:---|
| Telegram | 50-100ms | 中央サーバー経由 |
| Signal | 100-200ms | 中央サーバー経由 |
| Tor Hidden Service | 500-2000ms | 6-Hop (3+3) |
| I2P | 500-3000ms | Garlic Routing |
| **AETHER** | **200-350ms** | 3-Hop Onion |

---

## Part 14: 更新されたデータフロー

### 14.1 メッセージ送信フロー（シュレーディンガー方式）

```
Alice                           Relay Network              Mailbox/Gossip               Bob
  |                                   |                         |                        |
  |-- (1) 3-Hop回路構築 ------------->|                         |                        |
  |                                   |                         |                        |
  |-- (2) Nonce生成 ------------------|                         |                        |
  |      Mailbox_Key = SHA256(Nonce)  |                         |                        |
  |                                   |                         |                        |
  |-- (3) メッセージ暗号化 ------------|                         |                        |
  |      ChaCha20Poly1305(SharedSecret)|                        |                        |
  |                                   |                         |                        |
  |-- (4) PUT(Mailbox_Key, Encrypted) via Onion --------------->| Mailbox               |
  |                                   |                         | [ランダムKeyとして保存]|
  |                                   |                         |                        |
  |-- (5) Hint生成 -------------------|                         |                        |
  |      Enc(SharedSecret, Nonce||ID) |                         |                        |
  |                                   |                         |                        |
  |-- (6) Gossip broadcast(Hint) via Onion -------------------->| Gossip Network        |
  |                                   |                         |      ↓                |
  |                                   |                         | [全ノードに拡散]       |
  |                                   |                         |      ↓                |
  |                                   |                         |<----- Hint到着 ------>|
```

### 14.2 メッセージ受信フロー（シュレーディンガー方式）

```
Bob                             Relay Network              Mailbox/Gossip
  |                                   |                         |
  |<-- (1) Gossip経由でHint受信 ------|-------------------------|
  |                                   |                         |
  |-- (2) Blind Tagでフィルタリング --|                         |
  |      → 自分のコンタクトと一致？   |                         |
  |                                   |                         |
  |-- (3) Hint復号 -------------------|                         |
  |      → Nonce取得                  |                         |
  |                                   |                         |
  |-- (4) Mailbox_Key = SHA256(Nonce) |                         |
  |                                   |                         |
  |-- (5) GET(Mailbox_Key) via Onion ----------------------->| Mailbox
  |                                   |                      | [ランダムKeyで検索]
  |<-- (6) Encrypted Message --------|<-------------------------|
  |                                   |                         |
  |-- (7) メッセージ復号 -------------|                         |
  |      ChaCha20Poly1305(SharedSecret)|                        |
  |                                   |                         |
  |-- (8) DELETE(Mailbox_Key) via Onion -------------------->| Mailbox
  |                                   |                      | [Burn-on-Read]
```

---

## Part 15: 残課題

- [ ] Relay ノードの信頼モデル（ボランティア？インセンティブ？）
- [ ] Relay リストの安全な配布方法
- [ ] Gossip のスケーラビリティ（階層化？TTL調整？）
- [ ] Sybil Relay 対策（Node Age、PoW、招待制）
- [ ] Hint 配信の帯域最適化
- [ ] シュレーディンガーMailbox の詳細実装

---

## Part 16: 次のアクション

実装を始める準備ができました。以下から選んでください：

1. **Relay Network 実装**: `core/src/net/relay.rs` から
2. **Gossip Protocol 実装**: `core/src/net/gossip.rs` から
3. **シュレーディンガーMailbox 実装**: `core/src/mailbox/schrodinger.rs` から
4. **質問**: 特定の実装詳細について深掘り

どこから始めますか？

