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

