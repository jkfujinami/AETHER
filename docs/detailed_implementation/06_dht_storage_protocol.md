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

