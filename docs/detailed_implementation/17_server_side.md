# Part 17: サーバーサイド実装（Node/Router/Mailbox/Gossip）

## 17.1 概要

クライアント側（送信）のロジックは実装済み。本章ではサーバー側（受信・転送・保存）を実装する。

```
┌─────────────────────────────────────────────────────┐
│                   NodeServer                         │
├─────────────────────────────────────────────────────┤
│                                                      │
│  [QuicServer]                                        │
│       │                                              │
│       ▼                                              │
│  [PacketDispatcher]                                  │
│       │                                              │
│       ├── OnionPacket  → [Router]                   │
│       │                      │                       │
│       │                      ├── NextHop あり → 転送 │
│       │                      └── NextHop なし → ↓   │
│       │                                              │
│       ├── MailboxPut   → [MailboxServer] → 保存    │
│       ├── MailboxGet   → [MailboxServer] → 取得    │
│       │                                              │
│       └── GossipHint   → [GossipServer] → 拡散     │
│                                                      │
└─────────────────────────────────────────────────────┘
```

---

## 17.2 Router 実装

### 17.2.1 責務

受信した Onion Packet を復号し、次ホップへ転送するか、最終目的地として処理する。

### 17.2.2 構造体

```rust
// core/src/node/router.rs

use crate::crypto::identity::Identity;
use crate::net::onion::OnionCircuit;
use crate::net::quic::QuicClient;
use std::sync::Arc;

pub struct Router {
    /// このノードの秘密鍵（Onion復号用）
    identity: Arc<Identity>,

    /// 次ホップへの転送用クライアント
    quic_client: QuicClient,
}

impl Router {
    pub fn new(identity: Arc<Identity>) -> Result<Self> {
        let quic_client = QuicClient::new()?;
        Ok(Self { identity, quic_client })
    }

    /// Onion Packet を処理
    pub async fn handle_packet(&self, packet: &[u8]) -> Result<()> {
        // 1. 自分の秘密鍵で最外層を復号
        let shared_secret = self.derive_shared_secret(packet)?;
        let (next_hop, payload) = OnionCircuit::unwrap_packet(&shared_secret, packet)?;

        match next_hop {
            Some(addr) => {
                // 2a. 次ホップが存在 → 転送
                self.forward_packet(addr, &payload).await?;
            }
            None => {
                // 2b. 最終目的地 → Payload 処理
                self.process_final_payload(&payload).await?;
            }
        }
        Ok(())
    }

    /// 次ホップへ転送
    async fn forward_packet(&self, addr: SocketAddr, payload: &[u8]) -> Result<()> {
        let conn = self.quic_client.connect(addr, "aether-relay").await?;
        let mut stream = conn.open_uni().await?;
        wire::write_packet(&mut stream, PacketType::OnionPacket, payload).await?;
        Ok(())
    }

    /// 最終ペイロード処理（内部パケットタイプで分岐）
    async fn process_final_payload(&self, payload: &[u8]) -> Result<()> {
        let (inner_type, inner_payload) = wire::parse_inner_packet(payload)?;

        match inner_type {
            InnerPacketType::MailboxPut => {
                // MailboxServer::put() を呼ぶ
            }
            InnerPacketType::MailboxGet => {
                // MailboxServer::get() を呼ぶ
            }
            InnerPacketType::GossipHint => {
                // GossipServer::broadcast() を呼ぶ
            }
        }
        Ok(())
    }

    /// パケットから一時公開鍵を抽出し、共有秘密を導出
    fn derive_shared_secret(&self, packet: &[u8]) -> Result<[u8; 32]> {
        // packet[0..32] = 送信者の一時公開鍵
        let ephemeral_pub: [u8; 32] = packet[0..32].try_into()?;

        use x25519_dalek::{PublicKey, StaticSecret};
        let their_pub = PublicKey::from(ephemeral_pub);
        let my_secret = self.identity.x25519_secret();  // Identity に追加が必要
        let shared = my_secret.diffie_hellman(&their_pub);
        Ok(*shared.as_bytes())
    }
}
```

### 17.2.3 Identity への追加

```rust
// core/src/crypto/identity.rs に追加

impl Identity {
    /// X25519秘密鍵を取得（Onion復号用）
    /// Ed25519鍵からX25519鍵を導出するか、別途保持
    pub fn x25519_secret(&self) -> x25519_dalek::StaticSecret {
        // Ed25519秘密鍵のハッシュをX25519のシードとして使用
        use sha2::{Sha512, Digest};
        let hash = Sha512::digest(self.signing_key.as_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash[0..32]);
        x25519_dalek::StaticSecret::from(seed)
    }
}
```

---

## 17.3 MailboxServer 実装

### 17.3.1 責務

暗号化されたメッセージを Key-Value ストレージに保存・取得する。

### 17.3.2 構造体

```rust
// core/src/mailbox/server.rs

use sled::Db;
use std::path::Path;

pub struct MailboxServer {
    db: Db,
    max_size_bytes: u64,  // 1エントリの最大サイズ
    ttl_seconds: u64,     // 保存期間
}

impl MailboxServer {
    pub fn new(db_path: &Path) -> Result<Self> {
        let db = sled::open(db_path)?;
        Ok(Self {
            db,
            max_size_bytes: 1024 * 1024,  // 1MB
            ttl_seconds: 7 * 24 * 3600,   // 7日
        })
    }

    /// メッセージを保存
    pub fn put(&self, key: &[u8; 32], value: &[u8]) -> Result<()> {
        if value.len() > self.max_size_bytes as usize {
            return Err(AetherError::Mailbox("Value too large".into()));
        }

        // タイムスタンプ付きで保存
        let entry = MailboxEntry {
            value: value.to_vec(),
            created_at: current_timestamp(),
        };
        let encoded = bincode::serialize(&entry)?;
        self.db.insert(key, encoded)?;
        Ok(())
    }

    /// メッセージを取得
    pub fn get(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        if let Some(encoded) = self.db.get(key)? {
            let entry: MailboxEntry = bincode::deserialize(&encoded)?;

            // TTLチェック
            if current_timestamp() - entry.created_at > self.ttl_seconds {
                self.db.remove(key)?;  // 期限切れを削除
                return Ok(None);
            }
            return Ok(Some(entry.value));
        }
        Ok(None)
    }

    /// メッセージを削除（Burn-on-Read）
    pub fn delete(&self, key: &[u8; 32]) -> Result<()> {
        self.db.remove(key)?;
        Ok(())
    }

    /// 期限切れエントリの定期クリーンアップ
    pub fn cleanup_expired(&self) -> Result<usize> {
        let now = current_timestamp();
        let mut count = 0;

        for item in self.db.iter() {
            let (key, encoded) = item?;
            let entry: MailboxEntry = bincode::deserialize(&encoded)?;
            if now - entry.created_at > self.ttl_seconds {
                self.db.remove(key)?;
                count += 1;
            }
        }
        Ok(count)
    }
}

#[derive(Serialize, Deserialize)]
struct MailboxEntry {
    value: Vec<u8>,
    created_at: u64,
}
```

### 17.3.3 ワイヤーフォーマット

```
MailboxPut:
+----------+----------+---------------+
| Key      | ValueLen | Value         |
| 32 bytes | 4 bytes  | Variable      |
+----------+----------+---------------+

MailboxGet:
+----------+
| Key      |
| 32 bytes |
+----------+

MailboxResponse:
+--------+---------------+
| Status | Value         |
| 1 byte | Variable      |
+--------+---------------+
Status: 0x00=NotFound, 0x01=Found, 0x02=Error
```

---

## 17.4 GossipServer 実装

### 17.4.1 責務

受信した Hint を全ピアに拡散する。重複は送信しない。

### 17.4.2 構造体

```rust
// core/src/net/gossip_server.rs

use crate::protocol::hint::HintPacket;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use quinn::Connection;

pub struct GossipServer {
    /// 既に処理した Hint のハッシュ
    seen_hints: Mutex<HashSet<[u8; 32]>>,

    /// 接続中のピア
    peers: Arc<Mutex<Vec<Connection>>>,
}

impl GossipServer {
    pub fn new(peers: Arc<Mutex<Vec<Connection>>>) -> Self {
        Self {
            seen_hints: Mutex::new(HashSet::new()),
            peers,
        }
    }

    /// Hint を処理（重複チェック → 拡散）
    pub async fn handle_hint(&self, hint_bytes: &[u8]) -> Result<()> {
        // 1. ハッシュ計算
        let hash = Self::hash_hint(hint_bytes);

        // 2. 重複チェック
        {
            let mut seen = self.seen_hints.lock().unwrap();
            if seen.contains(&hash) {
                return Ok(());  // 既知なので無視
            }
            seen.insert(hash);
        }

        // 3. TTL チェック（デシリアライズ）
        let mut hint: HintPacket = bincode::deserialize(hint_bytes)?;
        if !hint.decrement_ttl() {
            return Ok(());  // TTL切れ
        }

        // 4. 全ピアに拡散
        let updated_bytes = bincode::serialize(&hint)?;
        self.broadcast_to_peers(&updated_bytes).await?;

        Ok(())
    }

    /// 全ピアに送信
    async fn broadcast_to_peers(&self, data: &[u8]) -> Result<()> {
        let peers = self.peers.lock().unwrap().clone();

        for conn in peers {
            if let Ok(mut stream) = conn.open_uni().await {
                let _ = wire::write_packet(&mut stream, PacketType::GossipHint, data).await;
            }
        }
        Ok(())
    }

    fn hash_hint(data: &[u8]) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        Sha256::digest(data).into()
    }
}
```

---

## 17.5 ピア管理

### 17.5.1 PeerManager

```rust
// core/src/node/peer.rs

use quinn::Connection;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

pub struct PeerManager {
    peers: Arc<Mutex<Vec<PeerInfo>>>,
}

#[derive(Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub connection: Connection,
    pub connected_at: u64,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 新しいピアを追加
    pub fn add_peer(&self, addr: SocketAddr, conn: Connection) {
        let mut peers = self.peers.lock().unwrap();
        peers.push(PeerInfo {
            addr,
            connection: conn,
            connected_at: current_timestamp(),
        });
    }

    /// 全ピアの接続を取得
    pub fn get_connections(&self) -> Vec<Connection> {
        self.peers.lock().unwrap()
            .iter()
            .map(|p| p.connection.clone())
            .collect()
    }

    /// 接続が切れたピアを削除
    pub fn cleanup_disconnected(&self) {
        let mut peers = self.peers.lock().unwrap();
        peers.retain(|p| !p.connection.close_reason().is_some());
    }
}
```

---

## 17.6 NodeServer 統合

### 17.6.1 全コンポーネントの統合

```rust
// core/src/node/server.rs (更新版)

pub struct NodeServer {
    quic_server: QuicServer,
    router: Arc<Router>,
    mailbox: Arc<MailboxServer>,
    gossip: Arc<GossipServer>,
    peers: Arc<PeerManager>,
    identity: Arc<Identity>,
}

impl NodeServer {
    pub fn new(port: u16, identity: Identity, db_path: &Path) -> Result<Self> {
        let config = Config { listen_port: port, ..Default::default() };
        let quic_server = QuicServer::new(&config)?;

        let identity = Arc::new(identity);
        let peers = Arc::new(PeerManager::new());

        let router = Arc::new(Router::new(identity.clone())?);
        let mailbox = Arc::new(MailboxServer::new(db_path)?);
        let gossip = Arc::new(GossipServer::new(peers.clone()));

        Ok(Self {
            quic_server,
            router,
            mailbox,
            gossip,
            peers,
            identity,
        })
    }

    /// 他ノードに接続
    pub async fn connect_to_peer(&self, addr: SocketAddr) -> Result<()> {
        let client = QuicClient::new()?;
        let conn = client.connect(addr, "aether-relay").await?;
        self.peers.add_peer(addr, conn);
        Ok(())
    }

    /// メインループ
    pub async fn run(&self) -> Result<()> {
        // 定期クリーンアップタスク
        let mailbox = self.mailbox.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                let _ = mailbox.cleanup_expired();
            }
        });

        // 接続受付ループ
        while let Some(incoming) = self.quic_server.accept().await {
            let router = self.router.clone();
            let mailbox = self.mailbox.clone();
            let gossip = self.gossip.clone();
            let peers = self.peers.clone();

            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    peers.add_peer(conn.remote_address(), conn.clone());
                    Self::handle_connection(conn, router, mailbox, gossip).await;
                }
            });
        }
        Ok(())
    }

    async fn handle_connection(
        conn: Connection,
        router: Arc<Router>,
        mailbox: Arc<MailboxServer>,
        gossip: Arc<GossipServer>,
    ) {
        while let Ok(mut stream) = conn.accept_uni().await {
            let router = router.clone();
            let mailbox = mailbox.clone();
            let gossip = gossip.clone();

            tokio::spawn(async move {
                if let Ok((packet_type, payload)) = wire::read_packet(&mut stream).await {
                    match packet_type {
                        PacketType::OnionPacket => {
                            let _ = router.handle_packet(&payload).await;
                        }
                        PacketType::GossipHint => {
                            let _ = gossip.handle_hint(&payload).await;
                        }
                        PacketType::MailboxPut => {
                            // parse key/value from payload
                            // mailbox.put(&key, &value);
                        }
                        PacketType::MailboxGet => {
                            // parse key from payload
                            // mailbox.get(&key);
                        }
                        _ => {}
                    }
                }
            });
        }
    }
}
```

---

## 17.7 実装チェックリスト

### Phase 1: Router (最優先)
- [ ] `Identity::x25519_secret()` 追加
- [ ] `Router::derive_shared_secret()` 実装
- [ ] `Router::handle_packet()` 完成
- [ ] `Router::forward_packet()` テスト

### Phase 2: MailboxServer
- [ ] `MailboxServer` 構造体作成
- [ ] `put()` / `get()` / `delete()` 実装
- [ ] `cleanup_expired()` 実装
- [ ] sled DBテスト

### Phase 3: GossipServer
- [ ] `GossipServer` 構造体作成
- [ ] `handle_hint()` 実装
- [ ] `broadcast_to_peers()` 実装
- [ ] 重複排除テスト

### Phase 4: 統合
- [ ] `PeerManager` 実装
- [ ] `NodeServer` への統合
- [ ] `--connect` オプション実装
- [ ] E2Eテスト

---

## 17.8 次のアクション

1. **今すぐ**: `Identity::x25519_secret()` を実装
2. **次に**: `Router::handle_packet()` を完成
3. **その後**: ローカル2ノードでパケット転送テスト
