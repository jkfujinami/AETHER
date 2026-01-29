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

