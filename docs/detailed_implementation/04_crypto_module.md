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

