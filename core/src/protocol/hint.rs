use serde::{Serialize, Deserialize};

/// Gossip で配信される Hint パケット
/// 誰宛てかは暗号化されており、受信者だけが blind_tag と復号試行で判断できる。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HintPacket {
    pub version: u8,
    pub ttl: u8,
    pub blind_tag: [u8; 4],   // HMAC(SharedSecret, Nonce)[0..4]
    pub nonce: [u8; 12],      // Encryption Nonce (ChaCha20)
    pub ciphertext: Vec<u8>,  // Encrypted Payload
    pub auth_tag: [u8; 16],   // Poly1305 Tag
}

impl HintPacket {
    /// 新しいパケットを作成
    pub fn new(blind_tag: [u8; 4], nonce: [u8; 12], ciphertext: Vec<u8>, auth_tag: [u8; 16], ttl: u8) -> Self {
        Self {
            version: 1,
            ttl,
            blind_tag,
            nonce,
            ciphertext,
            auth_tag,
        }
    }

    /// TTLを減らす（0になったら廃棄）
    pub fn decrement_ttl(&mut self) -> bool {
        if self.ttl > 0 {
            self.ttl -= 1;
            true
        } else {
            false
        }
    }
}

/// Hint の中身（復号後）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintPayload {
    pub nonce: [u8; 32],      // Mailbox Key 生成用 Nonce (SHA256(Nonce) = Key)
    pub message_id: u64,      // メッセージID
    pub timestamp: u64,       // 送信時刻
}
