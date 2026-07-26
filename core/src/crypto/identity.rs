use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Signature, Verifier};
use crate::error::{AetherError, Result};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use std::fmt;

/// 32バイトの公開鍵（ノードIDとして使用）
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", hex::encode(self.0))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl NodeId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// AETHERのID（Ed25519キーペアのラッパー）
pub struct Identity {
    keypair: SigningKey,
}

impl Identity {
    /// 新しいランダムなIDを生成
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let keypair = SigningKey::generate(&mut csprng);
        Self { keypair }
    }

    /// バイト列から復元
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(AetherError::Crypto("Invalid input length for SigningKey".into()));
        }
        let secret = TryInto::<[u8; 32]>::try_into(bytes).expect("Checked length");
        let keypair = SigningKey::from_bytes(&secret);
        Ok(Self { keypair })
    }

    /// 秘密鍵をバイト列として取得
    pub fn to_bytes(&self) -> [u8; 32] {
        self.keypair.to_bytes()
    }

    /// 公開鍵（Node ID）を取得
    pub fn public_id(&self) -> NodeId {
        NodeId(self.keypair.verifying_key().to_bytes())
    }

    /// 署名
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.keypair.sign(message).to_bytes().to_vec()
    }

    /// Onion Routing (X25519) 用の秘密鍵を導出する
    /// Ed25519の秘密鍵から決定論的に生成されるため、永続化の必要はない
    pub fn x25519_secret(&self) -> x25519_dalek::StaticSecret {
        use sha2::{Sha512, Digest};
        // Ed25519の秘密鍵をシードとして使用
        let hash = Sha512::digest(self.keypair.to_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash[0..32]);
        x25519_dalek::StaticSecret::from(seed)
    }

    /// 相手の NodeId から共有秘密を鍵合意する（`--secret` 手渡しを排除 / 3-1 ③）
    ///
    /// AETHER の identity X25519 鍵は Ed25519 NodeId の Montgomery 変換に一致するので、
    /// **相手の NodeId だけから**相手の X25519 公開鍵を導出でき、自分の X25519 秘密鍵と
    /// DH できる。両者が相手の NodeId だけから同じ秘密へ到達する（事前共有・広告不要）。
    ///
    /// これは静的鍵の DH（認証つき鍵合意）。会話本文の前方秘匿はこの秘密から立てる
    /// [`crate::crypto::session::Session`] のラチェットが担う。
    pub fn agree(&self, peer: &NodeId) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let peer_pub = x25519_public_from_node_id(peer)?;
        let shared = self
            .x25519_secret()
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer_pub));
        let mut h = Sha256::new();
        h.update(b"aether_contact_agree_v1");
        h.update(shared.to_bytes());
        Ok(h.finalize().into())
    }

    /// 秘密鍵をパスフレーズで暗号化してファイル用バイト列にする（押収対策 / 3-1）
    ///
    /// identity.key＝**ID そのもの**。押収されれば成りすまし＋全コンテンツ紐付けが可能。
    /// Argon2id でパスフレーズを伸ばし ChaCha20-Poly1305 で秘密鍵を暗号化する。
    ///
    /// 形式: `[MAGIC(4)][salt(16)][nonce(12)][ciphertext(48)]` = 80 バイト。
    /// 平文（ちょうど 32 バイト）とは長さとマジックで区別できる。
    pub fn to_encrypted_bytes(&self, passphrase: &str) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = crate::storage::at_rest::derive_key(passphrase, &salt)?;
        let enc = crate::storage::at_rest::encrypt_value(&key, &self.keypair.to_bytes())?;

        let mut out = Vec::with_capacity(4 + 16 + enc.len());
        out.extend_from_slice(ENCRYPTED_IDENTITY_MAGIC);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&enc);
        Ok(out)
    }

    /// 暗号化された identity.key バイト列から復元する（3-1）
    pub fn from_encrypted_bytes(raw: &[u8], passphrase: &str) -> Result<Self> {
        if !Self::is_encrypted_bytes(raw) || raw.len() < 4 + 16 + 12 {
            return Err(AetherError::Crypto("暗号化 identity.key の形式が不正です".into()));
        }
        let salt = &raw[4..20];
        let key = crate::storage::at_rest::derive_key(passphrase, salt)?;
        let secret = crate::storage::at_rest::decrypt_value(&key, &raw[20..])
            .map_err(|_| AetherError::Crypto("identity.key: 誤ったパスフレーズです".into()))?;
        Self::from_bytes(&secret)
    }

    /// バイト列が暗号化された identity.key か（マジック判定）
    ///
    /// 平文は**ちょうど 32 バイト**なので、80 バイト＋マジックの暗号化形式と衝突しない。
    pub fn is_encrypted_bytes(raw: &[u8]) -> bool {
        raw.len() >= 4 && &raw[0..4] == ENCRYPTED_IDENTITY_MAGIC
    }
}

/// 暗号化 identity.key の先頭マジック（平文＝ちょうど32バイトと区別する）
pub const ENCRYPTED_IDENTITY_MAGIC: &[u8; 4] = b"AEIK";

/// NodeId (Ed25519 公開鍵) から X25519 公開鍵を導出する（Montgomery 変換）
///
/// identity の X25519 鍵は Ed25519 の birational 変換なので、NodeId だけから復元できる。
pub fn x25519_public_from_node_id(node_id: &NodeId) -> Result<[u8; 32]> {
    let vk = VerifyingKey::from_bytes(&node_id.0)
        .map_err(|e| AetherError::Crypto(format!("Invalid NodeId for X25519: {}", e)))?;
    Ok(vk.to_montgomery().to_bytes())
}

/// 署名の検証
pub fn verify_signature(node_id: &NodeId, message: &[u8], signature: &[u8]) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(&node_id.0)
        .map_err(|e| AetherError::Crypto(format!("Invalid public key: {}", e)))?;

    let signature = Signature::from_slice(signature)
        .map_err(|e| AetherError::Crypto(format!("Invalid signature format: {}", e)))?;

    verifying_key.verify(message, &signature)
        .map_err(|e| AetherError::Crypto(format!("Signature verification failed: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_identities_agree_on_the_same_secret() {
        // 相手の NodeId だけから、両者が同じ共有秘密に到達する（事前共有・広告なし）
        let alice = Identity::generate();
        let bob = Identity::generate();

        let s1 = alice.agree(&bob.public_id()).unwrap();
        let s2 = bob.agree(&alice.public_id()).unwrap();
        assert_eq!(s1, s2, "相手の NodeId だけから同じ共有秘密に到達する");

        let carol = Identity::generate();
        assert_ne!(s1, alice.agree(&carol.public_id()).unwrap(), "相手が違えば秘密も違う");
    }

    #[test]
    fn identity_key_encrypts_and_decrypts_with_the_passphrase() {
        let id = Identity::generate();
        let enc = id.to_encrypted_bytes("correct horse").unwrap();

        // ディスク上に生の秘密鍵は現れない（平文32バイトとは別物・80バイト）
        assert!(Identity::is_encrypted_bytes(&enc), "マジックが立っている");
        assert_eq!(enc.len(), 4 + 16 + 12 + 32 + 16, "MAGIC+salt+nonce+ct+tag");
        assert!(!enc.windows(32).any(|w| w == id.to_bytes()), "秘密鍵が平文で残らない");

        // 同じパスフレーズで復元でき、同じ NodeId に戻る
        let restored = Identity::from_encrypted_bytes(&enc, "correct horse").unwrap();
        assert_eq!(restored.public_id(), id.public_id());

        // 誤ったパスフレーズは拒否
        assert!(Identity::from_encrypted_bytes(&enc, "wrong").is_err());
    }

    #[test]
    fn plaintext_identity_is_not_mistaken_for_encrypted() {
        // 平文の秘密鍵（32バイト）は暗号化形式と誤認されない
        let id = Identity::generate();
        assert!(!Identity::is_encrypted_bytes(&id.to_bytes()));
    }

    #[test]
    fn derived_x25519_public_matches_the_identity_key() {
        // NodeId から導出した X25519 公開鍵が、その identity の X25519 公開鍵と一致する
        let id = Identity::generate();
        let from_secret =
            x25519_dalek::PublicKey::from(&id.x25519_secret()).to_bytes();
        let from_node_id = x25519_public_from_node_id(&id.public_id()).unwrap();
        assert_eq!(from_secret, from_node_id, "Montgomery 変換が identity 鍵と一致する");
    }
}
