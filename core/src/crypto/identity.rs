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
