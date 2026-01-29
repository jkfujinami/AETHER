use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use rand::rngs::OsRng;


/// 一時的な鍵ペア（Onion Handshake用）
pub struct EphemeralKey {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl EphemeralKey {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// IDH (Diffie-Hellman) を実行して共有シークレットを計算
    pub fn diffie_hellman(self, peer_public: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer_public).to_bytes()
    }
}

/// 静的な鍵ペア（サーバー/リレーの長期鍵用）
pub struct StaticKey {
    secret: StaticSecret,
    public: PublicKey,
}

impl StaticKey {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer_public).to_bytes()
    }
}

pub fn public_from_bytes(bytes: &[u8; 32]) -> PublicKey {
    PublicKey::from(*bytes)
}
