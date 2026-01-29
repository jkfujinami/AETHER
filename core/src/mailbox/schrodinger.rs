use crate::error::{Result, AetherError};
use crate::net::relay::RelayClient;
use crate::net::gossip::GossipClient;
use crate::protocol::hint::{HintPacket, HintPayload};
use crate::crypto::{identity::NodeId, cipher};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use sha2::Sha256;
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use std::net::SocketAddr;

// 型エイリアス
type SharedSecret = [u8; 32];
type HmacSha256 = Hmac<Sha256>;

use crate::net::tunnel::InboundTunnel;

/// シュレーディンガーMailboxの実装
pub struct SchrodingerMailbox {
    relay: Arc<RelayClient>,
    gossip: Arc<GossipClient>,
    contacts: Arc<Mutex<HashMap<NodeId, SharedSecret>>>,
    inbound_tunnels: Arc<Mutex<Vec<InboundTunnel>>>, // Active inbound tunnels to decrypt replies
}

impl SchrodingerMailbox {
    pub fn new(
        relay: Arc<RelayClient>,
        gossip: Arc<GossipClient>,
        contacts: Arc<Mutex<HashMap<NodeId, SharedSecret>>>
    ) -> Self {
        Self {
            relay,
            gossip,
            contacts,
            inbound_tunnels: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// メッセージを暗号化し、Mailbox保存用ペイロードとHintパケットを生成する
    /// 副作用なし（ネットワークIOなし）
    /// Returns: (MailboxPayload, HintPacket)
    /// MailboxPayload structure: [MailboxKey(32)] + [MsgNonce(12)] + [EncryptedMessage]
    pub fn prepare_packet(&self, to: &NodeId, message: &[u8]) -> Result<(Vec<u8>, HintPacket)> {
        // 1. 相手との共有鍵を取得
        let shared_secret = {
            let contacts = self.contacts.lock().unwrap();
            *contacts.get(to).ok_or(AetherError::Config("Contact not found".into()))?
        };

        // 2. Nonce生成 & Mailbox Key 計算
        let nonce = cipher::generate_key(); // 32bytes random used for Key derivation
        use sha2::Digest;
        let mailbox_key: [u8; 32] = Sha256::digest(nonce).into();

        // 3. メッセージ暗号化
        let message_key = self.derive_key(&shared_secret, b"aether_message_v1");
        let (encrypted_message, msg_nonce) = cipher::encrypt(&message_key, message)?;

        // ペイロード構築: [MailboxKey] + [MsgNonce] + [EncMsg]
        let mut payload = Vec::new();
        payload.extend_from_slice(&mailbox_key);
        payload.extend_from_slice(&msg_nonce);
        payload.extend_from_slice(&encrypted_message);

        // 4. Hint 生成
        // Hint Payload: Nonce(32) || MsgID || Timestamp
        let hint_payload = HintPayload {
            nonce, // Mailbox Keyを決めるための32byte Nonce
            message_id: 0, // TODO: generate unique ID
            timestamp: 0,  // TODO: current time
        };
        let hint_payload_bytes = bincode::serialize(&hint_payload)
            .map_err(|e| AetherError::Config(e.to_string()))?;

        // Hint暗号化
        let hint_key = self.derive_key(&shared_secret, b"aether_hint_v1");
        // HintPacket用のNonce(12)を生成
        let (hint_ciphertext, hint_encrypt_nonce) = cipher::encrypt(&hint_key, &hint_payload_bytes)?;

        // Blind Tag 計算
        let mut mac = HmacSha256::new_from_slice(&shared_secret)
            .map_err(|_| AetherError::Crypto("HMAC init failed".into()))?;
        mac.update(&hint_encrypt_nonce);
        let mac_result = mac.finalize().into_bytes();
        let blind_tag: [u8; 4] = mac_result[0..4].try_into().unwrap();

        let hint_packet = HintPacket {
            version: 1,
            ttl: 5,
            blind_tag,
            nonce: hint_encrypt_nonce,
            ciphertext: hint_ciphertext,
            auth_tag: [0u8; 16], // Dummy (included in ciphertext)
        };

        Ok((payload, hint_packet))
    }

    /// メッセージを送信
    pub async fn send_message(&self, to: &NodeId, message: &[u8], dest: SocketAddr) -> Result<()> {
        let (payload, hint) = self.prepare_packet(to, message)?;

        // 1. Send Onion Packet (Mailbox Put)
        self.relay.send_onion_message(&payload, dest).await?;

        // 2. Broadcast Hint
        self.gossip.broadcast(&hint).await?;

        Ok(())
    }

    /// 受信した Hint を処理（試行復号）
    pub fn try_decrypt_hint(&self, hint: &HintPacket) -> Option<[u8; 32]> {
        let candidates = self.find_candidates(&hint.blind_tag, &hint.nonce);
        if candidates.is_empty() { return None; }

        for shared_secret in candidates {
            let hint_key = self.derive_key(&shared_secret, b"aether_hint_v1");
            if let Ok(payload_bytes) = cipher::decrypt(&hint_key, &hint.nonce, &hint.ciphertext)
                && let Ok(payload) = bincode::deserialize::<HintPayload>(&payload_bytes)
            {
                use sha2::Digest;
                let mailbox_key: [u8; 32] = Sha256::digest(payload.nonce).into();
                return Some(mailbox_key);
            }
        }
        None
    }

    pub async fn process_hint(&self, hint: &HintPacket) -> Result<Option<Vec<u8>>> {
        if let Some(_mailbox_key) = self.try_decrypt_hint(hint) {
             // Mock fetch logic
             return Ok(Some(b"Decrypted Message Mock".to_vec()));
        }
        Ok(None)
    }

    fn find_candidates(&self, blind_tag: &[u8; 4], nonce: &[u8; 12]) -> Vec<SharedSecret> {
        let contacts = self.contacts.lock().unwrap();
        let mut candidates = Vec::new();
        for secret in contacts.values() {
             let mut mac = HmacSha256::new_from_slice(secret).unwrap();
             mac.update(nonce);
             let result = mac.finalize().into_bytes();
             if &result[0..4] == blind_tag {
                 candidates.push(*secret);
             }
        }
        candidates
    }

    fn derive_key(&self, shared_secret: &[u8; 32], info: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm).expect("HKDF expand limits");
        okm
    }

    /// Inbound Tunnel を構築し、構築指示を各リレーに送信する
    /// エンドポイント情報を返す (Gossipで配布用)
    pub async fn build_inbound_tunnel(
        &self,
        path: Vec<SocketAddr>,
        path_pubkeys: Vec<[u8; 32]>,
    ) -> Result<crate::net::tunnel::TunnelEndpoint> {
        // Build tunnel object and instructions
        let (tunnel, instructions) = InboundTunnel::build(path, path_pubkeys)?;

        let endpoint = tunnel.endpoint.clone();

        // Store tunnel for decryption later
        {
            let mut tunnels = self.inbound_tunnels.lock().unwrap();
            tunnels.push(tunnel);
        }

        // Send Build instructions to relays
        for (addr, payload) in instructions {
            // パケットタイプ: TunnelBuild (0x31)
            // Payload: [ListenTunnelID][EphPK][Nonce][EncInstruction]
            // RelayClient経由で直接送信
            self.relay.send_direct_packet(addr, crate::protocol::wire::PacketType::TunnelBuild, &payload).await?;
        }

        Ok(endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;

    fn create_dummy_mailbox() -> SchrodingerMailbox {
         let relay = Arc::new(RelayClient::new().unwrap());
         let gossip = Arc::new(GossipClient::new(RelayClient::new().unwrap()));
         let contacts = Arc::new(Mutex::new(HashMap::new()));
         SchrodingerMailbox::new(relay, gossip, contacts)
    }

    #[tokio::test]
    async fn test_hint_exchange() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();
        let alice_mailbox = create_dummy_mailbox();
        let bob_mailbox = create_dummy_mailbox();
        let shared_secret = [0xabu8; 32];

        alice_mailbox.contacts.lock().unwrap().insert(bob_id.public_id(), shared_secret);
        bob_mailbox.contacts.lock().unwrap().insert(alice_id.public_id(), shared_secret);

        let message = b"Secrets of the Universe";

        // Use prepare_packet instad of encrypt_and_create_hint
        let (payload, hint) = alice_mailbox.prepare_packet(&bob_id.public_id(), message).unwrap();

        println!("Hint generated. Blind Tag: {:?}", hint.blind_tag);
        assert_eq!(payload.len(), 32 + 12 + message.len() + 16); // Key(32)+Nonce(12)+Msg+Tag(16)

        // Bob receives Hint
        let result_key = bob_mailbox.try_decrypt_hint(&hint);
        assert!(result_key.is_some(), "Bob should successfully decrypt the hint");

        // Verify message decryption
        // Payload: [Key(32)][Nonce(12)][EncMsg...]
        let msg_nonce = &payload[32..44];
        let msg_ciphertext = &payload[44..];

        let bob_msg_key = bob_mailbox.derive_key(&shared_secret, b"aether_message_v1");
        let msg_nonce_arr: [u8; 12] = msg_nonce.try_into().unwrap();

        let decrypted_msg = cipher::decrypt(&bob_msg_key, &msg_nonce_arr, msg_ciphertext).unwrap();
        assert_eq!(decrypted_msg, message);
        println!("Bob successfully decrypted message: {:?}", String::from_utf8_lossy(&decrypted_msg));
    }
}
