//! I2P風 Inbound Tunnel 実装
//!
//! 受信専用のトンネルを構築し、送信者に Gateway アドレスだけを公開する。
//! これにより、送信者は受信者の実IPを知ることなくメッセージを送れる。

use crate::error::{Result, AetherError};
use crate::crypto::{key_exchange, cipher};
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use x25519_dalek::PublicKey;

/// トンネル構築の結果: (トンネル本体, 各ホップへの命令)
pub type BuildResult = Result<(InboundTunnel, Vec<(SocketAddr, Vec<u8>)>)>;

/// 中継情報の詳細: (中継先アドレス, 中継用識別子, 暗号化済みデータ)
pub type ForwardingInstruction = (SocketAddr, [u8; 32], Vec<u8>);

/// Inbound Tunnel の公開情報
/// これを他のノードに伝えることで、相手はこのトンネル経由でメッセージを送れる
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelEndpoint {
    /// トンネルの入口 (Gateway) アドレス
    pub gateway: SocketAddr,

    /// トンネル識別子 (Gateway がルーティングに使用)
    pub tunnel_id: [u8; 32],
}

/// Inbound Tunnel の構築情報 (所有者のみが持つ)
#[derive(Debug)]
pub struct InboundTunnel {
    /// 公開情報
    pub endpoint: TunnelEndpoint,

    /// 各ホップでの復号に必要な共有秘密 (自分に近い順)
    /// 最後の要素が Gateway との共有秘密
    decrypt_keys: Vec<[u8; 32]>,

    /// 自分が受信する際の Tunnel ID (Alice が待ち受ける ID)
    pub receive_tunnel_id: [u8; 32],

    /// トンネル経路 (デバッグ用、運用時は持たなくてもよい)
    #[allow(dead_code)]
    path: Vec<SocketAddr>,
}

/// トンネル内を流れるデータのヘッダ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelHeader {
    /// トンネル識別子
    pub tunnel_id: [u8; 32],

    /// 一時公開鍵 (各ホップでの鍵導出用)
    pub ephemeral_pk: [u8; 32],
}

/// 各ホップが持つ、次のホップへの転送情報
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopInstruction {
    /// 次のホップのアドレス (None = 最終宛先)
    pub next_hop: Option<SocketAddr>,

    /// 次のホップ用の tunnel_id
    pub next_tunnel_id: [u8; 32],
}

impl InboundTunnel {
    /// 新しい Inbound Tunnel を構築する
    ///
    /// # Arguments
    /// * `path` - トンネル経路 (Gateway, Relay1, Relay2, ..., 最後が自分)
    ///   最低2ホップ必要 (Gateway + 自分)
    /// * `hop_pubkeys` - 各ホップの公開鍵 (path と同じ順序、自分も含む)
    ///
    /// # Returns
    /// * `InboundTunnel` - 構築されたトンネル
    /// * `Vec<(SocketAddr, Vec<u8>)>` - 各ホップへ配布するべき暗号化命令
    pub fn build(
        path: Vec<SocketAddr>,
        hop_pubkeys: Vec<[u8; 32]>,
    ) -> BuildResult {
        if path.len() < 2 {
            return Err(AetherError::Config("Tunnel path must have at least 2 hops".into()));
        }
        if hop_pubkeys.len() != path.len() {
            return Err(AetherError::Config("hop_pubkeys length mismatch".into()));
        }

        let mut decrypt_keys = Vec::new();
        let mut hop_instructions: Vec<(SocketAddr, Vec<u8>)> = Vec::new();

        // トンネルIDを生成
        let tunnel_id: [u8; 32] = rand::random();

        // Alice が受信する際の Tunnel ID を保存
        let mut receive_tunnel_id = [0u8; 32];

        // 各ホップ用の命令を構築 (逆順: 終端から Gateway へ)
        // path: [Gateway, Relay1, Relay2, Self]
        // pubkeys: [Gateway_pk, Relay1_pk, Relay2_pk]

        // 次のホップへ渡すためのTunnelID (初期値はAlice=自分向けなのでダミー [0;32])
        let mut next_hop_tunnel_id = [0u8; 32];

        for i in (0..hop_pubkeys.len()).rev() {
            let hop_addr = path[i];
            let hop_pk_bytes = hop_pubkeys[i];
            let hop_pk = PublicKey::from(hop_pk_bytes);

            // 自分が待ち受けるID
            let listen_tunnel_id = if i == 0 {
                tunnel_id // Gatewayは公開IDを使う
            } else {
                rand::random() // RelayはランダムID
            };

            // Alice (最後のホップ) の場合、receive_tunnel_id を保存
            if i == hop_pubkeys.len() - 1 {
                receive_tunnel_id = listen_tunnel_id;
            }

            // 次のホップ情報
            let next_hop = if i + 1 < path.len() {
                Some(path[i + 1])
            } else {
                // Last hop (Alice) - next_hop is self
                Some(path[i])
            };

            let instruction = HopInstruction {
                next_hop,
                next_tunnel_id: next_hop_tunnel_id,
            };

            // EphemeralKey を生成して共有秘密を導出
            let ephemeral = key_exchange::EphemeralKey::generate();
            let ephemeral_pk_bytes = ephemeral.public_bytes();
            let shared_secret = ephemeral.diffie_hellman(&hop_pk);

            // 命令を暗号化
            let instruction_bytes = bincode::serialize(&instruction)
                .map_err(|e| AetherError::Config(e.to_string()))?;

            let (encrypted_instruction, nonce) = cipher::encrypt(&shared_secret, &instruction_bytes)?;

            // Hop に渡すデータ: [TunnelID][EphemeralPK][Nonce][EncInstruction]
            let mut hop_data = Vec::new();
            hop_data.extend_from_slice(&listen_tunnel_id);
            hop_data.extend_from_slice(&ephemeral_pk_bytes);
            hop_data.extend_from_slice(&nonce);
            hop_data.extend_from_slice(&encrypted_instruction);

            hop_instructions.push((hop_addr, hop_data));

            // 復号鍵を記録 (自分に近い順に追加)
            decrypt_keys.push(shared_secret);

            // 次のループのために tunnel_id を更新
            next_hop_tunnel_id = listen_tunnel_id;
        }

        // hop_instructions を逆順にして Gateway からの順序にする
        hop_instructions.reverse();
        // decrypt_keys は既に自分に近い順なのでそのまま

        let tunnel = InboundTunnel {
            endpoint: TunnelEndpoint {
                gateway: path[0],
                tunnel_id,
            },
            decrypt_keys,
            receive_tunnel_id,
            path,
        };

        Ok((tunnel, hop_instructions))
    }

    /// トンネル経由で受信したデータを復号する
    ///
    /// # Arguments
    /// * `encrypted_data` - Gateway から転送されてきた暗号化データ
    ///
    /// # Returns
    /// * 復号されたペイロード
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        // 各層を復号していく
        let mut data = encrypted_data.to_vec();

        for key in &self.decrypt_keys {
            // データ形式: [Nonce(12)][Ciphertext]
            if data.len() < 12 {
                return Err(AetherError::Crypto("Data too short for nonce".into()));
            }

            let nonce: [u8; 12] = data[..12].try_into().unwrap();
            let ciphertext = &data[12..];

            data = cipher::decrypt(key, &nonce, ciphertext)?;
        }

        Ok(data)
    }

    /// 公開用のエンドポイント情報を取得
    pub fn endpoint(&self) -> &TunnelEndpoint {
        &self.endpoint
    }
}

/// トンネル中継ノードの処理
pub struct TunnelRelay {
    /// 登録されたトンネル: tunnel_id -> (共有鍵, 次ホップ, 次のトンネルID)
    tunnels: std::collections::HashMap<[u8; 32], ([u8; 32], SocketAddr, [u8; 32])>,
}

impl Default for TunnelRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelRelay {
    pub fn new() -> Self {
        Self {
            tunnels: std::collections::HashMap::new(),
        }
    }

    /// トンネルを登録する (Gateway がトンネル構築時に呼ばれる)
    pub fn register_tunnel(
        &mut self,
        tunnel_id: [u8; 32],
        shared_key: [u8; 32],
        next_hop: SocketAddr,
        next_tunnel_id: [u8; 32],
    ) {
        self.tunnels.insert(tunnel_id, (shared_key, next_hop, next_tunnel_id));
    }

    /// トンネルデータを処理する
    ///
    /// # Returns
    /// * `Ok(Some((next_hop, next_tunnel_id, forwarded_data)))` - 転送先情報
    /// * `Ok(None)` - 最終宛先 (自分)
    /// * `Err` - 処理失敗
    pub fn process_tunnel_data(
        &self,
        tunnel_id: &[u8; 32],
        data: &[u8],
    ) -> Result<Option<ForwardingInstruction>> {
        let (shared_key, next_hop, next_tunnel_id) = self.tunnels.get(tunnel_id)
            .ok_or_else(|| AetherError::Config("Unknown tunnel ID".into()))?;

        // データを暗号化 (Inbound Tunnel は通過するたびに暗号化層を追加する)
        // Note: 変数名は decrypt_key だが、実際は共有秘密鍵であり、ここでは暗号化に使う
        let (encrypted_data, nonce) = cipher::encrypt(shared_key, data)?;

        // [Nonce][EncryptedData] の形式にする
        let mut forwarded_data = Vec::new();
        forwarded_data.extend_from_slice(&nonce);
        forwarded_data.extend_from_slice(&encrypted_data);

        // 次のホップに転送
        Ok(Some((*next_hop, *next_tunnel_id, forwarded_data)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_endpoint_serialization() {
        let endpoint = TunnelEndpoint {
            gateway: "127.0.0.1:9000".parse().unwrap(),
            tunnel_id: [1u8; 32],
        };

        let serialized = bincode::serialize(&endpoint).unwrap();
        let deserialized: TunnelEndpoint = bincode::deserialize(&serialized).unwrap();

        assert_eq!(endpoint.gateway, deserialized.gateway);
        assert_eq!(endpoint.tunnel_id, deserialized.tunnel_id);
    }

    #[test]
    fn test_tunnel_build_processing_decrypt() {

        use crate::crypto::cipher;

        // 1. Setup Keys
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let alice_pk = x25519_dalek::PublicKey::from(&alice_secret);
        let alice_addr: SocketAddr = "10.0.0.3:9000".parse().unwrap();

        let relay_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let relay_pk = x25519_dalek::PublicKey::from(&relay_secret);
        let relay_addr: SocketAddr = "10.0.0.2:9000".parse().unwrap();

        let gateway_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let gateway_pk = x25519_dalek::PublicKey::from(&gateway_secret);
        let gateway_addr: SocketAddr = "10.0.0.1:9000".parse().unwrap();

        // 2. Build Tunnel: Gateway -> Relay -> Alice
        let path = vec![gateway_addr, relay_addr, alice_addr];
        let hop_pubkeys = vec![gateway_pk.to_bytes(), relay_pk.to_bytes(), alice_pk.to_bytes()];

        let (alice_tunnel, mut hop_instructions) = InboundTunnel::build(path.clone(), hop_pubkeys).unwrap();

        assert_eq!(hop_instructions.len(), 3);  // Gateway, Relay, Alice

        // 3. Register Tunnels
        let mut gateway_node = TunnelRelay::new();
        let mut relay_node = TunnelRelay::new();

        // --- Gateway Registration ---
        let (gw_target, gw_data) = hop_instructions.remove(0);
        assert_eq!(gw_target, gateway_addr);

        let gw_tunnel_id: [u8;32] = gw_data[0..32].try_into().unwrap();
        let gw_eph_pk: [u8;32] = gw_data[32..64].try_into().unwrap();
        let gw_nonce: [u8;12] = gw_data[64..76].try_into().unwrap();
        let gw_enc_inst = &gw_data[76..];

        let gw_eph_pub = x25519_dalek::PublicKey::from(gw_eph_pk);
        let gw_shared = gateway_secret.diffie_hellman(&gw_eph_pub).to_bytes();
        let gw_inst_bytes = cipher::decrypt(&gw_shared, &gw_nonce, gw_enc_inst).unwrap();
        let gw_inst: HopInstruction = bincode::deserialize(&gw_inst_bytes).unwrap();

        gateway_node.register_tunnel(gw_tunnel_id, gw_shared, gw_inst.next_hop.unwrap(), gw_inst.next_tunnel_id);

        // --- Relay Registration ---
        let (r_target, r_data) = hop_instructions.remove(0);
        assert_eq!(r_target, relay_addr);

        let r_tunnel_id: [u8;32] = r_data[0..32].try_into().unwrap();
        let r_eph_pk: [u8;32] = r_data[32..64].try_into().unwrap();
        let r_nonce: [u8;12] = r_data[64..76].try_into().unwrap();
        let r_enc_inst = &r_data[76..];

        let r_eph_pub = x25519_dalek::PublicKey::from(r_eph_pk);
        let r_shared = relay_secret.diffie_hellman(&r_eph_pub).to_bytes();
        let r_inst_bytes = cipher::decrypt(&r_shared, &r_nonce, r_enc_inst).unwrap();
        let r_inst: HopInstruction = bincode::deserialize(&r_inst_bytes).unwrap();

        relay_node.register_tunnel(r_tunnel_id, r_shared, r_inst.next_hop.unwrap(), r_inst.next_tunnel_id);

        // --- Alice (Endpoint) Setup for Encryption ---
        let (alice_target, alice_data) = hop_instructions.remove(0);
        assert_eq!(alice_target, alice_addr);
        let alice_eph_pk: [u8;32] = alice_data[32..64].try_into().unwrap();
        let alice_eph_pub = x25519_dalek::PublicKey::from(alice_eph_pk);
        let alice_shared = alice_secret.diffie_hellman(&alice_eph_pub).to_bytes();

        // 4. Send Data through Tunnel
        let original_msg = b"Hello Anonymously!";

        // Gateway receives Raw Message
        let (gw_next, gw_next_tid, gw_out) = gateway_node.process_tunnel_data(&gw_tunnel_id, original_msg).unwrap().unwrap();
        assert_eq!(gw_next, relay_addr);
        // gw_out is [Nonce][Enc(Msg)]

        // Relay processes (forwarded from Gateway)
        let (r_next, _r_next_tid, r_out) = relay_node.process_tunnel_data(&gw_next_tid, &gw_out).unwrap().unwrap();
        assert_eq!(r_next, alice_addr);

        // Alice processes (Endpoint encryption)
        // 手動で process_tunnel_data 相当を実行 (Alice Node 実体がないため)
        let (alice_enc, alice_nonce) = cipher::encrypt(&alice_shared, &r_out).unwrap();
        let mut alice_out = Vec::new();
        alice_out.extend_from_slice(&alice_nonce);
        alice_out.extend_from_slice(&alice_enc);

        // Alice Decrypts (Final Hop)
        let decrypted_msg = alice_tunnel.decrypt(&alice_out).unwrap();

        assert_eq!(decrypted_msg, original_msg);
    }
}
