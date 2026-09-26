use crate::error::{Result, AetherError};
use crate::crypto::{key_exchange, cipher};
use std::net::SocketAddr;
use x25519_dalek::PublicKey;
use serde::{Serialize, Deserialize};

/// 双方向匿名通信のための返信ブロック
/// 受信者はこれを使って、送信元の身元を知ることなく返信できる
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyBlock {
    // 最初の返信先（送信者にとってのEntry Node）
    pub first_hop: SocketAddr,

    // ここには本来、多層暗号化に必要な鍵情報やRouting Pathが含まれる
    // 今回は簡易実装としてバイナリblobとする
    pub callback_data: Vec<u8>,
}

/// Onion Circuit の最大ホップ数
pub const MAX_HOPS: usize = 3;

/// パディング後の最小サイズ（最内層）
///
/// Hint・MailboxGet・小さな私信シャードは全部この 1 バケットに収まり、
/// 中継から見て区別できなくなる。
const MIN_PADDED_LEN: usize = 1024;

/// これを超えるとバケットを 2 の冪でなくこの刻みにする（大きな本体で倍近く膨らませない）
const LARGE_PAD_STEP: usize = 256 * 1024;

/// 最内層を切り上げるバケットの大きさ
///
/// **中継は転送するパケットの長さを見ている。** 長さが中身そのままだと
/// 「Hint（数十B）か、本体シャード（数百KB）か、GET（数十B）か」が
/// 長さだけで分かり、役割の分類とセッション相関の足場になる。
/// 1KB から 2 の冪、256KB 超は 256KB 刻みに正規化する。
pub fn padded_len(n: usize) -> usize {
    if n <= MIN_PADDED_LEN {
        MIN_PADDED_LEN
    } else if n <= LARGE_PAD_STEP {
        n.next_power_of_two()
    } else {
        n.div_ceil(LARGE_PAD_STEP) * LARGE_PAD_STEP
    }
}

/// 回路内の各Hopの情報
#[derive(Debug)]
struct Hop {
    addr: SocketAddr,
    shared_secret: [u8; 32],
    client_ephemeral_pub: PublicKey,
    #[allow(dead_code)]
    peer_pubkey: PublicKey,
}

/// クライアント側の Onion 回路
#[derive(Debug)]
pub struct OnionCircuit {
    hops: Vec<Hop>,
    #[allow(dead_code)]
    circuit_id: u32,
}

impl OnionCircuit {
    /// 新しい回路を作成（まだ空）
    pub fn new(circuit_id: u32) -> Self {
        Self {
            hops: Vec::with_capacity(MAX_HOPS),
            circuit_id,
        }
    }

    /// ホップを追加 (Handshakeを実行して共有鍵を確立する想定)
    pub fn add_hop(&mut self, addr: SocketAddr, peer_pubkey_bytes: [u8; 32], ephemeral_secret: key_exchange::EphemeralKey) -> Result<()> {
        let peer_pubkey = key_exchange::public_from_bytes(&peer_pubkey_bytes);

        // クライアント側の一時公開鍵を保存（パケットに添付するため）
        let client_ephemeral_pub = ephemeral_secret.public_key();

        // ECDH で共有シークレットを導出
        // ephemeral_secret は消費される
        let shared_secret = ephemeral_secret.diffie_hellman(&peer_pubkey);

        self.hops.push(Hop {
            addr,
            shared_secret,
            client_ephemeral_pub,
            peer_pubkey,
        });

        Ok(())
    }

    /// ペイロードをOnion暗号化する
    /// HeaderFlags: 0x01 = Relay, 0x00 = Final
    /// Structure: [One-Time-Pubkey(32)] + [Nonce(12)] + [Ciphertext]
    ///
    /// 最終宛先は Onion 層ではなく最内層のペイロード
    /// (`InnerPacketType::MailboxForward`) が持つ。
    /// 出口リレーだけがそれを読める。
    pub fn wrap_packet(&self, final_payload: &[u8]) -> Result<Vec<u8>> {
        // 最深部 (Final Layer): Flag 0x00 + Len(u32 BE) + Payload + 乱数パディング
        //
        // パディングは暗号文の内側に入るので、出口以外は真の長さを知れない。
        // 外側の層が足す分はホップごとに一定なので、どのホップでもバケットが保たれる。
        let payload_len = u32::try_from(final_payload.len())
            .map_err(|_| AetherError::Protocol("Onion payload too large".into()))?;
        let unpadded = 1 + 4 + final_payload.len();
        let mut current_data = Vec::with_capacity(padded_len(unpadded));
        current_data.push(0x00);
        current_data.extend_from_slice(&payload_len.to_be_bytes());
        current_data.extend_from_slice(final_payload);
        let mut pad = vec![0u8; padded_len(unpadded) - unpadded];
        rand::Rng::fill(&mut rand::thread_rng(), &mut pad[..]);
        current_data.extend_from_slice(&pad);

        // 内側から外側へ暗号化
        for (i, hop) in self.hops.iter().enumerate().rev() {
            // 暗号化
            let (ciphertext, nonce) = cipher::encrypt(&hop.shared_secret, &current_data)?;

            // 次の層のデータ構築: [Pubkey] + [Nonce] + [Ciphertext]
            let mut layer_data = Vec::new();
            layer_data.extend_from_slice(hop.client_ephemeral_pub.as_bytes()); // 32 bytes
            layer_data.extend_from_slice(&nonce);                               // 12 bytes
            layer_data.extend_from_slice(&ciphertext);

            current_data = layer_data;

            if i > 0 {
                // 外側の層のために、現在のhopのaddrを付与する
                // Flag 0x01 + Addr + Payload
                let target_addr_bytes = bincode::serialize(&hop.addr)
                    .map_err(|e| AetherError::Config(e.to_string()))?;

                let mut new_data = Vec::new();
                new_data.push(0x01); // Relay Flag
                new_data.extend_from_slice(&target_addr_bytes);
                new_data.extend_from_slice(&current_data);

                current_data = new_data;
            }
        }

        Ok(current_data)
    }

    /// パケットを「皮剥き」する (Relayノード用)
    /// Input: Encrypted Packet [Pubkey(32)] + [Nonce(12)] + [Ciphertext]
    /// Output: Next Hop Address + Decrypted Inner Packet
    pub fn unwrap_packet(shared_secret: &[u8; 32], packet: &[u8]) -> Result<(Option<SocketAddr>, Vec<u8>)> {
        // パケット構造チェック
        if packet.len() < 32 + cipher::NONCE_SIZE {
            return Err(AetherError::Crypto("Packet too short".into()));
        }

        // Pubkey (32) はスキップ (Router側で既に読んでいる前提、あるいはここでは使わない)
        let (_pubkey, rest) = packet.split_at(32);

        let (nonce, ciphertext) = rest.split_at(cipher::NONCE_SIZE);
        let nonce_arr: [u8; 12] = nonce.try_into().expect("slice length check");

        let mut plaintext = cipher::decrypt(shared_secret, &nonce_arr, ciphertext)?;

        if plaintext.is_empty() {
            return Err(AetherError::Protocol("Empty plaintext".into()));
        }

        // 先頭バイトでフラグ判定
        let flag = plaintext[0];
        let mut cursor = std::io::Cursor::new(&plaintext);
        cursor.set_position(1); // Skip flag

        match flag {
            0x00 => {
                // Final destination: 長さで切り出してパディングを捨てる
                let len_bytes: [u8; 4] = plaintext
                    .get(1..5)
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| AetherError::Protocol("Final layer too short".into()))?;
                let len = u32::from_be_bytes(len_bytes) as usize;
                let inner_payload = plaintext
                    .get(5..5 + len)
                    .ok_or_else(|| AetherError::Protocol("Final layer length out of range".into()))?
                    .to_vec();
                Ok((None, inner_payload))
            },
            0x01 => {
                // Relay: Parse next hop address
                let next_addr: SocketAddr = bincode::deserialize_from(&mut cursor)
                    .map_err(|e| AetherError::Config(format!("Failed to deserialize address: {}", e)))?;

                let pos = cursor.position() as usize;
                let inner_payload = plaintext.split_off(pos);
                Ok((Some(next_addr), inner_payload))
            },
            _ => Err(AetherError::Protocol(format!("Unknown routing flag: 0x{:02x}", flag))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{key_exchange};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_onion_wrap_unwrap() {
        // 1. 回路の準備
        let mut circuit = OnionCircuit::new(1);

        // 3つのホップ
        let relays = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 8080),
        ];

        let mut relay_secrets = Vec::new();

        // 疑似的にHandshake
        for addr in &relays {
            let relay_static = key_exchange::StaticKey::generate();
            let client_ephemeral = key_exchange::EphemeralKey::generate();
            let shared = relay_static.diffie_hellman(&client_ephemeral.public_key());
            relay_secrets.push(shared);
            circuit.add_hop(*addr, relay_static.public_key().to_bytes(), client_ephemeral).unwrap();
        }

        // 2. パケット作成
        let msg = b"Hello, Anonymous World!";

        let wrapped_packet = circuit.wrap_packet(msg).unwrap();
        println!("Wrapped packet size: {} bytes", wrapped_packet.len());

        // 3. パケット転送 & 皮剥き

        // --- Hop 1 (Entry Relay) ---
        // 受信側はパケット先頭のPubkeyと自分の秘密鍵でSharedSecretを作るが、
        // テストでは既知の relay_secrets[0] を使う
        let (next_addr1, payload1) = OnionCircuit::unwrap_packet(&relay_secrets[0], &wrapped_packet).unwrap();
        println!("Relay 1 unwrapped. Next: {:?}", next_addr1);
        assert_eq!(next_addr1.unwrap(), relays[1]);

        // --- Hop 2 (Middle Relay) ---
        let (next_addr2, payload2) = OnionCircuit::unwrap_packet(&relay_secrets[1], &payload1).unwrap();
        println!("Relay 2 unwrapped. Next: {:?}", next_addr2);
        assert_eq!(next_addr2.unwrap(), relays[2]);

        // --- Hop 3 (Exit Relay) ---
        let (next_addr3, payload3) = OnionCircuit::unwrap_packet(&relay_secrets[2], &payload2).unwrap();
        println!("Relay 3 unwrapped. Next: {:?}", next_addr3);

        assert!(next_addr3.is_none());
        assert_eq!(payload3, msg);
    }

    /// 1ホップ回路を作り、(回路, 中継側の共有秘密) を返す
    fn single_hop() -> (OnionCircuit, [u8; 32]) {
        let mut circuit = OnionCircuit::new(1);
        let relay_static = key_exchange::StaticKey::generate();
        let client_ephemeral = key_exchange::EphemeralKey::generate();
        let shared = relay_static.diffie_hellman(&client_ephemeral.public_key());
        circuit
            .add_hop("10.0.0.1:8080".parse().unwrap(), relay_static.public_key().to_bytes(), client_ephemeral)
            .unwrap();
        (circuit, shared)
    }

    #[test]
    fn small_payloads_are_indistinguishable_by_length() {
        // Hint（数十B）と GET（百B弱）が同じ長さに見えること。
        // 長さで役割を分類されると中継に相関の足場を与える。
        let (circuit, _) = single_hop();
        let hint_like = circuit.wrap_packet(&[0x10; 40]).unwrap();
        let get_like = circuit.wrap_packet(&[0x21; 180]).unwrap();
        assert_eq!(hint_like.len(), get_like.len());
    }

    #[test]
    fn padding_is_stripped_at_the_exit() {
        let (circuit, shared) = single_hop();
        for size in [0usize, 1, 1019, 1020, 5000, 300 * 1024] {
            let msg: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let wrapped = circuit.wrap_packet(&msg).unwrap();
            let (next, out) = OnionCircuit::unwrap_packet(&shared, &wrapped).unwrap();
            assert!(next.is_none());
            assert_eq!(out, msg, "size {}", size);
        }
    }

    #[test]
    fn padded_len_buckets() {
        assert_eq!(padded_len(0), 1024);
        assert_eq!(padded_len(1024), 1024);
        assert_eq!(padded_len(1025), 2048);
        assert_eq!(padded_len(200 * 1024), 256 * 1024);
        assert_eq!(padded_len(256 * 1024 + 1), 512 * 1024);
        assert_eq!(padded_len(1024 * 1024 + 1), 1024 * 1024 + 256 * 1024);
    }
}
