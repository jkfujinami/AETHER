use crate::error::{Result, AetherError};
use crate::net::relay::RelayClient;
use crate::net::gossip::GossipClient;
use crate::net::gossip_server;
use crate::net::relay_list::RelayDirectory;
use crate::mailbox::sharding::{self, Shard};
use crate::mailbox::hint_release::{ReleasePolicy, UploadProfile};
use std::time::Instant;
use crate::protocol::hint::{self, HintPacket, HintPayload};
use crate::protocol::wire;
use crate::crypto::{identity::NodeId, cipher};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use std::net::SocketAddr;

// 型エイリアス
type SharedSecret = [u8; 32];
type HmacSha256 = Hmac<Sha256>;

use crate::net::tunnel::InboundTunnel;

/// 本体を何台の Mailbox に置くか (設計書 18.5.2)
///
/// 増やすほど可用性は上がるが、担当リレーが増える分 Sybil 露出も増える。
pub const K_REPLICAS: usize = 5;

/// 固定チャンクサイズ (設計書 18.8.3-b)
///
/// 転送サイズがそのまま指紋になるため、常にこの単位へ正規化する。
/// 3-Hop Onion のオーバーヘッドは 203 バイト固定なので、
/// 256KB に対しては +0.08% で償却される。
pub const CHUNK_SIZE: usize = 256 * 1024;

/// シュレーディンガーMailboxの実装
pub struct SchrodingerMailbox {
    relay: Arc<RelayClient>,
    gossip: Arc<GossipClient>,
    contacts: Arc<Mutex<HashMap<NodeId, SharedSecret>>>,
    /// K最近接をローカル計算するためのリレーリスト
    directory: Arc<RwLock<RelayDirectory>>,
    /// 返信受信用の Inbound Tunnel
    inbound_tunnels: Arc<Mutex<Vec<InboundTunnel>>>,
    /// 生成する Hint に課す PoW 難易度（19.2.1）
    ///
    /// 既定 0（テスト・私信の即時性優先）。実運用では
    /// [`with_pow_difficulty`](Self::with_pow_difficulty) で網の値を入れる。
    hint_pow_difficulty: u32,
}

impl SchrodingerMailbox {
    pub fn new(
        relay: Arc<RelayClient>,
        gossip: Arc<GossipClient>,
        contacts: Arc<Mutex<HashMap<NodeId, SharedSecret>>>
    ) -> Self {
        Self::with_directory(relay, gossip, contacts, Arc::new(RwLock::new(RelayDirectory::default())))
    }

    pub fn with_directory(
        relay: Arc<RelayClient>,
        gossip: Arc<GossipClient>,
        contacts: Arc<Mutex<HashMap<NodeId, SharedSecret>>>,
        directory: Arc<RwLock<RelayDirectory>>,
    ) -> Self {
        Self {
            relay,
            gossip,
            contacts,
            directory,
            inbound_tunnels: Arc::new(Mutex::new(Vec::new())),
            hint_pow_difficulty: 0,
        }
    }

    /// 生成 Hint の PoW 難易度を設定する（放流網の要求値に合わせる）
    pub fn with_pow_difficulty(mut self, difficulty: u32) -> Self {
        self.hint_pow_difficulty = difficulty;
        self
    }

    /// mailbox_key の担当リレーをローカル計算で決める
    ///
    /// **ネットワークへ問い合わせない。** 問い合わせると
    /// 「誰が何を探しているか」が観測される (Part 10.1)。
    /// 送信側と受信側が同じ `key` から独立に同じ集合へ到達する。
    pub async fn mailbox_targets(
        &self,
        mailbox_key: &[u8; 32],
        key: &SharedSecret,
    ) -> Vec<SocketAddr> {
        self.directory
            .read()
            .await
            .mailbox_targets(mailbox_key, key, K_REPLICAS)
            .into_iter()
            .map(|r| r.addr)
            .collect()
    }

    /// シャード `i` の担当リレーをローカル計算で決める (18.5.4)
    ///
    /// シャードごとに独立した座標を使うのでリング全体に散る。
    /// 攻撃者が1つの弧を支配しても取れるシャードは1個で、復元には届かない。
    pub async fn shard_targets(
        &self,
        mailbox_key: &[u8; 32],
        key: &SharedSecret,
        shard_index: u8,
    ) -> Vec<SocketAddr> {
        self.directory
            .read()
            .await
            .shard_targets(mailbox_key, key, shard_index, K_REPLICAS)
            .into_iter()
            .map(|r| r.addr)
            .collect()
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

        // 4. Hint 生成（この nonce = mailbox_key の素）
        let hint_packet = self.build_hint(&shared_secret, &nonce)?;

        Ok((payload, hint_packet))
    }

    /// 既存の nonce（= mailbox_key の素）に対して Hint を1つ組み立てる
    ///
    /// timestamp を毎回**現在時刻**で入れるので、同じコンテンツに対して
    /// 呼ぶたびに別の（新しい）Hint になる。これが再放流 (18.3-A) の核 ──
    /// 保持者が nonce を知っていれば、鮮度を保った Hint を作り直せる。
    fn build_hint(&self, shared_secret: &SharedSecret, nonce: &[u8; 32]) -> Result<HintPacket> {
        // Hint Payload: Nonce(32) || MsgID || Timestamp
        //
        // timestamp は受信側の鮮度検査に使う。必ず実時刻を入れること。
        let hint_payload = HintPayload {
            nonce: *nonce,
            message_id: rand::random::<u64>(),
            timestamp: hint::current_timestamp(),
        };
        let hint_payload_bytes = bincode::serialize(&hint_payload)
            .map_err(|e| AetherError::Config(e.to_string()))?;

        let hint_key = self.derive_key(shared_secret, b"aether_hint_v1");
        let (hint_ciphertext, hint_encrypt_nonce) = cipher::encrypt(&hint_key, &hint_payload_bytes)?;

        // Blind Tag = HMAC(K, hint_nonce)[0..4]
        let mut mac = HmacSha256::new_from_slice(shared_secret)
            .map_err(|_| AetherError::Crypto("HMAC init failed".into()))?;
        mac.update(&hint_encrypt_nonce);
        let mac_result = mac.finalize().into_bytes();
        let blind_tag: [u8; 4] = mac_result[0..4].try_into().unwrap();

        let mut hint_packet = HintPacket::new(
            blind_tag,
            hint_encrypt_nonce,
            hint_ciphertext,
            gossip_server::DEFAULT_HINT_TTL,
        );

        // 放流網が要求する PoW を解いておく（難易度 0 なら即座）。
        hint_packet.seal_pow(self.hint_pow_difficulty)?;
        Ok(hint_packet)
    }

    /// メッセージを送信
    ///
    /// 本体の PUT と Hint の放流はどちらも Onion 回路を経由する。
    /// Hint だけ素で流すと Entry Relay に発信源が割れる。
    pub async fn send_message(&self, to: &NodeId, message: &[u8]) -> Result<()> {
        self.send_message_with_policy(to, message, &ReleasePolicy::default()).await
    }

    /// 放流方針を指定して送信する
    ///
    /// 本体を配置したあと、送信の大きさと所要時間から遅延を計算して Hint を流す。
    /// チャット程度の大きさなら遅延は 0 になる（中継トラフィックに埋もれるため）。
    pub async fn send_message_with_policy(
        &self,
        to: &NodeId,
        message: &[u8],
        policy: &ReleasePolicy,
    ) -> Result<()> {
        let (hint, _mailbox_key, profile) = self.place_body_profiled(to, message).await?;

        let delay = policy.delay_for(&profile);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }

        self.gossip.broadcast(&hint).await
    }

    /// 現在の観測値から放流方針を組み立てる
    ///
    /// `observed_hint_rate` は Broadcast Veil のおかげでローカル観測できる。
    pub fn release_policy(&self, observed_hint_rate: f64, relay_throughput_bps: f64) -> ReleasePolicy {
        ReleasePolicy {
            relay_throughput_bps,
            observed_hint_rate,
            ..ReleasePolicy::default()
        }
    }

    /// 本体の配置だけ行い、Hint は返すだけで放流しない
    ///
    /// 一次放流者対策の時間分離 (18.4.5) を挟む場合、
    /// 呼び出し側がここで得た Hint を遅延させてから流す。
    ///
    /// 戻り値の `mailbox_key` は、実際に配置に使われたもの。
    /// `prepare_packet` は呼ぶたびに新しい nonce を引くため、
    /// 呼び出し側が別途 `prepare_packet` した結果とは一致しない。
    pub async fn place_body(
        &self,
        to: &NodeId,
        message: &[u8],
    ) -> Result<(HintPacket, [u8; 32])> {
        let (hint, key, _) = self.place_body_profiled(to, message).await?;
        Ok((hint, key))
    }

    /// 本体を配置し、送信の実測プロファイルも返す
    ///
    /// 返り値の [`UploadProfile`] は遅延窓の計算に使う。
    /// **実際にネットワークへ出したバイト数**（シャード込み、レプリカ込み）を数える。
    /// 元データ長ではない — 観測者が見るのは実送出量だから。
    pub async fn place_body_profiled(
        &self,
        to: &NodeId,
        message: &[u8],
    ) -> Result<(HintPacket, [u8; 32], UploadProfile)> {
        let started = Instant::now();
        let mut sent_bytes: u64 = 0;
        let shared_secret = self.shared_secret_for(to)?;
        let (payload, hint) = self.prepare_packet(to, message)?;

        let mailbox_key: [u8; 32] = payload[0..32].try_into().expect("payload 先頭は 32 バイト");

        // 1. 本体を Reed-Solomon 3+2 に分割し、シャードごとに別の座標へ置く
        //
        // どの保持者もファイル全体を持たない。5個中3個で復元でき、
        // 検閲するにはリング上の離れた3箇所を同時に押さえる必要がある。
        let body = &payload[32..];
        let shards = sharding::encode(body)?;

        for shard in &shards {
            let targets = self
                .shard_targets(&mailbox_key, &shared_secret, shard.index)
                .await;

            if targets.is_empty() {
                return Err(AetherError::Config(
                    "Relay directory is empty; cannot place shards".into(),
                ));
            }

            // Mailbox ペイロード: [ShardKey(32)][封をしたシャード]
            //
            // 封（HMAC）が無いと、K レプリカのうち1台が偽シャードを返すだけで
            // 復元が止まる。保持者は中身を読めないが書き換えは自由にできる
            let shard_key = sharding::shard_key(&mailbox_key, shard.index);
            let sealed = sharding::seal(shard, &mailbox_key, &self.shard_mac_key(&shared_secret));

            let mut put = Vec::with_capacity(32 + sealed.len());
            put.extend_from_slice(&shard_key);
            put.extend_from_slice(&sealed);

            for target in targets {
                self.relay.send_onion_message(&put, target).await?;
                sent_bytes += put.len() as u64;
            }
        }

        let profile = UploadProfile {
            bytes: sent_bytes,
            duration: started.elapsed(),
        };

        Ok((hint, mailbox_key, profile))
    }

    /// Hint を放流する
    ///
    /// [`place_body_profiled`] で本体を置いたあと、
    /// 時間分離の遅延を挟んでから呼ぶ (18.4.5)。
    pub async fn broadcast_hint(&self, hint: &HintPacket) -> Result<()> {
        self.gossip.broadcast(hint).await
    }

    fn shared_secret_for(&self, to: &NodeId) -> Result<SharedSecret> {
        let contacts = self.contacts.lock().unwrap();
        contacts
            .get(to)
            .copied()
            .ok_or(AetherError::Config("Contact not found".into()))
    }

    /// 受信した Hint を試行復号する
    ///
    /// 戻り値の共有秘密は Mailbox 位置 `H(mailbox_key ‖ K)` の計算に必要。
    pub fn try_decrypt_hint(&self, hint: &HintPacket) -> Option<([u8; 32], SharedSecret)> {
        let candidates = self.find_candidates(&hint.blind_tag, &hint.nonce);
        if candidates.is_empty() { return None; }

        let now = hint::current_timestamp();

        for shared_secret in candidates {
            let hint_key = self.derive_key(&shared_secret, b"aether_hint_v1");
            if let Ok(payload_bytes) = cipher::decrypt(&hint_key, &hint.nonce, &hint.ciphertext)
                && let Ok(payload) = bincode::deserialize::<HintPayload>(&payload_bytes)
            {
                // 受信者の取得判断は backlog 窓(24h)で見る。
                // オフライン明けに拾った古い Hint も、本体がまだ生きていれば取りに行く
                // (19.1.3)。それより古ければ本体も消えているので捨てる。
                if !payload.is_fresh_within(now, crate::net::hint_log::RETENTION_WINDOW_SECS) {
                    continue;
                }

                use sha2::Digest;
                let mailbox_key: [u8; 32] = Sha256::digest(payload.nonce).into();
                return Some((mailbox_key, shared_secret));
            }
        }
        None
    }

    /// 自分宛ての Hint なら、担当 Mailbox へ取得要求を出す
    ///
    /// 応答は同期的には返らない。Mailbox は [`InboundTunnel`] 経由で
    /// 投げ返すので、[`poll_replies`] で回収する。
    /// 直接返させると要求者の IP が Mailbox に割れるため、この非同期性は必須。
    ///
    /// 戻り値は要求を出した `mailbox_key`。自分宛てでなければ `None`。
    pub async fn process_hint(&self, hint: &HintPacket) -> Result<Option<[u8; 32]>> {
        let Some((mailbox_key, shared_secret)) = self.try_decrypt_hint(hint) else {
            return Ok(None);
        };

        let reply_to = {
            let tunnels = self.inbound_tunnels.lock().unwrap();
            tunnels
                .first()
                .map(|t| t.endpoint.clone())
                .ok_or(AetherError::Config(
                    "No inbound tunnel; cannot receive the reply anonymously".into(),
                ))?
        };

        // 全シャードを要求する。3個返ってくれば復元できるので、
        // 遅いノード・落ちたノードを待つ必要がない（これが実効速度の主因）。
        let mut requested = 0;
        for index in 0..sharding::TOTAL_SHARDS as u8 {
            let shard_key = sharding::shard_key(&mailbox_key, index);
            let request = wire::build_mailbox_get(&shard_key, &reply_to)?;

            for target in self.shard_targets(&mailbox_key, &shared_secret, index).await {
                self.relay
                    .send_onion_message_typed(wire::PacketType::MailboxGet, &request, target)
                    .await?;
                requested += 1;
            }
        }

        if requested == 0 {
            return Err(AetherError::Config("Relay directory is empty".into()));
        }

        Ok(Some(mailbox_key))
    }

    /// Inbound Tunnel に届いた応答を復号して取り出す
    ///
    /// `raw` は自ノードの Mailbox から `fetch_tunnel_messages` で取り出したもの。
    pub fn decrypt_replies(&self, raw: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let tunnels = self.inbound_tunnels.lock().unwrap();

        raw.iter()
            .filter_map(|data| tunnels.iter().find_map(|t| t.decrypt(data).ok()))
            .collect()
    }

    /// 返信受信用の Inbound Tunnel を登録する
    pub fn register_inbound_tunnel(&self, tunnel: InboundTunnel) {
        self.inbound_tunnels.lock().unwrap().push(tunnel);
    }

    /// 内部の RelayClient への参照（テスト・上位層から直接送信したい場合）
    pub fn relay_client(&self) -> &RelayClient {
        &self.relay
    }

    /// トンネルで回収したシャード群から本体を復元し、平文へ戻す
    ///
    /// 3個揃っていれば、どの組み合わせでも復元できる。
    /// 揃っていなければ `None`（まだ到着待ち）。
    pub fn reassemble(
        &self,
        replies: &[Vec<u8>],
        mailbox_key: &[u8; 32],
        key: &SharedSecret,
    ) -> Result<Option<Vec<u8>>> {
        let mac_key = self.shard_mac_key(key);
        let mut shards: Vec<Shard> = Vec::new();

        for reply in replies {
            // Mailbox の値は [封をしたシャード]（キーは取得時に剥がれている）。
            //
            // 封を検めずに受け入れると、悪意ある保持者が1台いるだけで
            // 復元が永久に止まる。RS は消失訂正であって誤り訂正ではないので、
            // 壊れたシャードを1枚混ぜられた時点で結果が丸ごと壊れる。
            // タグは mailbox_key も含むので、別メッセージの混入も弾ける
            let Some(shard) = sharding::open(reply, mailbox_key, &mac_key) else {
                continue;
            };

            if !shards.iter().any(|s| s.index == shard.index) {
                shards.push(shard);
            }
        }

        if shards.len() < sharding::DATA_SHARDS {
            return Ok(None);
        }

        let body = sharding::decode(&shards)?;
        Ok(Some(self.decrypt_mailbox_value(&body, key)?))
    }

    /// Mailbox に格納された値を平文へ戻す
    ///
    /// 値の形式: `[MsgNonce(12)][EncMsg]`
    pub fn decrypt_mailbox_value(&self, stored: &[u8], key: &SharedSecret) -> Result<Vec<u8>> {
        if stored.len() < 12 {
            return Err(AetherError::Protocol("Mailbox value too short".into()));
        }

        let nonce: [u8; 12] = stored[0..12].try_into().expect("長さ確認済み");
        let message_key = self.derive_key(key, b"aether_message_v1");
        cipher::decrypt(&message_key, &nonce, &stored[12..])
    }

    /// 応答受信に使う Tunnel ID
    pub fn receive_tunnel_id(&self) -> Option<[u8; 32]> {
        self.inbound_tunnels
            .lock()
            .unwrap()
            .first()
            .map(|t| t.receive_tunnel_id)
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

    /// シャード認証鍵（テスト・上位層が保存形式を組み立てる場合）
    pub fn shard_mac_key_for(&self, shared_secret: &SharedSecret) -> [u8; 32] {
        self.shard_mac_key(shared_secret)
    }

    /// シャード認証用の鍵
    ///
    /// 本文暗号鍵とは分ける。同じ鍵を暗号化と MAC に使い回さない
    fn shard_mac_key(&self, shared_secret: &SharedSecret) -> [u8; 32] {
        self.derive_key(shared_secret, b"aether_shard_mac_v1")
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
