use crate::error::{Result, AetherError};
use crate::net::relay::RelayClient;
use crate::net::gossip::GossipClient;
use crate::net::gossip_server;
use crate::net::relay_list::RelayDirectory;
use crate::mailbox::sharding::{self, Shard};
use crate::mailbox::index::{self, IndexDescriptor, IndexRecord};
use crate::mailbox::chunk;
use crate::mailbox::sharding_v2;
use crate::mailbox::hint_release::{ReleasePolicy, UploadProfile};
use crate::net::tunnel::TunnelEndpoint;
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

/// 索引の記述子に解く PoW の下限（ビット）。2^16 回の SHA-256 で、1 件あたり数十ミリ秒
const INDEX_RECORD_MIN_POW: u32 = 16;

/// 内容アドレスに一致するシャードの組み合わせを探す回数の上限
///
/// 板の読者なら誰でも封の通る偽シャードを作れるので、最初に届いた組が正しいとは限らない。
/// 上限は、偽シャードを大量に送りつけられても CPU を食い尽くされないため。
const MAX_REASSEMBLY_ATTEMPTS: usize = 256;

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
        let shared_secret = self.shared_secret_for(to)?;
        let (payload, hint) = self.prepare_packet(to, message)?;

        let mailbox_key: [u8; 32] = payload[0..32].try_into().expect("payload 先頭は 32 バイト");

        // 本体（[msg_nonce][enc]）を RS で割って配置する。
        let profile = self
            .place_object(&mailbox_key, &shared_secret, &payload[32..])
            .await?;

        Ok((hint, mailbox_key, profile))
    }

    /// 前方秘匿された本体（[`Session::seal`] 済み）を配置する (3-1)
    ///
    /// 本文は既にラチェットで暗号化済みなので、ここは mailbox_key・シャード・Hint を
    /// 組むだけ。**Hint 認識（blind_tag）は静的な共有秘密のまま**なので、受信者は
    /// 従来どおり「自分宛て」を判定できる（前方秘匿は本文だけに掛ける）。
    ///
    /// [`Session::open`]: crate::crypto::session::Session::open
    /// [`Session::seal`]: crate::crypto::session::Session::seal
    pub async fn place_ratchet_body(
        &self,
        to: &NodeId,
        sealed_body: &[u8],
    ) -> Result<(HintPacket, [u8; 32], UploadProfile)> {
        use sha2::Digest;
        let secret = self.shared_secret_for(to)?;

        let nonce = cipher::generate_key(); // 32B。SHA256(nonce) = mailbox_key
        let mailbox_key: [u8; 32] = Sha256::digest(nonce).into();

        let profile = self.place_object(&mailbox_key, &secret, sealed_body).await?;
        let hint = self.build_hint(&secret, &nonce)?;
        Ok((hint, mailbox_key, profile))
    }

    /// 任意のオブジェクト（`[nonce(12)][ciphertext]`）を指定 mailbox_key に配置する
    ///
    /// Reed-Solomon 3+2 に割り、シャードごとに封をして `H(mailbox_key ‖ K ‖ i)` の
    /// 担当へ置く。**本体・チャンク・Manifest すべてこれを通る**（Hint は作らない）。
    ///
    /// - どの保持者もオブジェクト全体を持たない（5個中3個で復元）。
    /// - 封（HMAC）が無いと、K レプリカの1台が偽シャードを返すだけで復元が止まる。
    ///   RS は消失訂正であって誤り訂正ではないため。
    pub async fn place_object(
        &self,
        mailbox_key: &[u8; 32],
        secret: &SharedSecret,
        object: &[u8],
    ) -> Result<UploadProfile> {
        let started = Instant::now();
        let mut sent_bytes: u64 = 0;
        let mac_key = self.shard_mac_key(secret);
        let shards = sharding::encode(object)?;

        for shard in &shards {
            let targets = self.shard_targets(mailbox_key, secret, shard.index).await;

            if targets.is_empty() {
                return Err(AetherError::Config(
                    "Relay directory is empty; cannot place shards".into(),
                ));
            }

            let shard_key = sharding::shard_key(mailbox_key, shard.index);
            let sealed = sharding::seal(shard, mailbox_key, &mac_key);

            let mut put = Vec::with_capacity(32 + sealed.len());
            put.extend_from_slice(&shard_key);
            put.extend_from_slice(&sealed);

            for target in targets {
                self.relay.send_onion_message(&put, target).await?;
                sent_bytes += put.len() as u64;
            }
        }

        Ok(UploadProfile {
            bytes: sent_bytes,
            duration: started.elapsed(),
        })
    }

    /// 収束的暗号化でオブジェクト `[nonce(12)][ciphertext]` を作り、content-address を返す
    ///
    /// 同じ `(secret, 平文)` からは同じ `(content_ref, object)` が出る ── これが重複排除の要。
    /// `object` は本体と同じ `[nonce][ct]` 形式なので、取得側は
    /// [`reassemble`](Self::reassemble) でそのまま平文へ戻せる。
    fn seal_chunk(&self, secret: &SharedSecret, plaintext: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
        let message_key = self.derive_key(secret, b"aether_message_v1");
        let nonce = chunk::convergent_nonce(secret, plaintext);
        let ciphertext = cipher::encrypt_with_nonce(&message_key, &nonce, plaintext)?;

        let mut object = Vec::with_capacity(12 + ciphertext.len());
        object.extend_from_slice(&nonce);
        object.extend_from_slice(&ciphertext);

        let content_ref = chunk::content_address(&object);
        Ok((content_ref, object))
    }

    /// 大きなファイルを v2 の形で置き、Manifest の `content_ref` を返す（Part 23 の 7 章）
    ///
    /// v2 では 16 チャンクごとに RS(16+m) を掛け、**各シャードを担当 1 台にだけ**置く。
    /// **メモリは 1 ストライプ分**: チャンクを封じ、パリティを作り、その場で全シャードを置いて捨てる。
    /// 手元に残すのはハッシュだけ。最後に [`ManifestV2`](chunk::ManifestV2) を小さなものの経路
    /// （[`place_object`](Self::place_object)）で置く。同じ中身のチャンクは収束暗号で同じシャード・
    /// 同じハッシュになり、2 回目の put は保持者が同じ値として受ける。
    ///
    /// `pad` なら、チャンク数を 2 倍刻みに切り上げ（[`chunk::padded_chunk_count`]）、足した分は
    /// ファイルごとに別の中身の埋め草のチャンクにして**本物の後ろに**置く
    /// （[`chunk::pad_chunk_plain`]）。`size` は本当の大きさのまま ── 取る側は復元後に `size` で
    /// 切るので埋め草は落ちる。Manifest は暗号化されていて、ガードには見えない。
    ///
    /// Manifest が 1 オブジェクトに収まらない大きさは、何も送らずにエラーにする。
    /// **互換は無い**（v1 の形では置かない）。公開コンテンツ専用。
    pub async fn place_file_v2(
        &self,
        secret: &SharedSecret,
        name: &str,
        data: &[u8],
        pad: bool,
    ) -> Result<([u8; 32], UploadProfile)> {
        use sha2::Digest;
        let started = Instant::now();
        let size = data.len() as u64;
        // 送る前に確かめる（途中まで置いて断ることのないように）。切り上げた後のチャンク数で数える
        let total_chunks = chunk::v2_layout_chunks(name.len(), size, pad)?;
        let shapes = chunk::v2_stripe_shapes(total_chunks)?;
        let sealed_len = chunk::manifest_v2_sealed_len(name.len(), total_chunks)?;
        if sealed_len > chunk::SINGLE_BODY_LIMIT {
            return Err(AetherError::Config(format!(
                "File too large for a single v2 manifest ({} bytes sealed, max {})",
                sealed_len,
                chunk::SINGLE_BODY_LIMIT
            )));
        }
        let file_hash: [u8; 32] = Sha256::digest(data).into();

        let mut sent_bytes: u64 = 0;
        let mut stripes = Vec::with_capacity(shapes.len());
        let mut next_index: usize = 0;
        for (k, m) in shapes {
            let mut objects = Vec::with_capacity(k);
            for _ in 0..k {
                let plain = v2_chunk_plain(secret, data, &file_hash, next_index, pad);
                objects.push(self.seal_chunk(secret, &plain)?.1);
                next_index += 1;
            }
            let built = sharding_v2::build_stripe(&objects, m)?;
            drop(objects);
            for shard in &built.shards {
                sent_bytes += self.put_shard_v2(secret, shard).await?;
            }
            stripes.push(built.stripe);
        }

        let manifest = chunk::ManifestV2 {
            version: chunk::MANIFEST_V2_VERSION,
            name: name.to_string(),
            size,
            chunk_plain: chunk::V2_CHUNK_PLAIN as u32,
            stripes,
        };
        let (mref, object) = self.seal_chunk(secret, &manifest.encode()?)?;
        let profile = self.place_object(&mref, secret, &object).await?;
        Ok((
            mref,
            UploadProfile {
                bytes: sent_bytes + profile.bytes,
                duration: started.elapsed(),
            },
        ))
    }

    /// v2 のシャード 1 枚を、ハッシュから決まる担当 1 台へ置く。送ったバイト数を返す
    ///
    /// 置き場所は `shard_targets(H(シャード), 秘密, 0)` の先頭 1 台、キーは `shard_key(H, 0)`。
    /// 封（HMAC）は付けない（Manifest のハッシュで 1 枚ずつ照合するため）。
    /// 保持者側は v1 と区別できない `[put_key 32][値]` の形のまま。
    /// 担当が居ないときは黙って飛ばさずエラーにする。
    pub async fn put_shard_v2(&self, secret: &SharedSecret, shard: &[u8]) -> Result<u64> {
        let hash = chunk::shard_hash(shard);
        let targets = self.shard_targets(&hash, secret, 0).await;
        let Some(&target) = targets.first() else {
            return Err(AetherError::Config(
                "Relay directory is empty; cannot place shards".into(),
            ));
        };
        let mut put = Vec::with_capacity(32 + shard.len());
        put.extend_from_slice(&sharding::shard_key(&hash, 0));
        put.extend_from_slice(shard);
        self.relay
            .send_onion_message_typed(wire::PacketType::MailboxPut, &put, target)
            .await?;
        Ok(put.len() as u64)
    }

    /// v2 のシャードをハッシュで指定して、担当 1 台へ要求する（返信は Inbound Tunnel）
    ///
    /// 送った本数を返す。担当が居ないシャードは数えない（呼び出し側が 0 ならエラーにする）。
    pub async fn request_shards_v2(
        &self,
        secret: &SharedSecret,
        hashes: &[[u8; 32]],
    ) -> Result<usize> {
        let reply_to = {
            let tunnels = self.inbound_tunnels.lock().unwrap();
            tunnels
                .first()
                .map(|t| t.endpoint.clone())
                .ok_or(AetherError::Config(
                    "No inbound tunnel; cannot receive the reply anonymously".into(),
                ))?
        };
        let mut sent = 0;
        for hash in hashes {
            let targets = self.shard_targets(hash, secret, 0).await;
            let Some(&target) = targets.first() else {
                continue;
            };
            let request = wire::build_mailbox_get(&sharding::shard_key(hash, 0), &reply_to)?;
            self.relay
                .send_onion_message_typed(wire::PacketType::MailboxGet, &request, target)
                .await?;
            sent += 1;
        }
        Ok(sent)
    }

    /// content-addressed なオブジェクト（チャンク／Manifest）の取得要求を出す (2-4)
    ///
    /// [`fetch_by_ref`](Self::fetch_by_ref) と違い `SHA256(nonce)` の変換をしない ──
    /// `mailbox_key` は content-address そのもの。応答は Inbound Tunnel 経由で戻る。
    pub async fn request_object(&self, mailbox_key: &[u8; 32], secret: &SharedSecret) -> Result<()> {
        self.request_body(mailbox_key, secret).await
    }

    /// 単一 body の `content_ref`（= nonce）から mailbox_key を出す
    ///
    /// [`fetch_by_ref`](Self::fetch_by_ref) が内部で行う変換を、取得側が
    /// 取得要求と復元を分けて回したい場合に使えるよう公開したもの。
    pub fn body_mailbox_key(content_ref: &[u8; 32]) -> [u8; 32] {
        use sha2::Digest;
        Sha256::digest(content_ref).into()
    }

    /// Hint を放流する
    ///
    /// [`place_body_profiled`] で本体を置いたあと、
    /// 時間分離の遅延を挟んでから呼ぶ (18.4.5)。
    pub async fn broadcast_hint(&self, hint: &HintPacket) -> Result<()> {
        self.gossip.broadcast(hint).await
    }

    /// ダウンロードした本体を再シードする (18.3-C・ダウンローダが保持者になる)
    ///
    /// **検証済みの本体**（[`open_public`](Self::open_public) が内容アドレスと照合したもの）
    /// からシャードを作り直し、**現在の** K 最近接へ置き直す。RS 符号化と封は決定論的なので、
    /// 元の投稿者が置いたものと同じシャードになる。
    ///
    /// 受け取ったシャードをそのまま撒き直すと、封の鍵は板の鍵から誰でも導けるので、
    /// 偽のシャードを混ぜられたときに偽物まで広めてしまう。
    pub async fn reseed_object(
        &self,
        mailbox_key: &[u8; 32],
        secret: &SharedSecret,
        object: &[u8],
    ) -> Result<UploadProfile> {
        self.place_object(mailbox_key, secret, object).await
    }

    /// 索引に記述子を1件公開する (19.7 / Phase 2-3)
    ///
    /// キーワードの索引位置 `H(index_key ‖ K_pub)` の担当保持者へ、
    /// **K_pub で封じた記述子**を Onion 経由で追記する。保持者は中身を読めない。
    pub async fn publish_descriptor(
        &self,
        k_pub: &SharedSecret,
        descriptor: &IndexDescriptor,
    ) -> Result<()> {
        // 保持者は索引を PoW の強い順に返す（弱い記述子の洪水で一覧から追い出されないように）。
        // Hint より強めに解いておく。難易度 0（試験）はそのまま
        let difficulty = match self.hint_pow_difficulty {
            0 => 0,
            d => d.max(INDEX_RECORD_MIN_POW),
        };
        let record = IndexRecord::create(k_pub, descriptor, difficulty)?;
        let idx_key = index::index_key(k_pub);
        let record_bytes = record.encode()?;

        // payload: [index_key(32)][record_id(32)][record]
        let mut payload = Vec::with_capacity(64 + record_bytes.len());
        payload.extend_from_slice(&idx_key);
        payload.extend_from_slice(&record.id());
        payload.extend_from_slice(&record_bytes);

        let targets = self.mailbox_targets(&idx_key, k_pub).await;
        if targets.is_empty() {
            return Err(AetherError::Config("Relay directory is empty".into()));
        }
        for target in targets {
            self.relay
                .send_onion_message_typed(wire::PacketType::IndexPut, &payload, target)
                .await?;
        }
        Ok(())
    }

    /// 索引を pull で引く（返信は Inbound Tunnel 経由で戻る）(19.7 / Phase 2-3)
    ///
    /// キーワードを知っていれば誰でも位置を計算でき、Onion 越しに引ける。
    /// 保持者からは「その索引が引かれた」ことは見えるが、**誰が引いたかは割れない**。
    pub async fn query_index(&self, k_pub: &SharedSecret, reply_to: &TunnelEndpoint) -> Result<()> {
        let idx_key = index::index_key(k_pub);
        let request = wire::build_mailbox_get(&idx_key, reply_to)?;

        let targets = self.mailbox_targets(&idx_key, k_pub).await;
        if targets.is_empty() {
            return Err(AetherError::Config("Relay directory is empty".into()));
        }
        for target in targets {
            self.relay
                .send_onion_message_typed(wire::PacketType::IndexQuery, &request, target)
                .await?;
        }
        Ok(())
    }

    /// トンネルで回収した索引応答を記述子へ復号する
    ///
    /// `decrypted` は [`decrypt_replies`](Self::decrypt_replies) を通したもの。
    /// K 保持者ぶんの応答が来るので id で重複排除し、PoW を検証してから開く。
    /// 各記述子に**達成 PoW ビット**（ランク付け用 / 2-7）を添えて返す。
    pub fn decode_index_replies(
        &self,
        decrypted: &[Vec<u8>],
        k_pub: &SharedSecret,
    ) -> Vec<(IndexDescriptor, u32)> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();

        for data in decrypted {
            let Ok(records) = bincode::deserialize::<Vec<Vec<u8>>>(data) else {
                continue;
            };
            for rb in records {
                let Ok(rec) = IndexRecord::decode(&rb) else { continue };
                if !rec.verify_pow(self.hint_pow_difficulty) {
                    continue;
                }
                if !seen.insert(rec.id()) {
                    continue;
                }
                let pow_bits = rec.pow_bits();
                if let Some(d) = rec.open(k_pub) {
                    out.push((d, pow_bits));
                }
            }
        }
        out
    }

    fn shared_secret_for(&self, to: &NodeId) -> Result<SharedSecret> {
        let contacts = self.contacts.lock().unwrap();
        contacts
            .get(to)
            .copied()
            .ok_or(AetherError::Config("Contact not found".into()))
    }

    /// 受信した Hint を復号し、`(nonce, 共有秘密)` を返す
    ///
    /// `nonce` は `mailbox_key = SHA256(nonce)` の素。再放流 (18.3-A) では
    /// この nonce から鮮度を保った Hint を作り直す。
    pub fn decrypt_hint(&self, hint: &HintPacket) -> Option<([u8; 32], SharedSecret)> {
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
                return Some((payload.nonce, shared_secret));
            }
        }
        None
    }

    /// 受信した Hint を試行復号する
    ///
    /// 戻り値の共有秘密は Mailbox 位置 `H(mailbox_key ‖ K)` の計算に必要。
    pub fn try_decrypt_hint(&self, hint: &HintPacket) -> Option<([u8; 32], SharedSecret)> {
        let (nonce, shared_secret) = self.decrypt_hint(hint)?;
        use sha2::Digest;
        let mailbox_key: [u8; 32] = Sha256::digest(nonce).into();
        Some((mailbox_key, shared_secret))
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
        self.request_body(&mailbox_key, &shared_secret).await?;
        Ok(Some(mailbox_key))
    }

    /// 索引で見つけた `content_ref`（= nonce）から本体の取得要求を出す
    ///
    /// pull で発見したコンテンツを取りに行く経路 (Phase 2-3)。
    /// Hint を受け取っていなくても、nonce と鍵さえあれば取得できる。
    /// 戻り値の `mailbox_key` は復元・封検証に要る。
    pub async fn fetch_by_ref(
        &self,
        secret: &SharedSecret,
        content_ref: &[u8; 32],
    ) -> Result<[u8; 32]> {
        use sha2::Digest;
        let mailbox_key: [u8; 32] = Sha256::digest(content_ref).into();
        self.request_body(&mailbox_key, secret).await?;
        Ok(mailbox_key)
    }

    /// 全シャードの取得要求を Inbound Tunnel 返信付きで送る
    ///
    /// 3個返れば復元できるので、遅い・落ちたノードを待たない。
    async fn request_body(&self, mailbox_key: &[u8; 32], secret: &SharedSecret) -> Result<()> {
        let reply_to = {
            let tunnels = self.inbound_tunnels.lock().unwrap();
            tunnels
                .first()
                .map(|t| t.endpoint.clone())
                .ok_or(AetherError::Config(
                    "No inbound tunnel; cannot receive the reply anonymously".into(),
                ))?
        };

        let mut requested = 0;
        for index in 0..sharding::TOTAL_SHARDS as u8 {
            let shard_key = sharding::shard_key(mailbox_key, index);
            let request = wire::build_mailbox_get(&shard_key, &reply_to)?;

            for target in self.shard_targets(mailbox_key, secret, index).await {
                self.relay
                    .send_onion_message_typed(wire::PacketType::MailboxGet, &request, target)
                    .await?;
                requested += 1;
            }
        }

        if requested == 0 {
            return Err(AetherError::Config("Relay directory is empty".into()));
        }
        Ok(())
    }

    /// 指定したシャードだけを、担当の指定した順位の保持者へ要求する（hedged request の 1 段）
    ///
    /// `wants` は `(シャード index, 担当の順位)`。順位は距離の近い順（0 が一番近い）で、
    /// 担当がその順位まで居なければ飛ばす（小さな網では担当が重なる・足りない）。
    /// 送った本数を返す。どの保持者に何番目で頼むかは手元で決めるだけで、網には出ない。
    /// 全シャードへ一斉に出す [`request_body`](Self::request_body) とは別で、そちらは変えない。
    pub async fn request_shards(
        &self,
        mailbox_key: &[u8; 32],
        secret: &SharedSecret,
        wants: &[(u8, usize)],
    ) -> Result<usize> {
        let reply_to = {
            let tunnels = self.inbound_tunnels.lock().unwrap();
            tunnels
                .first()
                .map(|t| t.endpoint.clone())
                .ok_or(AetherError::Config(
                    "No inbound tunnel; cannot receive the reply anonymously".into(),
                ))?
        };

        let mut sent = 0;
        // 同じシャードの担当表は一度だけ計算する
        let mut targets_by_index: HashMap<u8, Vec<SocketAddr>> = HashMap::new();
        for &(index, rank) in wants {
            if index as usize >= sharding::TOTAL_SHARDS {
                continue;
            }
            let targets = match targets_by_index.entry(index) {
                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(self.shard_targets(mailbox_key, secret, index).await)
                }
            };
            let Some(&target) = targets.get(rank) else {
                continue;
            };
            let shard_key = sharding::shard_key(mailbox_key, index);
            let request = wire::build_mailbox_get(&shard_key, &reply_to)?;
            self.relay
                .send_onion_message_typed(wire::PacketType::MailboxGet, &request, target)
                .await?;
            sent += 1;
        }
        Ok(sent)
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
    /// 認識に使う連絡先（共有秘密）を丸ごと差し替える
    ///
    /// 受信の途中で秘密が増える・変わる（会話が立って Hint 鍵チェーンが加わる、日付が
    /// 変わる、友だちが増える）ときに使う。返信トンネルは秘密に依存しないので張り直さない。
    pub fn replace_contacts(&self, contacts: HashMap<NodeId, SharedSecret>) {
        *self.contacts.lock().unwrap() = contacts;
    }

    pub fn register_inbound_tunnel(&self, tunnel: InboundTunnel) {
        self.inbound_tunnels.lock().unwrap().push(tunnel);
    }

    /// 内部の RelayClient への参照（テスト・上位層から直接送信したい場合）
    pub fn relay_client(&self) -> &RelayClient {
        &self.relay
    }

    /// 公開の本体（板への 1 件の投稿）を**内容アドレス**で置く
    ///
    /// 本体 `[MsgNonce(12)][EncMsg]` のハッシュ [`chunk::content_address`] を `content_ref`
    /// とし、`mailbox_key = SHA256(content_ref)` に置く。Hint の nonce も `content_ref` に
    /// するので、Hint から取り寄せた人も索引から取り寄せた人も、**復元した本体のハッシュを
    /// `content_ref` と照合できる**（[`open_public`](Self::open_public)）。
    ///
    /// 板の鍵は読者全員が知っているので、封も暗号も「板の鍵を知る誰か」が作ったことしか
    /// 保証しない。照合が無いと、読者の誰でも同じ ref の中身を別物（マルウェアなど）に
    /// 差し替えられた。
    pub async fn place_public_body(
        &self,
        secret: &SharedSecret,
        message: &[u8],
    ) -> Result<(HintPacket, [u8; 32], UploadProfile)> {
        let message_key = self.derive_key(secret, b"aether_message_v1");
        let (ciphertext, msg_nonce) = cipher::encrypt(&message_key, message)?;
        let mut object = Vec::with_capacity(12 + ciphertext.len());
        object.extend_from_slice(&msg_nonce);
        object.extend_from_slice(&ciphertext);

        let content_ref = chunk::content_address(&object);
        let mailbox_key = Self::body_mailbox_key(&content_ref);
        let profile = self.place_object(&mailbox_key, secret, &object).await?;
        let hint = self.build_hint(secret, &content_ref)?;
        Ok((hint, content_ref, profile))
    }

    /// シャード群から、**内容アドレスが `content_ref` に一致する**生の本体を復元する
    ///
    /// 封の通るシャードを index ごとに集め、3 つの index の組み合わせを試して、
    /// 復元結果のハッシュが一致するものだけを返す。偽シャードが混ざっていても、
    /// 正しいシャードが 3 枚あれば復元できる。
    pub fn reassemble_verified(
        &self,
        replies: &[Vec<u8>],
        mailbox_key: &[u8; 32],
        key: &SharedSecret,
        content_ref: &[u8; 32],
    ) -> Option<Vec<u8>> {
        let mac_key = self.shard_mac_key(key);
        let mut by_index: Vec<Vec<Shard>> = vec![Vec::new(); sharding::TOTAL_SHARDS];
        for reply in replies {
            let Some(shard) = sharding::open(reply, mailbox_key, &mac_key) else {
                continue;
            };
            let slot = &mut by_index[shard.index as usize];
            if !slot.contains(&shard) {
                slot.push(shard);
            }
        }

        let present: Vec<usize> = (0..sharding::TOTAL_SHARDS)
            .filter(|i| !by_index[*i].is_empty())
            .collect();
        let mut attempts = 0;
        for a in 0..present.len() {
            for b in a + 1..present.len() {
                for c in b + 1..present.len() {
                    let [ia, ib, ic] = [present[a], present[b], present[c]];
                    for sa in &by_index[ia] {
                        for sb in &by_index[ib] {
                            for sc in &by_index[ic] {
                                attempts += 1;
                                if attempts > MAX_REASSEMBLY_ATTEMPTS {
                                    return None;
                                }
                                let trio = [sa.clone(), sb.clone(), sc.clone()];
                                if let Ok(object) = sharding::decode(&trio)
                                    && chunk::content_address(&object) == *content_ref
                                {
                                    return Some(object);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// 公開の本体を、内容アドレスを照合したうえで平文へ戻す
    ///
    /// 戻り値は `(平文, 生の本体)`。生の本体は再シード（[`reseed_object`](Self::reseed_object)）に使う。
    pub fn open_public(
        &self,
        replies: &[Vec<u8>],
        mailbox_key: &[u8; 32],
        key: &SharedSecret,
        content_ref: &[u8; 32],
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        let object = self.reassemble_verified(replies, mailbox_key, key, content_ref)?;
        let plain = self.decrypt_mailbox_value(&object, key).ok()?;
        Some((plain, object))
    }

    /// トンネルで回収したシャード群から本体を復元し、平文へ戻す（静的鍵）
    ///
    /// 3個揃っていれば、どの組み合わせでも復元できる。揃っていなければ `None`。
    /// 公開コンテンツ（K_pub 静的暗号）用。私信の前方秘匿は
    /// [`reassemble_raw`](Self::reassemble_raw) で生本体を取り、Session で開く。
    pub fn reassemble(
        &self,
        replies: &[Vec<u8>],
        mailbox_key: &[u8; 32],
        key: &SharedSecret,
    ) -> Result<Option<Vec<u8>>> {
        match self.reassemble_raw(replies, mailbox_key, key)? {
            Some(body) => Ok(Some(self.decrypt_mailbox_value(&body, key)?)),
            None => Ok(None),
        }
    }

    /// シャード群を復元して**生の本体**を返す（復号しない / 3-1 のラチェット用）
    ///
    /// 封（HMAC）の検証は静的な共有秘密で行う（完全性・別メッセージ混入防止）。
    /// 中身の復号は呼び出し側が [`crate::crypto::session::Session::open`] で行う。
    pub fn reassemble_raw(
        &self,
        replies: &[Vec<u8>],
        mailbox_key: &[u8; 32],
        key: &SharedSecret,
    ) -> Result<Option<Vec<u8>>> {
        let mac_key = self.shard_mac_key(key);
        let mut shards: Vec<Shard> = Vec::new();

        for reply in replies {
            // 封を検めずに受け入れると、悪意ある保持者1台で復元が止まる（RS は消失訂正）。
            // タグは mailbox_key も含むので別メッセージの混入も弾ける。
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

        Ok(Some(sharding::decode(&shards)?))
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

/// v2 の `index` 番目のチャンクの平文（本物、または埋め草）
///
/// 本物の後ろに埋め草を続けるので、`pad` のときは短い最後の本物のチャンクもゼロで満杯にする
/// （ストライプの途中に短いオブジェクトを置けない）。取る側は復元後に `size` で切るので落ちる。
fn v2_chunk_plain(
    secret: &SharedSecret,
    data: &[u8],
    file_hash: &[u8; 32],
    index: usize,
    pad: bool,
) -> Vec<u8> {
    let start = index * chunk::V2_CHUNK_PLAIN;
    if start >= data.len() {
        return chunk::pad_chunk_plain(secret, file_hash, index as u32);
    }
    let mut plain = data[start..(start + chunk::V2_CHUNK_PLAIN).min(data.len())].to_vec();
    if pad {
        plain.resize(chunk::V2_CHUNK_PLAIN, 0);
    }
    plain
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

    /// 本物の封じ方（seal_chunk）で v2 のストライプを作り、データを欠いた状態から開き直せる
    ///
    /// build_stripe は「最後以外のオブジェクトはちょうど V2_SHARD_BYTES」を前提にする。
    /// 封じたチャンクの長さがずれると公開が必ず失敗するので、偽のオブジェクトではなく実物で確かめる。
    #[tokio::test]
    async fn v2_sealed_chunks_survive_striping_and_open_again() {
        let mailbox = create_dummy_mailbox();
        let secret = [7u8; 32];
        let size = 17 * chunk::V2_CHUNK_PLAIN + 1234;
        let data: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();

        let mut restored = Vec::new();
        let mut pieces = data.chunks(chunk::V2_CHUNK_PLAIN);
        for (k, m) in chunk::v2_stripe_shapes(chunk::v2_chunk_count(size as u64)).unwrap() {
            let objects: Vec<Vec<u8>> = pieces
                .by_ref()
                .take(k)
                .map(|p| mailbox.seal_chunk(&secret, p).unwrap().1)
                .collect();
            let built = sharding_v2::build_stripe(&objects, m).unwrap();
            // 先頭のデータシャードを欠き、パリティで補う
            let missing = m.min(k);
            let got: Vec<Option<Vec<u8>>> = built
                .shards
                .iter()
                .enumerate()
                .map(|(i, s)| (i >= missing).then(|| s.clone()))
                .collect();
            for object in sharding_v2::restore_stripe(&built.stripe, &got).unwrap() {
                restored.extend(mailbox.decrypt_mailbox_value(&object, &secret).unwrap());
            }
        }
        assert_eq!(restored, data);
    }

    /// 切り上げて置いた形（本物 + 埋め草）が、ストライプに組めて、元のファイルに戻る
    #[tokio::test]
    async fn v2_padded_layout_builds_stripes_and_restores_the_file() {
        use sha2::Digest;
        let mailbox = create_dummy_mailbox();
        let secret = [9u8; 32];
        let size = 4 * chunk::V2_CHUNK_PLAIN + 777; // 5 チャンク → 8 に切り上げ
        let data: Vec<u8> = (0..size).map(|i| (i * 13 % 247) as u8).collect();
        let hash: [u8; 32] = Sha256::digest(&data).into();
        let total = chunk::v2_layout_chunks(5, size as u64, true).unwrap();
        assert_eq!(total, 8);

        let mut restored = Vec::new();
        let mut index = 0;
        let mut all_hashes = Vec::new();
        for (k, m) in chunk::v2_stripe_shapes(total).unwrap() {
            let objects: Vec<Vec<u8>> = (0..k)
                .map(|_| {
                    let plain = v2_chunk_plain(&secret, &data, &hash, index, true);
                    index += 1;
                    mailbox.seal_chunk(&secret, &plain).unwrap().1
                })
                .collect();
            let built = sharding_v2::build_stripe(&objects, m).unwrap();
            all_hashes.extend(built.stripe.shard_hashes[..k].iter().copied());
            let got: Vec<Option<Vec<u8>>> = built.shards.iter().cloned().map(Some).collect();
            for object in sharding_v2::restore_stripe(&built.stripe, &got).unwrap() {
                restored.extend(mailbox.decrypt_mailbox_value(&object, &secret).unwrap());
            }
        }
        assert_eq!(restored.len(), 8 * chunk::V2_CHUNK_PLAIN);
        restored.truncate(size);
        assert_eq!(restored, data, "size で切ると元のファイル");
        let distinct: std::collections::HashSet<_> = all_hashes.iter().collect();
        assert_eq!(distinct.len(), 8, "埋め草も含めて、データシャードのハッシュはすべて別");
    }
}
