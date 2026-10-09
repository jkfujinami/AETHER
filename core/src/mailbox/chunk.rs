//! 大容量コンテンツのチャンク化と content-addressing (Phase 2-4)
//!
//! 単一 body の RS 分割は 1 オブジェクト ~3MB が上限（5 シャード × 1MB / 3 データ）。
//! それを超えるファイルは [`CHUNK_SIZE`] ごとに割り、各チャンクを独立した
//! **content-addressed** オブジェクトとして配置する。[`Manifest`] がチャンク参照を束ねる。
//!
//! # content-addressing と重複排除
//!
//! チャンクは**収束的暗号化**する ── nonce = `H(secret ‖ 平文チャンク)`。
//! 同じ秘密（公開なら `K_pub`）と同じ平文なら暗号文が一致するので、
//! `chunk_ref = H(暗号文)` が一致し、リング上の同じ位置（`H(chunk_ref ‖ K)`）に落ちる。
//!
//! → **同一ファイルを複数人が公開しても重複排除され、複数保持者から並列取得（swarm）できる。**
//!   Winny の「人気なファイルほど速く・落ちにくい」がそのまま出る。
//!
//! 収束暗号は「平文を推測できれば存在を確認できる」弱点を持つが、
//! **チャンク化は公開コンテンツ専用**なので無害（そもそも公開で発見可能にしている）。
//! 私信は単一 body のまま（メッセージは小さくチャンク化不要）。

use crate::error::{AetherError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// チャンク 1 つの大きさ (256KB)
///
/// 転送サイズがそのまま指紋になるため、常にこの単位へ正規化する。
/// 256KB に対する 3-Hop Onion のオーバーヘッドは +0.08% で償却される。
pub const CHUNK_SIZE: usize = 256 * 1024;

/// これ以下なら単一 body で置ける（チャンク化不要）
///
/// 単一 body は RS 3+2・各シャード <= 1MB なので理論上 ~3MB まで置けるが、
/// 判定を単純にするため 1 チャンク分を境界にする。
pub const SINGLE_BODY_LIMIT: usize = CHUNK_SIZE;

/// 1 つの [`Manifest`] が束ねられるチャンク数の上限
///
/// Manifest 自体も 1 オブジェクトとして置くので、その本体が収まる必要がある。
/// 32B × 65536 = 2MB。CHUNK_SIZE と掛けて最大 ~16GB のファイルを 1 Manifest で扱える。
/// これを超えるファイルは Manifest の木構造（将来）が要る。
pub const MAX_CHUNKS_PER_MANIFEST: usize = 65536;

/// ファイルのチャンク構成表
///
/// これ自体が 1 つの content-addressed オブジェクトとして配置され、
/// その参照（= 索引の `content_ref`）を辿ると本体を復元できる。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// 表示名（ファイル名）
    pub name: String,
    /// 復元後の全体サイズ（バイト）
    pub size: u64,
    /// 各チャンクの content-address（= そのチャンクの mailbox_key）。
    /// **並び順が本体の連結順**。
    pub chunk_refs: Vec<[u8; 32]>,
}

impl Manifest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| AetherError::Serialization(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let m: Self = bincode::deserialize(bytes)
            .map_err(|e| AetherError::Protocol(format!("Invalid Manifest: {}", e)))?;
        if m.chunk_refs.len() > MAX_CHUNKS_PER_MANIFEST {
            return Err(AetherError::Protocol(format!(
                "Manifest too large: {} chunks (max {})",
                m.chunk_refs.len(),
                MAX_CHUNKS_PER_MANIFEST
            )));
        }
        Ok(m)
    }
}

/// v2 のシャード 1 枚の大きさ（バイト）。データもパリティも同じ長さ
///
/// **`chunk::tests::v2_shard_bytes_fills_the_256k_onion_bucket` で決めた値。**
/// 保持者へ `send_onion_message_typed(MailboxPut, [put_key 32][シャード], 宛先)` で送るとき、
/// 出口に届く本文は `[内側の種別 1][宛先 SocketAddr（bincode。IPv6 で 22）][PacketType 1][put_key 32][シャード]`
/// で、onion はこれに長さ 4 バイトを前置して `padded_len` で切り上げる。
/// その結果がちょうど 262,144（256KiB のバケット）に収まる最大のシャードが
/// `262_144 − 4 − 1 − 22 − 1 − 32 = 262_084`。1 バイト増やすと 524,288 に跳ねて倍になる。
/// 宛先が IPv4（bincode で 10）なら 12 バイト短くなるが、同じバケットに切り上がるので長さは変わらない。
pub const V2_SHARD_BYTES: usize = 262_084;

/// 収束暗号のオブジェクトの付加分: nonce 12 + 認証タグ 16
pub const V2_SEAL_OVERHEAD: usize = 12 + 16;

/// v2 のチャンクの平文の大きさ（最後以外）。シャードに収まる暗号文から nonce・タグを引いた分
pub const V2_CHUNK_PLAIN: usize = V2_SHARD_BYTES - V2_SEAL_OVERHEAD;

/// [`ManifestV2`] の版番号
pub const MANIFEST_V2_VERSION: u8 = 2;

/// [`StripeV2`] 1 つの bincode での固定部分: data 1 + parity 1 + last_object_len 4 + ハッシュ列の長さ 8
const STRIPE_V2_FIXED: usize = 1 + 1 + 4 + 8;

/// 1 つの [`ManifestV2`] が持てるストライプ数の上限
///
/// Manifest 自体も 1 オブジェクトとして置く（暗号化後に [`SINGLE_BODY_LIMIT`] 以内）ので、
/// ストライプ 1 つが最低でもハッシュ 1 個分（固定部分 + 32）かかるとして割った値。受信側の肥大対策。
pub const MAX_STRIPES_PER_MANIFEST_V2: usize = SINGLE_BODY_LIMIT / (STRIPE_V2_FIXED + 32);

/// シャードのハッシュ。Manifest v2 の `shard_hashes` と、同時に置き場所（担当の計算）の入力になる
pub fn shard_hash(shard: &[u8]) -> [u8; 32] {
    Sha256::digest(shard).into()
}

/// v2 のストライプ 1 つ（連続するデータシャード k 個 + パリティ m 個）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeV2 {
    /// このストライプのデータシャード数 k
    pub data: u8,
    /// パリティシャード数 m
    pub parity: u8,
    /// 最後のデータシャードの、埋める前のオブジェクト長（他のデータシャードは [`V2_SHARD_BYTES`]）
    pub last_object_len: u32,
    /// データ k 個 → パリティ m 個の順の、シャードの SHA-256
    pub shard_hashes: Vec<[u8; 32]>,
}

impl StripeV2 {
    /// 受け取ったシャードのうち、ハッシュが合うものだけを残す（`None` のままか、偽物なら `None`）
    ///
    /// 板の読者なら誰でも偽のシャードを作れるので、使う前に必ず通す。
    /// 戻り値は [`crate::mailbox::sharding_v2::decode_stripe`] にそのまま渡せる並び。
    pub fn keep_verified(&self, got: &[Option<Vec<u8>>]) -> Vec<Option<Vec<u8>>> {
        self.shard_hashes
            .iter()
            .enumerate()
            .map(|(i, want)| {
                got.get(i)
                    .and_then(|s| s.as_ref())
                    .filter(|s| s.len() == V2_SHARD_BYTES && shard_hash(s) == *want)
                    .cloned()
            })
            .collect()
    }
}

/// v2 のファイルのチャンク構成表（Part 23 の 7 章）
///
/// v1 の [`Manifest`] とは別の形で、**互換は無い**（v1 のファイルは v2 の読み手が読まない）。
/// 置き方は v1 の Manifest と同じ（小さなものの経路）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestV2 {
    /// 常に [`MANIFEST_V2_VERSION`]
    pub version: u8,
    /// 表示名（ファイル名）
    pub name: String,
    /// ファイルの平文の大きさ
    pub size: u64,
    /// チャンクの平文の大きさ（最後のチャンク以外）
    pub chunk_plain: u32,
    pub stripes: Vec<StripeV2>,
}

impl ManifestV2 {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| AetherError::Serialization(e.to_string()))
    }

    /// 復号して形を検べる。受信側の増幅・肥大と、後段の添字あふれを防ぐ
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let m: Self = bincode::deserialize(bytes)
            .map_err(|e| AetherError::Protocol(format!("Invalid ManifestV2: {}", e)))?;
        if m.version != MANIFEST_V2_VERSION {
            return Err(AetherError::Protocol(format!(
                "ManifestV2 version {} is not supported",
                m.version
            )));
        }
        if m.stripes.len() > MAX_STRIPES_PER_MANIFEST_V2 {
            return Err(AetherError::Protocol(format!(
                "ManifestV2 too large: {} stripes (max {})",
                m.stripes.len(),
                MAX_STRIPES_PER_MANIFEST_V2
            )));
        }
        if m.chunk_plain as usize != V2_CHUNK_PLAIN {
            return Err(AetherError::Protocol("ManifestV2 chunk size mismatch".into()));
        }
        for s in &m.stripes {
            let total = s.data as usize + s.parity as usize;
            if s.data == 0
                || s.parity == 0
                || total > crate::mailbox::sharding_v2::MAX_TOTAL_SHARDS
                || s.shard_hashes.len() != total
            {
                return Err(AetherError::Protocol("ManifestV2 stripe shape is invalid".into()));
            }
            let last = s.last_object_len as usize;
            if last <= V2_SEAL_OVERHEAD || last > V2_SHARD_BYTES {
                return Err(AetherError::Protocol("ManifestV2 last_object_len is out of range".into()));
            }
        }
        Ok(m)
    }
}

/// このサイズはチャンク化が要るか
pub fn needs_chunking(size: usize) -> bool {
    size > SINGLE_BODY_LIMIT
}

/// 平文を [`CHUNK_SIZE`] ごとに切る
pub fn split(data: &[u8]) -> Vec<&[u8]> {
    if data.is_empty() {
        return Vec::new();
    }
    data.chunks(CHUNK_SIZE).collect()
}

/// 収束的 nonce ── 同じ `(secret, 平文)` から必ず同じ nonce を出す
///
/// 異なる平文からは（高確率で）異なる nonce になるので、ChaCha20 の
/// **nonce 再利用は起きない**。同一平文で一致するのが重複排除の要。
pub fn convergent_nonce(secret: &[u8; 32], plaintext: &[u8]) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(b"aether_chunk_nonce_v1");
    h.update(secret);
    h.update(plaintext);
    let digest = h.finalize();
    digest[..12].try_into().expect("12 <= 32")
}

/// 格納オブジェクト（`[nonce(12)][ciphertext]`）から content-address を出す
///
/// これがチャンク／Manifest の `mailbox_key` になる。同一内容 → 同一位置。
pub fn content_address(stored_object: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"aether_chunk_id_v1");
    h.update(stored_object);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_covers_all_bytes_in_order() {
        let data: Vec<u8> = (0..(CHUNK_SIZE * 2 + 123)).map(|i| i as u8).collect();
        let chunks = split(&data);
        assert_eq!(chunks.len(), 3, "2 チャンク + 端数で 3 つ");
        assert_eq!(chunks[0].len(), CHUNK_SIZE);
        assert_eq!(chunks[1].len(), CHUNK_SIZE);
        assert_eq!(chunks[2].len(), 123);

        let rejoined: Vec<u8> = chunks.concat();
        assert_eq!(rejoined, data, "連結で元に戻る");
    }

    #[test]
    fn empty_data_has_no_chunks() {
        assert!(split(&[]).is_empty());
    }

    #[test]
    fn convergent_nonce_is_deterministic() {
        let secret = [7u8; 32];
        let plain = b"the same content";
        assert_eq!(
            convergent_nonce(&secret, plain),
            convergent_nonce(&secret, plain),
            "同一 (secret, 平文) は同一 nonce"
        );
    }

    #[test]
    fn convergent_nonce_diverges_on_content_and_secret() {
        assert_ne!(
            convergent_nonce(&[1u8; 32], b"a"),
            convergent_nonce(&[1u8; 32], b"b"),
            "別の平文は別の nonce（nonce 再利用を避ける）"
        );
        assert_ne!(
            convergent_nonce(&[1u8; 32], b"a"),
            convergent_nonce(&[2u8; 32], b"a"),
            "別の秘密は別の nonce"
        );
    }

    #[test]
    fn content_address_is_stable_and_content_bound() {
        let object = b"[nonce][ciphertext]";
        assert_eq!(content_address(object), content_address(object));
        assert_ne!(content_address(object), content_address(b"different"));
    }

    #[test]
    fn manifest_survives_wire_roundtrip() {
        let m = Manifest {
            name: "cool.mkv".into(),
            size: 700 * 1024,
            chunk_refs: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        };
        let decoded = Manifest::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(decoded, m);
    }

    #[test]
    fn oversized_manifest_is_rejected() {
        let m = Manifest {
            name: "huge".into(),
            size: u64::MAX,
            chunk_refs: vec![[0u8; 32]; MAX_CHUNKS_PER_MANIFEST + 1],
        };
        // encode は通るが decode で弾く（受信側の増幅・肥大対策）
        let bytes = bincode::serialize(&m).unwrap();
        assert!(Manifest::decode(&bytes).is_err());
    }

    fn sample_stripe(k: u8, m: u8) -> StripeV2 {
        StripeV2 {
            data: k,
            parity: m,
            last_object_len: 1000,
            shard_hashes: (0..(k + m)).map(|i| [i; 32]).collect(),
        }
    }

    fn sample_v2() -> ManifestV2 {
        ManifestV2 {
            version: MANIFEST_V2_VERSION,
            name: "big.iso".into(),
            size: 5_000_000,
            chunk_plain: V2_CHUNK_PLAIN as u32,
            stripes: vec![sample_stripe(16, 27), sample_stripe(3, 1)],
        }
    }

    #[test]
    fn manifest_v2_survives_wire_roundtrip() {
        let m = sample_v2();
        assert_eq!(ManifestV2::decode(&m.encode().unwrap()).unwrap(), m);
    }

    #[test]
    fn manifest_v2_rejects_malformed_shapes() {
        let bad = |f: &dyn Fn(&mut ManifestV2)| {
            let mut m = sample_v2();
            f(&mut m);
            assert!(ManifestV2::decode(&m.encode().unwrap()).is_err());
        };
        bad(&|m| m.version = 1);
        bad(&|m| m.chunk_plain += 1);
        bad(&|m| {
            m.stripes[0].shard_hashes.pop();
        });
        bad(&|m| m.stripes[0].data = 0);
        bad(&|m| m.stripes[0].parity = 0);
        bad(&|m| m.stripes[0].last_object_len = V2_SHARD_BYTES as u32 + 1);
        bad(&|m| m.stripes[0].last_object_len = 0);
        // v1 の Manifest のバイト列は v2 として読めない（互換を切る）
        let v1 = Manifest { name: "x".into(), size: 1, chunk_refs: vec![[0u8; 32]] };
        assert!(ManifestV2::decode(&v1.encode().unwrap()).is_err());
    }

    #[test]
    fn oversized_manifest_v2_is_rejected() {
        let mut m = sample_v2();
        m.stripes = vec![sample_stripe(1, 1); MAX_STRIPES_PER_MANIFEST_V2 + 1];
        assert!(ManifestV2::decode(&m.encode().unwrap()).is_err());
    }

    #[test]
    fn counterfeit_shards_are_dropped_and_the_stripe_still_decodes() {
        use crate::mailbox::sharding_v2::{decode_stripe, encode_stripe};
        let k = 4;
        let m = 2;
        let data: Vec<Vec<u8>> = (0..k)
            .map(|i| (0..V2_SHARD_BYTES).map(|j| (i * 13 + j) as u8).collect())
            .collect();
        let mut all = data.clone();
        all.extend(encode_stripe(&data, m).unwrap());
        let stripe = StripeV2 {
            data: k as u8,
            parity: m as u8,
            last_object_len: V2_SHARD_BYTES as u32,
            shard_hashes: all.iter().map(|s| shard_hash(s)).collect(),
        };
        // データ 1 枚を偽物にすり替え、もう 1 枚は短い偽物にし、パリティは正しいまま
        let mut got: Vec<Option<Vec<u8>>> = all.iter().cloned().map(Some).collect();
        got[0].as_mut().unwrap()[5] ^= 1;
        got[1] = Some(vec![0u8; 10]);
        let verified = stripe.keep_verified(&got);
        assert!(verified[0].is_none() && verified[1].is_none(), "偽物は捨てる");
        assert!(verified[2..].iter().all(|s| s.is_some()));
        assert_eq!(decode_stripe(k, m, &verified).unwrap(), data);
        // 偽物を捨てた結果 k 枚に満たなければ復元しない
        got[2] = None;
        assert!(decode_stripe(k, m, &stripe.keep_verified(&got)).is_err());
    }

    /// 保持者へ送る 1 件を、実際の onion の組み立てで包んだときの切り上げ後の本文の大きさ
    ///
    /// `RelayClient::send_onion_message_typed(MailboxPut, [put_key][シャード], dest)` と同じ
    /// `build_typed_forward` → `OnionCircuit::wrap_packet` を通し、パケット長から逆算する。
    /// パケット = `HEADER_LEN` + 切り上げた本文 + AEAD タグ 16。
    fn onion_bucket_for_shard(shard_len: usize, dest: std::net::SocketAddr) -> usize {
        use crate::net::onion::{OnionCircuit, HEADER_LEN};
        use crate::protocol::wire::{self, PacketType};
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut circuit = OnionCircuit::new();
        for i in 0..3u8 {
            let s = StaticSecret::random_from_rng(rand::rngs::OsRng);
            let addr: std::net::SocketAddr = format!("10.0.0.{}:9000", i + 1).parse().unwrap();
            circuit.add_hop(addr, PublicKey::from(&s).to_bytes()).unwrap();
        }
        // send_onion_message_typed と同じ組み立て: [PacketType 1][message] を TypedForward で包む
        let mut message = vec![0u8; 32];
        message.extend(vec![0xAB; shard_len]);
        let mut body = vec![PacketType::MailboxPut as u8];
        body.extend_from_slice(&message);
        let inner = wire::build_typed_forward(dest, &body).unwrap();
        let packet = circuit.wrap_packet(&inner).unwrap();
        packet.len() - HEADER_LEN - 16
    }

    #[test]
    fn v2_shard_bytes_fills_the_256k_onion_bucket() {
        use crate::net::onion::padded_len;
        let v6: std::net::SocketAddr = "[2001:db8::1]:9443".parse().unwrap();
        let v4: std::net::SocketAddr = "192.0.2.1:9443".parse().unwrap();

        // 組み立てた本文の長さを数式でも出し、実際のパケット長と一致することを確かめる
        let inner_len = |dest: &std::net::SocketAddr| 1 + bincode::serialize(dest).unwrap().len() + 1 + 32;
        assert_eq!(bincode::serialize(&v6).unwrap().len(), 22);
        assert_eq!(bincode::serialize(&v4).unwrap().len(), 10);

        // 最悪の宛先（IPv6）で、ちょうど 262,144 に収まる最大
        let body_v6 = 4 + inner_len(&v6) + V2_SHARD_BYTES;
        assert_eq!(padded_len(body_v6), 262_144, "IPv6 宛先でちょうど 256KiB");
        assert_eq!(padded_len(body_v6 + 1), 524_288, "1 バイト増やすと倍のバケットに跳ねる");
        assert_eq!(body_v6, 262_144, "IPv6 では隙間が無い");

        // 実際の onion パケットの長さからも確かめる（数式の転記ミスを防ぐ）
        assert_eq!(onion_bucket_for_shard(V2_SHARD_BYTES, v6), 262_144);
        assert_eq!(onion_bucket_for_shard(V2_SHARD_BYTES + 1, v6), 524_288);
        // IPv4 宛先でも同じバケット（長さで宛先の種類は見えない）
        assert_eq!(onion_bucket_for_shard(V2_SHARD_BYTES, v4), 262_144);

        // 保持者の 1 件の上限（MAX_ENTRY_BYTES = 1MiB）に収まる
        const { assert!(32 + V2_SHARD_BYTES <= 1024 * 1024) };
        // 収束暗号のオブジェクト（nonce 12 + 暗号文 + タグ 16）がシャードにちょうど入る
        assert_eq!(V2_CHUNK_PLAIN + V2_SEAL_OVERHEAD, V2_SHARD_BYTES);
    }

    #[test]
    fn needs_chunking_boundary() {
        assert!(!needs_chunking(SINGLE_BODY_LIMIT));
        assert!(needs_chunking(SINGLE_BODY_LIMIT + 1));
    }
}
