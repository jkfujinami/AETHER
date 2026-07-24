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

    #[test]
    fn needs_chunking_boundary() {
        assert!(!needs_chunking(SINGLE_BODY_LIMIT));
        assert!(needs_chunking(SINGLE_BODY_LIMIT + 1));
    }
}
