//! 索引層 — キーワードで引ける記述子ストア (19.7 / Phase 2-3)
//!
//! 掲示板もファイル検索も、実体は「`H(keyword)` にぶら下がる記述子の集合」で、
//! これが**同じ機構**になる。記述子は本体そのものではなく**ポインタ**（数十バイト）。
//!
//! # push（2-1）との違い
//!
//! 2-1 の公開モードは Hint を流して購読者が拾う **push**。こちらは
//! 「キーワードの索引を引きに行く」**pull**。オフライン中に公開されたものや
//! 24h backlog を超えたものも、索引を引けば発見できる。
//!
//! # 保持者に中身を見せない
//!
//! 索引の位置 `H(index_key ‖ K_pub)` はキーワードを知る者だけが計算できるが、
//! 保持者自身は記述子を **K_pub で暗号化された状態** でしか持たない
//! （ファイル名やポインタを平文で抱えさせない）。キーワードを知る検索者だけが復号できる。

use crate::error::{AetherError, Result};
use crate::crypto::cipher;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 索引に載る記述子（平文）。公開者・検索者が扱う形
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexDescriptor {
    /// 本体への参照。
    ///
    /// - `chunked = false`（単一 body）: `content_ref` は **nonce**。
    ///   検索者は `SHA256(content_ref)` で mailbox_key を出して本体を取りに行く。
    /// - `chunked = true`（大容量 / 2-4）: `content_ref` は **Manifest の mailbox_key**。
    ///   Manifest を取り、そこに並ぶ各チャンクを content-address で取りに行く。
    pub content_ref: [u8; 32],
    /// 表示名（ファイル名 / スレッド見出し）
    pub name: String,
    /// 本体サイズ（バイト、目安）
    pub size: u64,
    /// 投稿時刻 (UNIX秒)
    pub timestamp: u64,
    /// `content_ref` が Manifest を指す（チャンク化された大容量コンテンツ）か
    #[serde(default)]
    pub chunked: bool,
    /// スレッド DAG の親投稿（掲示板 / 2-5）。
    ///
    /// 空なら新規スレッド（根）。1 つ以上の親（= 親投稿の `content_ref`）を参照すると
    /// DAG を成す。木ではなく DAG なのは、同時に書かれた複数の先端（tips）を
    /// 後続がまとめられる（分岐が収束する）ため。全ノードが同じ DAG から
    /// **決定論的なトポロジカル順序**で同じ並びを再現する（[`crate::mailbox::board`]）。
    /// 保持者は K_pub 封じの中しか見えないので、スレッド構造も割れない。
    #[serde(default)]
    pub parents: Vec<[u8; 32]>,
}

/// ネットワーク上に保存・転送される索引レコード
///
/// 保持者はこれを **不透明なまま** 持つ。復号にはキーワード鍵 `K_pub` が要る。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexRecord {
    /// スパム対策の PoW（2-7 でランクにも使う）
    pub pow_nonce: u64,
    /// 暗号化 nonce
    pub nonce: [u8; 12],
    /// `K_pub` 由来鍵で暗号化した [`IndexDescriptor`]
    pub ciphertext: Vec<u8>,
}

/// 索引の配置キーを導出する
///
/// これと `K_pub` を [`RelayDirectory::mailbox_targets`] に渡すと担当保持者が出る。
pub fn index_key(k_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"aether_index_key_v1");
    h.update(k_pub);
    h.finalize().into()
}

fn record_key(k_pub: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, k_pub);
    let mut okm = [0u8; 32];
    hk.expand(b"aether_index_v1", &mut okm)
        .expect("HKDF expand");
    okm
}

impl IndexRecord {
    /// 記述子を `K_pub` で封じて保存レコードにする（PoW 付き）
    pub fn create(
        k_pub: &[u8; 32],
        descriptor: &IndexDescriptor,
        pow_difficulty: u32,
    ) -> Result<Self> {
        let plain = bincode::serialize(descriptor)
            .map_err(|e| AetherError::Serialization(e.to_string()))?;
        let (ciphertext, nonce) = cipher::encrypt(&record_key(k_pub), &plain)?;

        let mut record = Self {
            pow_nonce: 0,
            nonce,
            ciphertext,
        };
        record.pow_nonce = crate::crypto::pow::hint::solve(&record.id(), pow_difficulty)?;
        Ok(record)
    }

    /// 重複排除・PoW 束縛用の識別子（pow_nonce は除外）
    pub fn id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"aether_index_rec_v1");
        h.update(self.nonce);
        h.update(&self.ciphertext);
        h.finalize().into()
    }

    pub fn verify_pow(&self, difficulty: u32) -> bool {
        crate::crypto::pow::hint::verify(&self.id(), self.pow_nonce, difficulty)
    }

    /// この記録の PoW が実際に達成した難易度（先頭ゼロビット数）。ランク付けに使う (2-7)
    ///
    /// **記述子ではなく PoW から計算する**ので、公開者が weight を偽れない。
    pub fn pow_bits(&self) -> u32 {
        crate::crypto::pow::hint::achieved_bits(&self.id(), self.pow_nonce)
    }

    /// `K_pub` で開いて記述子を取り出す。鍵が違えば `None`
    pub fn open(&self, k_pub: &[u8; 32]) -> Option<IndexDescriptor> {
        let plain = cipher::decrypt(&record_key(k_pub), &self.nonce, &self.ciphertext).ok()?;
        bincode::deserialize(&plain).ok()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| AetherError::Serialization(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| AetherError::Protocol(format!("Invalid IndexRecord: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(name: &str) -> IndexDescriptor {
        IndexDescriptor {
            content_ref: [0xAB; 32],
            name: name.into(),
            size: 1234,
            timestamp: 1_700_000_000,
            chunked: false,
            parents: Vec::new(),
        }
    }

    #[test]
    fn seals_and_opens_with_the_keyword_key() {
        let k = [0x5A; 32];
        let rec = IndexRecord::create(&k, &descriptor("movie.mkv"), 0).unwrap();

        let got = rec.open(&k).expect("同じ鍵なら開ける");
        assert_eq!(got, descriptor("movie.mkv"));
    }

    #[test]
    fn a_different_keyword_cannot_open_it() {
        let rec = IndexRecord::create(&[0x5A; 32], &descriptor("x"), 0).unwrap();
        assert!(rec.open(&[0xEE; 32]).is_none(), "別キーワードでは開けない");
    }

    #[test]
    fn holder_sees_only_ciphertext_not_the_name() {
        // 保持者が持つバイト列に、平文のファイル名が現れてはならない
        let rec = IndexRecord::create(&[0x5A; 32], &descriptor("secret-file-name"), 0).unwrap();
        let wire = rec.encode().unwrap();
        assert!(
            !wire.windows(16).any(|w| w == b"secret-file-name"),
            "記述子は暗号化されて保存される"
        );
    }

    #[test]
    fn pow_binds_to_the_record() {
        let mut rec = IndexRecord::create(&[1; 32], &descriptor("a"), 8).unwrap();
        assert!(rec.verify_pow(8));

        rec.pow_nonce = rec.pow_nonce.wrapping_add(1);
        assert!(!rec.verify_pow(8), "改竄した pow_nonce は通らない");
    }

    #[test]
    fn index_key_is_deterministic_per_keyword() {
        let k = [7u8; 32];
        assert_eq!(index_key(&k), index_key(&k));
        assert_ne!(index_key(&k), index_key(&[8u8; 32]));
    }
}
