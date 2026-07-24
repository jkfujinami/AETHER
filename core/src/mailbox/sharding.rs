//! Reed-Solomon による分割・復元 (設計書 Part 5.2 / 18.3-D / 18.5.4)
//!
//! # 3つの役割を同時に果たす
//!
//! 1. **可用性** — 5個中3個あれば復元できる。保持者が2台落ちても失われない。
//!    Winny の「キャッシュが消えて落ちきらない」問題への耐性。
//! 2. **否認可能性** — どの保持者も**ファイル全体を持たない**。
//! 3. **Sybil / 検閲耐性** — 各シャードは
//!    `H(mailbox_key ‖ K ‖ i)` で**リング上の別々の場所**に置かれる (18.5.4)。
//!    攻撃者が1つの弧を支配しても取れるシャードは1個で復元できず、
//!    検閲するには離れた3箇所を同時に押さえる必要がある。
//!
//! # 速度への寄与
//!
//! 3シャードを3ノードから**並列取得**できる。
//! 3ホップ鎖のスループットは min(各ホップ) に落ちるため、
//! 単一ソースだと遅いノードを踏んだ時点で終わる。
//! 5レプリカから最速を選べる並列取得が、実効速度の主要因になる。

use crate::error::{AetherError, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::{Digest, Sha256};

/// データシャード数（復元に必要な個数）
pub const DATA_SHARDS: usize = 3;

/// パリティシャード数（欠損許容数）
pub const PARITY_SHARDS: usize = 2;

/// 総シャード数
pub const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;

/// シャードのワイヤ形式ヘッダ長: `[index(1)][original_len(4)]`
const SHARD_HEADER: usize = 5;

/// シャード認証タグ長
///
/// 16 バイト = 偽造成功確率 2^-128。5シャードで +80 バイト。
pub const SHARD_TAG_LEN: usize = 16;

/// 1つのシャード
#[derive(Debug, Clone, PartialEq)]
pub struct Shard {
    pub index: u8,
    /// 分割前の全体長。パディングを剥がすのに必要
    pub original_len: u32,
    pub data: Vec<u8>,
}

impl Shard {
    /// ワイヤ形式へ: `[index(1)][original_len(4 BE)][data]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SHARD_HEADER + self.data.len());
        buf.push(self.index);
        buf.extend_from_slice(&self.original_len.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SHARD_HEADER {
            return Err(AetherError::Protocol("Shard too short".into()));
        }

        let index = bytes[0];
        if index as usize >= TOTAL_SHARDS {
            return Err(AetherError::Protocol(format!(
                "Shard index {} out of range (total {})",
                index, TOTAL_SHARDS
            )));
        }

        let original_len = u32::from_be_bytes(bytes[1..5].try_into().expect("長さ確認済み"));

        Ok(Self {
            index,
            original_len,
            data: bytes[SHARD_HEADER..].to_vec(),
        })
    }
}

/// シャード `i` の保存キー
///
/// 位置は `ring::position_of_shard` が決めるが、
/// Mailbox 上のキーは別途必要（同じノードが複数シャードを持つことがある）。
pub fn shard_key(mailbox_key: &[u8; 32], index: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aether_shard_key_v1");
    hasher.update(mailbox_key);
    hasher.update([index]);
    hasher.finalize().into()
}

/// シャードを封をして保存形式にする
///
/// 形式: `[index(1)][original_len(4)][data][tag(16)]`
///
/// # なぜタグが要るか
///
/// 保持者は共有秘密を持たないので中身は読めないが、**書き換えは自由**にできる。
/// index と長さは平文で見えているため、正しい形をした偽シャードを返せる。
///
/// 認証が無いと、K レプリカのうち **1台が悪意を持つだけで復元が止まる**。
/// Reed-Solomon は誤り訂正符号ではなく消失訂正符号なので、
/// 「壊れたシャード」を見分けられず、混ぜた時点で復元結果が丸ごと壊れる。
/// AEAD は最後に落ちるが、その時点でどのシャードが原因かは分からない。
///
/// タグは `mailbox_key` も含めて計算するので、
/// **別メッセージのシャードが混ざることも防げる**。
pub fn seal(shard: &Shard, mailbox_key: &[u8; 32], mac_key: &[u8; 32]) -> Vec<u8> {
    let mut buf = shard.to_bytes();
    let tag = shard_tag(mailbox_key, mac_key, &buf);
    buf.extend_from_slice(&tag);
    buf
}

/// 封を検めてシャードを取り出す
///
/// タグが合わなければ `None`。偽造・別メッセージ・破損のいずれか。
pub fn open(bytes: &[u8], mailbox_key: &[u8; 32], mac_key: &[u8; 32]) -> Option<Shard> {
    if bytes.len() < SHARD_HEADER + SHARD_TAG_LEN {
        return None;
    }

    let (body, tag) = bytes.split_at(bytes.len() - SHARD_TAG_LEN);
    let expected = shard_tag(mailbox_key, mac_key, body);

    // 定数時間比較。バイト単位で早期 return すると
    // タグを1バイトずつ詰めるオラクルになる
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&expected[..], tag)) {
        return None;
    }

    Shard::from_bytes(body).ok()
}

fn shard_tag(mailbox_key: &[u8; 32], mac_key: &[u8; 32], body: &[u8]) -> [u8; SHARD_TAG_LEN] {
    use hmac::{Hmac, Mac};

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("HMAC accepts any length");
    mac.update(b"aether_shard_mac_v1");
    mac.update(mailbox_key);
    mac.update(body);

    mac.finalize().into_bytes()[..SHARD_TAG_LEN]
        .try_into()
        .expect("SHARD_TAG_LEN <= 32")
}

fn codec() -> Result<ReedSolomon> {
    ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
        .map_err(|e| AetherError::Protocol(format!("Reed-Solomon init failed: {}", e)))
}

/// データを 3+2 に分割する
pub fn encode(data: &[u8]) -> Result<Vec<Shard>> {
    if data.is_empty() {
        return Err(AetherError::Protocol("Cannot shard empty data".into()));
    }
    if data.len() > u32::MAX as usize {
        return Err(AetherError::Protocol("Data too large to shard".into()));
    }

    let original_len = data.len() as u32;
    // 全シャードが同じ長さでなければならないのでパディングする
    let shard_len = data.len().div_ceil(DATA_SHARDS);

    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(TOTAL_SHARDS);
    for i in 0..DATA_SHARDS {
        let start = i * shard_len;
        let end = ((i + 1) * shard_len).min(data.len());

        let mut shard = vec![0u8; shard_len];
        if start < data.len() {
            shard[..end - start].copy_from_slice(&data[start..end]);
        }
        shards.push(shard);
    }
    for _ in 0..PARITY_SHARDS {
        shards.push(vec![0u8; shard_len]);
    }

    codec()?
        .encode(&mut shards)
        .map_err(|e| AetherError::Protocol(format!("Reed-Solomon encode failed: {}", e)))?;

    Ok(shards
        .into_iter()
        .enumerate()
        .map(|(index, data)| Shard {
            index: index as u8,
            original_len,
            data,
        })
        .collect())
}

/// 集まったシャードから復元する
///
/// [`DATA_SHARDS`] 個以上あれば、どの組み合わせでも復元できる。
pub fn decode(available: &[Shard]) -> Result<Vec<u8>> {
    if available.len() < DATA_SHARDS {
        return Err(AetherError::Protocol(format!(
            "Need at least {} shards to reconstruct, got {}",
            DATA_SHARDS,
            available.len()
        )));
    }

    let original_len = available[0].original_len as usize;
    let shard_len = available[0].data.len();

    // 混在した別オブジェクトのシャードを掴むと静かに壊れたデータを返してしまう
    if available
        .iter()
        .any(|s| s.original_len as usize != original_len || s.data.len() != shard_len)
    {
        return Err(AetherError::Protocol(
            "Shards disagree on original length or shard size".into(),
        ));
    }

    let mut slots: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
    for shard in available {
        slots[shard.index as usize] = Some(shard.data.clone());
    }

    codec()?
        .reconstruct(&mut slots)
        .map_err(|e| AetherError::Protocol(format!("Reed-Solomon reconstruct failed: {}", e)))?;

    let mut out = Vec::with_capacity(shard_len * DATA_SHARDS);
    for slot in slots.iter().take(DATA_SHARDS) {
        out.extend_from_slice(slot.as_ref().expect("reconstruct 済み"));
    }

    out.truncate(original_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn produces_the_expected_shard_count() {
        let shards = encode(&sample(1000)).unwrap();
        assert_eq!(shards.len(), TOTAL_SHARDS);

        // 全シャードが同じ長さ（Reed-Solomon の要件）
        let len = shards[0].data.len();
        assert!(shards.iter().all(|s| s.data.len() == len));
    }

    #[test]
    fn roundtrip_with_all_shards() {
        let data = sample(1000);
        let shards = encode(&data).unwrap();
        assert_eq!(decode(&shards).unwrap(), data);
    }

    #[test]
    fn any_three_of_five_reconstructs() {
        // ここが本質。どの3個の組み合わせでも復元できなければ
        // 「2台落ちても平気」も「1つの弧を支配されても平気」も成立しない
        let data = sample(1000);
        let shards = encode(&data).unwrap();

        let mut combinations = 0;
        for a in 0..TOTAL_SHARDS {
            for b in (a + 1)..TOTAL_SHARDS {
                for c in (b + 1)..TOTAL_SHARDS {
                    let subset = vec![shards[a].clone(), shards[b].clone(), shards[c].clone()];
                    assert_eq!(
                        decode(&subset).unwrap(),
                        data,
                        "シャード {},{},{} から復元できない",
                        a,
                        b,
                        c
                    );
                    combinations += 1;
                }
            }
        }
        assert_eq!(combinations, 10, "C(5,3) = 10 通り全てを検査するはず");
    }

    #[test]
    fn two_shards_are_not_enough() {
        let shards = encode(&sample(1000)).unwrap();
        let subset = vec![shards[0].clone(), shards[1].clone()];

        assert!(
            decode(&subset).is_err(),
            "3個未満で復元できてしまうと冗長度の前提が崩れる"
        );
    }

    #[test]
    fn handles_sizes_not_divisible_by_three() {
        // パディングの剥がし忘れがあるとここで壊れる
        for len in [1usize, 2, 3, 4, 5, 7, 100, 1001, 65_537] {
            let data = sample(len);
            let shards = encode(&data).unwrap();
            let subset = vec![shards[1].clone(), shards[3].clone(), shards[4].clone()];

            assert_eq!(decode(&subset).unwrap(), data, "長さ {} で復元に失敗", len);
        }
    }

    #[test]
    fn rejects_empty_input() {
        assert!(encode(&[]).is_err());
    }

    #[test]
    fn shard_survives_wire_roundtrip() {
        let shards = encode(&sample(500)).unwrap();
        for shard in &shards {
            let restored = Shard::from_bytes(&shard.to_bytes()).unwrap();
            assert_eq!(&restored, shard);
        }
    }

    #[test]
    fn rejects_out_of_range_index() {
        let mut bytes = encode(&sample(100)).unwrap()[0].to_bytes();
        bytes[0] = TOTAL_SHARDS as u8;
        assert!(Shard::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_mismatched_shards() {
        // 別オブジェクトのシャードが混ざると、黙って壊れたデータを返しかねない
        let a = encode(&sample(1000)).unwrap();
        let b = encode(&sample(2000)).unwrap();

        let mixed = vec![a[0].clone(), a[1].clone(), b[2].clone()];
        assert!(decode(&mixed).is_err());
    }

    #[test]
    fn shard_keys_are_distinct_per_index() {
        let mailbox_key = [0x42u8; 32];
        let keys: Vec<_> = (0..TOTAL_SHARDS as u8)
            .map(|i| shard_key(&mailbox_key, i))
            .collect();

        let unique: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(unique.len(), TOTAL_SHARDS);
    }

    #[test]
    fn shard_keys_depend_on_the_mailbox_key() {
        assert_ne!(shard_key(&[1u8; 32], 0), shard_key(&[2u8; 32], 0));
    }
}
