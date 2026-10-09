//! 大容量ファイル用の符号化 v2 ── ストライプごとの RS(k+m)（純粋な関数だけ）
//!
//! 出典: Part 23 の 7 章。v1（`sharding.rs` の 3+2 を 5 複製）は、小さな投稿・私信・索引が使い続ける。
//! こちらは 16 チャンク前後の「ストライプ」ごとに RS(k+m) を掛け、**各シャードを 1 か所にだけ置く**。
//! 複製の代わりに冗長度 m をファイルごとに選び、上りと保存を減らしつつ取り切れる確率を保つ。
//!
//! ここには通信も保存も無い。シャードの置き場所やハッシュの照合は呼び出し側（Manifest v2）の仕事。

use crate::error::{AetherError, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;

/// 1 ストライプのデータシャード数の既定値
pub const DEFAULT_DATA_SHARDS: usize = 16;

/// `k + m` の上限（GF(2^8) の RS が扱える総数）
pub const MAX_TOTAL_SHARDS: usize = 256;

/// 1 ストライプが取れる確率 `P(X >= k)`、`X ~ Binomial(k+m, 1-q)` の「取れない側」`P(X < k)`
///
/// 組み合わせ数は大きくなるので、対数の階乗（逐次の和）で項を出して桁あふれを避ける。
fn stripe_failure(q: f64, k: usize, m: usize) -> f64 {
    let n = k + m;
    let p = 1.0 - q;
    // ln_fact[i] = ln(i!)
    let mut ln_fact = vec![0.0f64; n + 1];
    for i in 1..=n {
        ln_fact[i] = ln_fact[i - 1] + (i as f64).ln();
    }
    let mut fail = 0.0f64;
    for i in 0..k {
        let ln_term = ln_fact[n] - ln_fact[i] - ln_fact[n - i]
            + (i as f64) * p.ln()
            + ((n - i) as f64) * q.ln();
        fail += ln_term.exp();
    }
    fail.min(1.0)
}

/// 「全ストライプが取れる確率 >= target」を満たす最小のパリティ数 m
///
/// - `q`: 取りに行ったとき保持者が不在の確率の仮定（0 以上 1 未満）
/// - `k`: 1 ストライプのデータシャード数
/// - `stripes`: ストライプ数。1 ストライプが取れる確率の `stripes` 乗が全体の確率
/// - `target`: 目標（0 より大きく 1 未満）
///
/// `k + m` が 256 を超えないと目標に届かないときはエラー（黙って切り詰めない）。
pub fn m_for(q: f64, k: usize, stripes: usize, target: f64) -> Result<usize> {
    if !((0.0..1.0).contains(&q) && target > 0.0 && target < 1.0) {
        return Err(AetherError::Config(format!(
            "m_for: invalid probability (q={}, target={})",
            q, target
        )));
    }
    if k == 0 || k > MAX_TOTAL_SHARDS || stripes == 0 {
        return Err(AetherError::Config(format!(
            "m_for: invalid shape (k={}, stripes={})",
            k, stripes
        )));
    }
    for m in 0..=(MAX_TOTAL_SHARDS - k) {
        let fail = stripe_failure(q, k, m);
        // (1 - fail)^stripes を対数で。fail が極小でも 1 - fail に丸められない
        let all_ok = ((stripes as f64) * (-fail).ln_1p()).exp();
        if all_ok >= target {
            return Ok(m);
        }
    }
    Err(AetherError::Config(format!(
        "m_for: target {} is unreachable with k={} (k+m would exceed {})",
        target, k, MAX_TOTAL_SHARDS
    )))
}

fn rs(k: usize, m: usize) -> Result<ReedSolomon> {
    if k == 0 || m == 0 || k + m > MAX_TOTAL_SHARDS {
        return Err(AetherError::Config(format!(
            "RS(k={}, m={}) is out of range (k>=1, m>=1, k+m<={})",
            k, m, MAX_TOTAL_SHARDS
        )));
    }
    ReedSolomon::new(k, m).map_err(|e| AetherError::Protocol(format!("RS init failed: {:?}", e)))
}

/// データシャード k 個から**パリティシャード m 個だけ**を作る（データは呼び出し側が持っている）
///
/// データシャードは全て同じ長さであること。**暗号文のシャードから作る**（平文から RS を作らない）。
pub fn encode_stripe(data: &[Vec<u8>], parity: usize) -> Result<Vec<Vec<u8>>> {
    let k = data.len();
    let codec = rs(k, parity)?;
    let len = data[0].len();
    if len == 0 || data.iter().any(|s| s.len() != len) {
        return Err(AetherError::Protocol(
            "encode_stripe: data shards must be non-empty and of equal length".into(),
        ));
    }
    let mut shards: Vec<Vec<u8>> = data.to_vec();
    shards.extend((0..parity).map(|_| vec![0u8; len]));
    codec
        .encode(&mut shards)
        .map_err(|e| AetherError::Protocol(format!("RS encode failed: {:?}", e)))?;
    Ok(shards.split_off(k))
}

/// 揃ったシャードからデータシャード k 個を取り戻す
///
/// `shards` は長さ `k + m`、並びは データ k 個 → パリティ m 個。取れなかった所は `None`。
/// 有効なものが k 個未満ならエラー。データが全部あれば RS の計算はしない。
/// 呼び出し側はハッシュを照合し、合ったものだけを `Some` にして渡すこと。
pub fn decode_stripe(k: usize, m: usize, shards: &[Option<Vec<u8>>]) -> Result<Vec<Vec<u8>>> {
    if shards.len() != k + m {
        return Err(AetherError::Protocol(format!(
            "decode_stripe: expected {} shards, got {}",
            k + m,
            shards.len()
        )));
    }
    let codec = rs(k, m)?;
    let present = shards.iter().filter(|s| s.is_some()).count();
    if present < k {
        return Err(AetherError::Protocol(format!(
            "decode_stripe: only {} of {} needed shards",
            present, k
        )));
    }
    let mut work: Vec<Option<Vec<u8>>> = shards.to_vec();
    if work[..k].iter().any(|s| s.is_none()) {
        let mut lens = work.iter().flatten().map(|s| s.len());
        let first = lens.next().unwrap_or(0);
        if first == 0 || lens.any(|l| l != first) {
            return Err(AetherError::Protocol(
                "decode_stripe: shards must be non-empty and of equal length".into(),
            ));
        }
        codec
            .reconstruct_data(&mut work)
            .map_err(|e| AetherError::Protocol(format!("RS reconstruct failed: {:?}", e)))?;
    }
    work.into_iter()
        .take(k)
        .map(|s| s.ok_or_else(|| AetherError::Protocol("decode_stripe: data shard missing".into())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_shards(k: usize, len: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|i| (0..len).map(|j| (i * 31 + j * 7 + 1) as u8).collect())
            .collect()
    }

    fn with_parity(data: &[Vec<u8>], m: usize) -> Vec<Vec<u8>> {
        let mut all = data.to_vec();
        all.extend(encode_stripe(data, m).unwrap());
        all
    }

    fn keep(all: &[Vec<u8>], idx: &[usize]) -> Vec<Option<Vec<u8>>> {
        (0..all.len())
            .map(|i| idx.contains(&i).then(|| all[i].clone()))
            .collect()
    }

    #[test]
    fn m_for_matches_the_part23_table() {
        assert_eq!(m_for(0.1, 16, 239, 0.999).unwrap(), 11);
        assert_eq!(m_for(0.3, 16, 239, 0.999).unwrap(), 27);
        assert_eq!(m_for(0.5, 16, 239, 0.999).unwrap(), 51);
    }

    #[test]
    fn m_for_grows_with_stripes_and_loss() {
        let small = m_for(0.3, 16, 1, 0.999).unwrap();
        let big = m_for(0.3, 16, 239, 0.999).unwrap();
        assert!(small < big, "ストライプが増えるほど冗長が要る");
        assert!(m_for(0.1, 16, 10, 0.999).unwrap() < m_for(0.5, 16, 10, 0.999).unwrap());
    }

    #[test]
    fn m_for_is_zero_when_nothing_is_lost() {
        assert_eq!(m_for(0.0, 16, 100, 0.999).unwrap(), 0);
    }

    #[test]
    fn m_for_rejects_unreachable_and_invalid_input() {
        assert!(m_for(0.99, 16, 1000, 0.999).is_err(), "k+m が 256 を超える");
        assert!(m_for(1.0, 16, 1, 0.999).is_err());
        assert!(m_for(0.3, 0, 1, 0.999).is_err());
        assert!(m_for(0.3, 16, 0, 0.999).is_err());
        assert!(m_for(0.3, 16, 1, 1.0).is_err());
    }

    #[test]
    fn decode_restores_from_any_k_shards() {
        let data = data_shards(16, 64);
        let all = with_parity(&data, 4);
        // データを 3 枚欠いてパリティで補う
        let idx: Vec<usize> = (3..20).collect();
        assert_eq!(idx.len(), 17);
        assert_eq!(decode_stripe(16, 4, &keep(&all, &idx[..16])).unwrap(), data);
        // パリティを多く使う（データ 12 枚 + パリティ 4 枚）
        let idx: Vec<usize> = (0..12).chain(16..20).collect();
        assert_eq!(decode_stripe(16, 4, &keep(&all, &idx)).unwrap(), data);
        // データが全部あれば計算せずそのまま
        let idx: Vec<usize> = (0..16).collect();
        assert_eq!(decode_stripe(16, 4, &keep(&all, &idx)).unwrap(), data);
    }

    #[test]
    fn decode_fails_with_fewer_than_k() {
        let data = data_shards(16, 64);
        let all = with_parity(&data, 4);
        let idx: Vec<usize> = (0..15).collect();
        assert!(decode_stripe(16, 4, &keep(&all, &idx)).is_err());
    }

    #[test]
    fn short_last_stripe_roundtrips() {
        let data = data_shards(3, 40);
        let all = with_parity(&data, 1);
        let got = decode_stripe(3, 1, &keep(&all, &[0, 2, 3])).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn parity_is_computed_from_the_given_bytes_only() {
        let data = data_shards(4, 32);
        assert_eq!(encode_stripe(&data, 2).unwrap(), encode_stripe(&data, 2).unwrap());
        assert_eq!(encode_stripe(&data, 2).unwrap().len(), 2);
        assert!(encode_stripe(&data, 2).unwrap().iter().all(|p| p.len() == 32));
    }

    #[test]
    fn unequal_or_wrong_shape_is_an_error() {
        let mut data = data_shards(4, 32);
        data[2].pop();
        assert!(encode_stripe(&data, 2).is_err(), "長さが揃わない");
        assert!(encode_stripe(&data_shards(4, 32), 0).is_err(), "m=0 は符号にならない");
        assert!(decode_stripe(4, 2, &vec![None; 5]).is_err(), "枚数が k+m と違う");
    }
}
