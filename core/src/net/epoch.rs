//! エポックビーコン — 位置グラインディング対策の日次シード (3-4)
//!
//! # 何を防ぐか
//!
//! リング座標は `position = H(NodeId ‖ epoch_seed)`（[`crate::net::ring`]）。`epoch_seed` が
//! 固定だと、攻撃者は Ed25519 鍵を大量生成して**狙った mailbox_key の隣に着地する NodeId**を
//! 選べる（保持者になりすまして覗く・検閲する）。`epoch_seed` を**前もって予測できない日次
//! 乱数**にすると、グラインドした NodeId は1エポック（1日）で無効化され、毎日引き直しを
//! 強いられる（NodeId PoW = Argon2id の高コストと相乗する）。
//!
//! # なぜ drand か
//!
//! seed に要る条件は ①全ノード一致 ②予測不能 ③捏造不能。自前の合意層は重いので、
//! 公開の乱数ビーコン **drand（League of Entropy）** を使う。30 秒ごとに BLS 署名付き乱数を
//! 出し、世界中が同じ値を見る。エポック開始時刻に対応する**ラウンド番号は決定論的**なので、
//! 全ノードが独立に同じラウンド→同じ seed に到達する。
//!
//! # 真正性について（正直な限界）
//!
//! [`DrandBeacon::verify_integrity`] は `randomness == SHA256(signature)`（chained scheme の
//! 整合性）だけを確認する。これは**真正性（BLS 署名検証）ではない** ── 取得は HTTPS(TLS) の
//! 信頼に依る。MITM された1ノードは誤った seed で座標がずれるだけ（自分の可用性問題であって、
//! 網全体のグラインド突破にはならない）。BLS 検証と網内伝播は hardening の後段。

use crate::error::{AetherError, Result};
use sha2::{Digest, Sha256};

/// drand League of Entropy デフォルトチェーン（`pedersen-bls-chained`・30 秒周期）
const DRAND_CHAIN_HASH: &str = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce";
/// 上記チェーンの genesis 時刻（UNIX 秒）
const DRAND_GENESIS: u64 = 1_595_431_050;
/// 上記チェーンのラウンド周期（秒）
const DRAND_PERIOD_SECS: u64 = 30;

/// フェイルオーバ用の drand HTTP エンドポイント（順に試す）
const DRAND_ENDPOINTS: &[&str] = &["https://api.drand.sh", "https://drand.cloudflare.com"];

/// エポック長（秒）＝ 1 日
pub const EPOCH_SECS: u64 = 24 * 60 * 60;

/// `now`(UNIX 秒) が属するエポック番号（＝日）
pub fn epoch_index(now: u64) -> u64 {
    now / EPOCH_SECS
}

/// エポック開始時刻に対応する drand ラウンド番号
///
/// 全ノードが独立に同じ値を計算する（＝同じ seed に到達する）。エポック開始は
/// 常に過去（起動時にはそのラウンドは既に生成済み）なので、未来ラウンド要求で
/// 404 にならない。
pub fn round_for_epoch(epoch: u64) -> u64 {
    let epoch_start = epoch.saturating_mul(EPOCH_SECS);
    if epoch_start <= DRAND_GENESIS {
        return 1;
    }
    (epoch_start - DRAND_GENESIS) / DRAND_PERIOD_SECS + 1
}

/// エポックと randomness から `epoch_seed` を導出する
///
/// ドメイン分離のため用途タグとチェーンハッシュを混ぜる。全ノードが同じ
/// `(epoch, randomness)` から同じ 32 バイトへ到達する。
pub fn seed_from(epoch: u64, randomness: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"aether_epoch_v1");
    h.update(DRAND_CHAIN_HASH.as_bytes());
    h.update(epoch.to_be_bytes());
    h.update(randomness);
    h.finalize().into()
}

/// drand の 1 ラウンド応答
#[derive(Debug, Clone)]
pub struct DrandBeacon {
    pub round: u64,
    pub randomness: Vec<u8>,
    pub signature: Vec<u8>,
}

impl DrandBeacon {
    /// `randomness == SHA256(signature)` の整合性を確認する（chained scheme）
    ///
    /// **整合性チェックであって真正性（BLS）ではない。** 応答が内部矛盾していないことだけを
    /// 見る。真正性は取得経路（TLS）の信頼に依る。
    pub fn verify_integrity(&self) -> bool {
        if self.randomness.len() != 32 {
            return false;
        }
        let h: [u8; 32] = Sha256::digest(&self.signature).into();
        self.randomness.as_slice() == h
    }
}

/// 指定エポックの `epoch_seed` を drand から取得して導出する（ネットワーク I/O・ブロッキング）
///
/// エンドポイントを順に試し、最初に成功したものを使う。整合性チェックを通らない
/// 応答は拒否する。呼び出し側は [`tokio::task::spawn_blocking`] から呼ぶこと。
pub fn fetch_epoch_seed(epoch: u64) -> Result<[u8; 32]> {
    let round = round_for_epoch(epoch);
    let beacon = fetch_beacon(round)?;
    if beacon.round != round {
        return Err(AetherError::Protocol(format!(
            "drand returned round {} but {} was requested",
            beacon.round, round
        )));
    }
    if !beacon.verify_integrity() {
        return Err(AetherError::Crypto(
            "drand beacon integrity check failed (randomness != SHA256(signature))".into(),
        ));
    }
    Ok(seed_from(epoch, &beacon.randomness))
}

/// 指定ラウンドの drand ビーコンを HTTP 取得する（ブロッキング）
fn fetch_beacon(round: u64) -> Result<DrandBeacon> {
    let mut last_err = String::new();
    for base in DRAND_ENDPOINTS {
        let url = format!("{}/{}/public/{}", base, DRAND_CHAIN_HASH, round);
        match fetch_beacon_from(&url) {
            Ok(b) => return Ok(b),
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(AetherError::Network(std::io::Error::other(format!(
        "all drand endpoints failed: {}",
        last_err
    ))))
}

fn fetch_beacon_from(url: &str) -> Result<DrandBeacon> {
    let resp = ureq::get(url)
        .timeout(std::time::Duration::from_secs(10))
        .call()
        .map_err(|e| AetherError::Network(std::io::Error::other(e.to_string())))?;

    let json: serde_json::Value = resp
        .into_json()
        .map_err(|e| AetherError::Protocol(format!("drand JSON parse failed: {}", e)))?;

    let round = json["round"]
        .as_u64()
        .ok_or_else(|| AetherError::Protocol("drand response missing round".into()))?;
    let randomness = hex::decode(
        json["randomness"]
            .as_str()
            .ok_or_else(|| AetherError::Protocol("drand response missing randomness".into()))?,
    )
    .map_err(|e| AetherError::Protocol(format!("drand randomness not hex: {}", e)))?;
    let signature = hex::decode(
        json["signature"]
            .as_str()
            .ok_or_else(|| AetherError::Protocol("drand response missing signature".into()))?,
    )
    .map_err(|e| AetherError::Protocol(format!("drand signature not hex: {}", e)))?;

    Ok(DrandBeacon {
        round,
        randomness,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_index_advances_daily() {
        assert_eq!(epoch_index(0), 0);
        assert_eq!(epoch_index(EPOCH_SECS - 1), 0);
        assert_eq!(epoch_index(EPOCH_SECS), 1);
        assert_eq!(epoch_index(2 * EPOCH_SECS + 5), 2);
    }

    #[test]
    fn round_for_epoch_is_deterministic_and_past() {
        // 全ノードが同じエポックから同じラウンドを出す
        let e = epoch_index(1_700_000_000);
        assert_eq!(round_for_epoch(e), round_for_epoch(e));
        // エポック開始は genesis より後 → ラウンドは 1 より大きい
        assert!(round_for_epoch(e) > 1);
        // 隣のエポックは別のラウンド
        assert_ne!(round_for_epoch(e), round_for_epoch(e + 1));
        // 1 日 = 86400s / 30s = 2880 ラウンドぶん進む
        assert_eq!(round_for_epoch(e + 1) - round_for_epoch(e), EPOCH_SECS / DRAND_PERIOD_SECS);
    }

    #[test]
    fn round_before_genesis_clamps_to_one() {
        assert_eq!(round_for_epoch(0), 1);
    }

    #[test]
    fn seed_depends_on_epoch_and_randomness() {
        let r = [0xABu8; 32];
        assert_eq!(seed_from(10, &r), seed_from(10, &r), "決定論的");
        assert_ne!(seed_from(10, &r), seed_from(11, &r), "エポックが違えば seed も違う");
        assert_ne!(seed_from(10, &r), seed_from(10, &[0xCDu8; 32]), "乱数が違えば seed も違う");
    }

    #[test]
    fn integrity_check_matches_real_drand_round() {
        // 実在の drand round 6317147（randomness == SHA256(signature) を実測で確認済み）
        let sig = hex::decode(
            "b27f642d642998fdaecdb3de1b33b22b4ae3e8ae2218040de47e31b7431c24100396e4c21a42532540eb1c130ea6cbe31874eceabe5f088bc21719ba17bf9cb14947936a04683c0fe50e0a201a17c1e294677359042917652795b652df97e704",
        )
        .unwrap();
        let randomness =
            hex::decode("e1d037b4cf25807ddb6ef5081fe4f799f196d6d3f262b57d1784265555bf771b").unwrap();

        let good = DrandBeacon { round: 6317147, randomness: randomness.clone(), signature: sig.clone() };
        assert!(good.verify_integrity(), "本物のビーコンは整合する");

        // signature を1バイト改竄すると randomness と食い違う
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0x01;
        let bad = DrandBeacon { round: 6317147, randomness, signature: bad_sig };
        assert!(!bad.verify_integrity(), "改竄した署名は整合しない");
    }

    /// ネットワークを叩く生の疎通テスト（既定では実行しない）。
    /// `cargo test -p aether-core --lib epoch -- --ignored --nocapture` で確認。
    #[test]
    #[ignore = "drand への実ネットワークアクセスが要る"]
    fn live_fetch_derives_a_seed() {
        let epoch = epoch_index(crate::protocol::hint::current_timestamp());
        let seed = fetch_epoch_seed(epoch).expect("drand から seed を取得");
        assert_ne!(seed, [0u8; 32], "取得した seed が非ゼロ");
        // 同じエポックなら再取得しても同じ seed（決定論的ラウンド）
        assert_eq!(seed, fetch_epoch_seed(epoch).unwrap());
        println!("epoch {} seed = {}", epoch, hex::encode(seed));
    }
}
