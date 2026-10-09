//! 保持者の「保存用の身元（SID）」と leaseSet（Part 23 の 5.1・5.2、Part 24 の L4）
//!
//! 保持者は IP と切り離した身元（SID = Ed25519 の鍵）でリング上の位置（**枠**）を取り、
//! 自分宛ての受け口（トンネルの入口）を leaseSet にして PEX で配る。
//! 置く側・取る側は、リレーの IP ではなく leaseSet から保持者の受け口を引く。
//!
//! # leaseSet に入れないもの
//!
//! **IP アドレスは入れない。** 受け口は NodeId とトンネル ID だけで、受け口のリレーの IP は
//! そのリレーの記述子（公開）から引く。SID と保持者の IP を結ぶものは、ここには無い。
//!
//! # 指紋を減らす丸め
//!
//! - 枠の数は 2 の冪に切り捨てる（容量がそのまま見えないように。Part 24 の L4）
//! - `issued_at` は 10 分単位に切り捨てる（更新の時刻が細かく見えないように）
//!
//! 丸めは作る側で行い、受け取る側で丸まっていることを確かめる（丸まっていないものは
//! 作り手が丸めを守っていない＝指紋を残す実装なので受け取らない）。

use crate::crypto::identity::{Identity, NodeId};
use crate::crypto::pow;
use crate::error::{AetherError, Result};
use crate::net::ring::{self, RingPosition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// leaseSet の署名に混ぜるドメイン分離タグ
const LEASE_SET_SIG_DOMAIN: &[u8] = b"aether_lease_set_v1";

/// 枠ごとの PoW の入力（`slot_id`）を導くドメイン分離タグ
const SLOT_ID_DOMAIN: &[u8] = b"aether_storage_slot_v1";

/// 枠 1 つあたりの容量（バイト）。容量 1GiB ごとに 1 枠
pub const SLOT_CAPACITY_BYTES: u64 = 1 << 30;

/// 1 つの SID が取れる枠の上限（2 の冪）
///
/// 枠ごとに Argon2 の PoW を検証するので、受け取り側の検証費用の上限にもなる。
pub const MAX_SLOTS_PER_LEASE_SET: usize = 64;

/// 受け口の数の上限（下限は 1）
pub const MAX_GATEWAYS_PER_LEASE_SET: usize = 3;

/// `issued_at` を丸める単位（秒）
pub const ISSUED_AT_GRANULARITY_SECS: u64 = 600;

/// leaseSet の有効期間（秒）。`expires_at = issued_at + これ`
///
/// 保持者は期限の前に（ランダムな時刻に）作り直す。リレーの記述子の期限と同じ長さ。
pub const LEASE_SET_TTL_SECS: u64 = 3 * 3600;

/// ディレクトリが持つ leaseSet の上限。超えたら期限の近いものから捨てる
///
/// 上限が無いと、SID を量産した攻撃者がメモリを食い潰せる。
pub const MAX_LEASE_SETS: usize = 100_000;

/// PEX の 1 回の応答に載せる leaseSet の上限（増幅攻撃を抑える）
pub const MAX_LEASE_SETS_PER_RESPONSE: usize = 64;

/// 枠 1 つの証明（番号と PoW の解）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotProof {
    pub index: u32,
    pub pow_nonce: u64,
}

/// 受け口 1 つ。**IP は持たない**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGateway {
    /// 受け口のリレー（IP はそのリレーの記述子から引く）
    pub gateway: NodeId,
    pub tunnel_id: [u8; 32],
}

/// 保持者の leaseSet
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseSet {
    /// SID の公開鍵（Ed25519）
    pub sid: [u8; 32],
    /// 枠。数は 2 の冪で、番号は 0 から順に並ぶ
    pub slots: Vec<SlotProof>,
    /// 受け口（1〜3 個）
    pub gateways: Vec<LeaseGateway>,
    /// 発行の時刻。10 分単位に切り捨てる
    pub issued_at: u64,
    /// `issued_at + LEASE_SET_TTL_SECS`
    pub expires_at: u64,
    /// 上の全フィールドへの SID の署名（ドメイン分離のタグ付き）
    pub signature: Vec<u8>,
}

/// 容量（バイト）から枠の数を決める。1GiB ごとに 1 枠で、**2 の冪に切り捨てる**
///
/// 最低 1、最大 [`MAX_SLOTS_PER_LEASE_SET`]。切り捨てるのは、申告する枠の数が
/// 容量そのものの指紋にならないようにするため（3GiB の人も 2GiB の人も 2 枠に見える）。
pub fn slot_count_for_capacity(capacity_bytes: u64) -> u32 {
    let raw = (capacity_bytes / SLOT_CAPACITY_BYTES).max(1);
    let pow2 = 1u64 << (63 - raw.leading_zeros());
    pow2.min(MAX_SLOTS_PER_LEASE_SET as u64) as u32
}

/// 時刻を発行の単位（10 分）に切り捨てる
pub fn round_issued_at(now: u64) -> u64 {
    now - now % ISSUED_AT_GRANULARITY_SECS
}

/// 枠 `index` の PoW を掛ける 32 バイト
///
/// 枠ごとに別の入力にして、PoW の解を枠の間で使い回せないようにする。
pub fn slot_id(sid: &[u8; 32], index: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_ID_DOMAIN);
    hasher.update(sid);
    hasher.update(index.to_be_bytes());
    hasher.finalize().into()
}

/// 枠 `count` 個の PoW を解く（SID の生成後に 1 回だけ。難易度によっては長くかかる）
pub fn solve_slots(
    sid: &[u8; 32],
    count: u32,
    difficulty: u32,
    max_attempts: u64,
) -> Result<Vec<SlotProof>> {
    (0..count)
        .map(|index| {
            let pow_nonce = pow::node_id::solve(&slot_id(sid, index), difficulty, max_attempts)?;
            Ok(SlotProof { index, pow_nonce })
        })
        .collect()
}

impl SlotProof {
    /// 枠のリング上の位置
    pub fn position(&self, sid: &[u8; 32], epoch_seed: &[u8; 32]) -> RingPosition {
        ring::position_of_slot(&slot_id(sid, self.index), self.pow_nonce, epoch_seed)
    }
}

impl LeaseSet {
    /// leaseSet を組み立てて署名する
    ///
    /// `now` は 10 分単位に切り捨てて `issued_at` にする（丸めは作る側の責務）。
    /// 検証に通らない形（枠の数・受け口の数）は、署名する前に弾く。
    pub fn new_signed(
        sid: &Identity,
        slots: Vec<SlotProof>,
        gateways: Vec<LeaseGateway>,
        now: u64,
    ) -> Result<Self> {
        let issued_at = round_issued_at(now);
        let mut lease = Self {
            sid: sid.public_id().0,
            slots,
            gateways,
            issued_at,
            expires_at: issued_at + LEASE_SET_TTL_SECS,
            signature: Vec::new(),
        };
        lease.check_shape()?;
        lease.signature = sid.sign(&lease.signing_bytes());
        Ok(lease)
    }

    /// 署名の対象。**全フィールドを入れる**（入れ忘れたフィールドは書き換えられる）
    fn signing_bytes(&self) -> Vec<u8> {
        let body = (
            &self.sid,
            &self.slots,
            &self.gateways,
            self.issued_at,
            self.expires_at,
        );
        let mut buf = LEASE_SET_SIG_DOMAIN.to_vec();
        buf.extend_from_slice(&bincode::serialize(&body).expect("固定形のタプルは直列化できる"));
        buf
    }

    /// 署名・PoW を見ない、形と時刻の丸めだけの検査
    fn check_shape(&self) -> Result<()> {
        let n = self.slots.len();
        if n == 0 || !n.is_power_of_two() || n > MAX_SLOTS_PER_LEASE_SET {
            return Err(AetherError::Protocol(format!(
                "LeaseSet slot count {} is not a power of two in 1..={}",
                n, MAX_SLOTS_PER_LEASE_SET
            )));
        }
        // 番号を 0.. の連番に固定する。番号を自由に選べると、位置の良い番号を
        // 探して選べる分だけ狙い撃ちの自由度が増える。
        if self.slots.iter().enumerate().any(|(i, s)| s.index as usize != i) {
            return Err(AetherError::Protocol(
                "LeaseSet slot indices must be 0..n in order".into(),
            ));
        }
        let g = self.gateways.len();
        if g == 0 || g > MAX_GATEWAYS_PER_LEASE_SET {
            return Err(AetherError::Protocol(format!(
                "LeaseSet gateway count {} is not in 1..={}",
                g, MAX_GATEWAYS_PER_LEASE_SET
            )));
        }
        for (i, a) in self.gateways.iter().enumerate() {
            if self.gateways[..i].contains(a) {
                return Err(AetherError::Protocol("LeaseSet has a duplicate gateway".into()));
            }
        }
        if !self.issued_at.is_multiple_of(ISSUED_AT_GRANULARITY_SECS) {
            return Err(AetherError::Protocol(
                "LeaseSet issued_at is not rounded to the granularity".into(),
            ));
        }
        if self.expires_at != self.issued_at.saturating_add(LEASE_SET_TTL_SECS) {
            return Err(AetherError::Protocol(
                "LeaseSet expires_at is not issued_at plus the fixed lifetime".into(),
            ));
        }
        Ok(())
    }

    /// 期限が切れているか
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// 受け取った leaseSet を検証する
    ///
    /// 形（枠・受け口の数、丸め）→ 時刻 → 署名 → 枠の PoW の順（安いものから）。
    /// `pow_difficulty` は網全体の値（`NetworkParams::directory_pow_difficulty`）。
    pub fn verify(&self, now: u64, pow_difficulty: u32) -> Result<()> {
        self.verify_with_known_slots(now, pow_difficulty, &[])
    }

    /// [`verify`](Self::verify) と同じだが、`known` に含まれる枠（同じ SID の、確かめ済みの leaseSet の枠）は
    /// PoW を確かめ直さない
    ///
    /// 枠の PoW は SID と枠の番号だけで決まり、出し直し（3 時間ごと）でも変わらない。毎回 Argon2 を
    /// 枠の数だけ回すと、PEX の応答 1 回（leaseSet 64 件 × 枠 64）で数千回になり、CPU を浪費させられる。
    /// 署名は毎回確かめるので、`known` は「この SID が以前に正しく示した枠」でなければならない。
    pub fn verify_with_known_slots(&self, now: u64, pow_difficulty: u32, known: &[SlotProof]) -> Result<()> {
        self.check_shape()?;

        // 遠い未来の発行を一度入れると、以後の正しい更新が「古い」として弾かれる。
        if self.issued_at > now + crate::net::relay_list::MAX_DESCRIPTOR_CLOCK_SKEW_SECS {
            return Err(AetherError::Protocol("LeaseSet is dated in the future".into()));
        }
        if self.is_expired(now) {
            return Err(AetherError::Protocol("LeaseSet has expired".into()));
        }

        crate::crypto::identity::verify_signature(
            &NodeId(self.sid),
            &self.signing_bytes(),
            &self.signature,
        )?;

        for slot in self.slots.iter().filter(|s| !known.contains(s)) {
            let ok = pow::node_id::verify(&slot_id(&self.sid, slot.index), slot.pow_nonce, pow_difficulty)?;
            if !ok {
                return Err(AetherError::Crypto("LeaseSet slot has invalid PoW".into()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000; // 600 の倍数

    fn gateway(n: u8) -> LeaseGateway {
        LeaseGateway {
            gateway: NodeId([n; 32]),
            tunnel_id: [n; 32],
        }
    }

    fn lease_with(id: &Identity, slots: u32, gateways: u8, now: u64) -> LeaseSet {
        LeaseSet::new_signed(
            id,
            solve_slots(&id.public_id().0, slots, 0, 1).unwrap(),
            (1..=gateways).map(gateway).collect(),
            now,
        )
        .unwrap()
    }

    #[test]
    fn capacity_maps_to_a_power_of_two_slot_count() {
        let gib = SLOT_CAPACITY_BYTES;
        for (cap, want) in [(1, 1), (2, 2), (3, 2), (5, 4), (8, 8), (0, 1), (63, 32), (64, 64), (1000, 64)] {
            assert_eq!(slot_count_for_capacity(cap * gib), want, "{} GiB", cap);
        }
        assert_eq!(slot_count_for_capacity(gib - 1), 1, "1GiB 未満も最低 1 枠");
    }

    #[test]
    fn signed_lease_set_verifies() {
        let id = Identity::generate();
        let lease = lease_with(&id, 4, 3, NOW + 123);
        assert_eq!(lease.issued_at, NOW, "作る側で 10 分単位に切り捨てる");
        assert_eq!(lease.expires_at, NOW + LEASE_SET_TTL_SECS);
        lease.verify(NOW + 200, 0).unwrap();
    }

    #[test]
    fn every_field_is_covered_by_the_signature() {
        let id = Identity::generate();
        let lease = lease_with(&id, 2, 2, NOW);
        let other = Identity::generate();

        let mut cases: Vec<(&str, LeaseSet)> = Vec::new();
        let mut l = lease.clone();
        l.sid = other.public_id().0;
        cases.push(("sid", l));
        let mut l = lease.clone();
        l.slots[0].pow_nonce += 1; // 難易度 0 では PoW は通るので、署名で落ちる
        cases.push(("slots", l));
        let mut l = lease.clone();
        l.gateways[0].tunnel_id = [9; 32];
        cases.push(("tunnel_id", l));
        let mut l = lease.clone();
        l.gateways[1].gateway = NodeId([9; 32]);
        cases.push(("gateway", l));
        let mut l = lease.clone();
        l.issued_at += ISSUED_AT_GRANULARITY_SECS;
        l.expires_at += ISSUED_AT_GRANULARITY_SECS; // 形は保ったまま日付だけ動かす
        cases.push(("issued_at", l));
        let mut l = lease.clone();
        l.signature[0] ^= 1;
        cases.push(("signature", l));

        for (name, l) in cases {
            assert!(l.verify(NOW + 200, 0).is_err(), "{} を書き換えても通った", name);
        }
    }

    #[test]
    fn signature_has_a_domain_tag() {
        // 別の用途の署名（タグなし）を流用できない
        let id = Identity::generate();
        let mut lease = lease_with(&id, 1, 1, NOW);
        let bare = bincode::serialize(&(
            &lease.sid,
            &lease.slots,
            &lease.gateways,
            lease.issued_at,
            lease.expires_at,
        ))
        .unwrap();
        lease.signature = id.sign(&bare);
        assert!(lease.verify(NOW, 0).is_err());
    }

    #[test]
    fn rejects_insufficient_slot_pow() {
        let id = Identity::generate();
        // 難易度 0 で解いた（nonce = 0）枠は、難易度 8 では通らない（確率 1/256 で偶然通る）
        let mut lease = lease_with(&id, 4, 1, NOW);
        let mut found = false;
        for nonce in 0..50_000u64 {
            lease.slots[0].pow_nonce = nonce;
            if !pow::node_id::verify(&slot_id(&lease.sid, 0), nonce, 8).unwrap() {
                found = true;
                break;
            }
        }
        assert!(found);
        lease.signature = id.sign(&lease.signing_bytes());
        assert!(lease.verify(NOW, 8).is_err(), "PoW の足りない枠を受け入れた");
    }

    #[test]
    fn solved_slot_pow_passes_a_real_difficulty() {
        let id = Identity::generate();
        let sid = id.public_id().0;
        let slots = solve_slots(&sid, 2, 4, 1_000_000).unwrap();
        let lease = LeaseSet::new_signed(&id, slots, vec![gateway(1)], NOW).unwrap();
        lease.verify(NOW, 4).unwrap();
    }

    #[test]
    fn slot_pow_cannot_be_reused_between_slots() {
        let sid = [7u8; 32];
        assert_ne!(slot_id(&sid, 0), slot_id(&sid, 1));
        assert_ne!(slot_id(&sid, 0), slot_id(&[8u8; 32], 0));
    }

    #[test]
    fn rejects_non_power_of_two_slot_counts() {
        let id = Identity::generate();
        for n in [0u32, 3, 5, 6, 7, 128] {
            let mut lease = lease_with(&id, 1, 1, NOW);
            lease.slots = solve_slots(&lease.sid, n, 0, 1).unwrap();
            lease.signature = id.sign(&lease.signing_bytes());
            assert!(lease.verify(NOW, 0).is_err(), "{} 枠を受け入れた", n);
            assert!(
                LeaseSet::new_signed(&id, lease.slots.clone(), lease.gateways.clone(), NOW).is_err(),
                "{} 枠を作れてしまった",
                n
            );
        }
    }

    #[test]
    fn rejects_slot_indices_that_are_not_sequential() {
        let id = Identity::generate();
        let mut lease = lease_with(&id, 2, 1, NOW);
        lease.slots[1].index = 5;
        lease.signature = id.sign(&lease.signing_bytes());
        assert!(lease.verify(NOW, 0).is_err());
    }

    #[test]
    fn rejects_bad_gateway_counts_and_duplicates() {
        let id = Identity::generate();
        let mut lease = lease_with(&id, 1, 1, NOW);
        for gateways in [vec![], (1..=4).map(gateway).collect(), vec![gateway(1), gateway(1)]] {
            lease.gateways = gateways;
            lease.signature = id.sign(&lease.signing_bytes());
            assert!(lease.verify(NOW, 0).is_err());
        }
    }

    #[test]
    fn rejects_unrounded_issued_at() {
        let id = Identity::generate();
        let mut lease = lease_with(&id, 1, 1, NOW);
        lease.issued_at = NOW + 1;
        lease.expires_at = lease.issued_at + LEASE_SET_TTL_SECS;
        lease.signature = id.sign(&lease.signing_bytes());
        assert!(lease.verify(NOW + 100, 0).is_err(), "丸まっていない時刻を受け入れた");
    }

    #[test]
    fn rejects_a_lifetime_other_than_the_fixed_one() {
        let id = Identity::generate();
        let mut lease = lease_with(&id, 1, 1, NOW);
        lease.expires_at += 3600;
        lease.signature = id.sign(&lease.signing_bytes());
        assert!(lease.verify(NOW, 0).is_err());
    }

    #[test]
    fn rejects_expired_and_future_lease_sets() {
        let id = Identity::generate();
        let lease = lease_with(&id, 1, 1, NOW);
        lease.verify(NOW + LEASE_SET_TTL_SECS - 1, 0).unwrap();
        assert!(lease.verify(NOW + LEASE_SET_TTL_SECS, 0).is_err(), "期限切れ");
        assert!(lease.verify(NOW - 3600, 0).is_err(), "遠い未来の発行");
    }

    #[test]
    fn slot_position_is_deterministic_and_depends_on_every_input() {
        let seed = [0u8; 32];
        let base = ring::position_of_slot(&slot_id(&[1; 32], 0), 5, &seed).value();
        assert_eq!(base, ring::position_of_slot(&slot_id(&[1; 32], 0), 5, &seed).value());
        assert_ne!(base, ring::position_of_slot(&slot_id(&[2; 32], 0), 5, &seed).value(), "SID");
        assert_ne!(base, ring::position_of_slot(&slot_id(&[1; 32], 1), 5, &seed).value(), "枠の番号");
        assert_ne!(base, ring::position_of_slot(&slot_id(&[1; 32], 0), 6, &seed).value(), "pow_nonce");
        assert_ne!(base, ring::position_of_slot(&slot_id(&[1; 32], 0), 5, &[1; 32]).value(), "epoch_seed");
    }

    #[test]
    fn slot_position_is_not_the_relay_position() {
        // タグを変えてあるので、同じ 32 バイトでも同じ位置にならない
        let bytes = [3u8; 32];
        let seed = [0u8; 32];
        assert_ne!(
            ring::position_of_slot(&bytes, 1, &seed).value(),
            ring::position_of_node(&NodeId(bytes), 1, &seed).value()
        );
    }

    #[test]
    fn encoded_size_for_typical_shapes() {
        // 大きさの目安（失敗しない。cargo test -- --nocapture で見る）
        let id = Identity::generate();
        for slots in [1u32, 8] {
            let lease = lease_with(&id, slots, 3, NOW);
            println!("leaseSet (受け口 3, 枠 {}): {} bytes", slots, bincode::serialize(&lease).unwrap().len());
        }
    }
}
