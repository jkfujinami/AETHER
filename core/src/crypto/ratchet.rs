//! Double Ratchet — 前方秘匿と break-in recovery (Phase 3-1)
//!
//! # 何を守るか（脅威モデル＝押収）
//!
//! AETHER の脅威は「監視ノード→IP特定→**押収**→フォレンジック」。
//! 事前共有秘密のままだと、**端末を1台押収された瞬間に過去の全通信が復号される**。
//! Double Ratchet は各メッセージごとに鍵を前進させ、使った鍵を捨てるので:
//!
//! - **前方秘匿 (forward secrecy):** 今この鍵を押収されても、**過去**のメッセージは
//!   復号できない（過去の鍵は削除済み・KDF は一方向で遡れない）。
//! - **break-in recovery:** DH ラチェット（往復ごとに新しい X25519 鍵を交換）により、
//!   一度状態が漏れても、次の往復で秘匿性が回復する。
//!
//! # Signal 仕様に忠実
//!
//! [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) の
//! アルゴリズムをそのまま実装している。KDF_RK=HKDF-SHA256、KDF_CK=HMAC-SHA256、
//! メッセージ暗号は ChaCha20-Poly1305。順不同・取りこぼしは skipped message key で扱う。
//!
//! # AETHER への組み込み（この先）
//!
//! 状態は serde で**連絡先ごとに永続化**する（KeyStore）。初期共有秘密は当面
//! 既存の事前共有秘密（`--secret`）or X3DH（未実装）の出力を使う。
//! メッセージ本文の暗号鍵をラチェット鍵にし、Hint の認識（blind_tag）とは分離する。

use crate::crypto::cipher;
use crate::error::{AetherError, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

/// 順不同で溜められる skipped message key の上限（DoS 対策）
///
/// 攻撃者が巨大な `n` を持つヘッダを送ると、正直な受信者が
/// その数だけ鍵を導出させられる。上限を超えたら拒否する。
pub const MAX_SKIP: u32 = 1000;

/// メッセージヘッダ（平文で付く）
///
/// 受信者は `dh`（送信者の現在のラチェット公開鍵）で DH ラチェットの要否を判断し、
/// `n` でチェーン上の位置を、`pn` で前チェーンの長さ（取りこぼし埋め）を知る。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// 送信者の現在のラチェット公開鍵
    pub dh: [u8; 32],
    /// 前の送信チェーンのメッセージ数（DH ラチェット跨ぎの取りこぼし用）
    pub pn: u32,
    /// この送信チェーンでのメッセージ番号
    pub n: u32,
}

impl Header {
    fn encode(&self) -> Vec<u8> {
        // AD に連結するので、決定論的でコンパクトな固定長表現にする
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(&self.dh);
        out.extend_from_slice(&self.pn.to_be_bytes());
        out.extend_from_slice(&self.n.to_be_bytes());
        out
    }
}

/// Double Ratchet の状態（連絡先ごとに1つ・serde で永続化）
#[derive(Clone, Serialize, Deserialize)]
pub struct Ratchet {
    /// 自分の現在のラチェット秘密鍵（バイト保持で serde 可能に）
    dhs_secret: [u8; 32],
    /// 相手の現在のラチェット公開鍵（未受信なら None）
    dhr: Option<[u8; 32]>,
    /// ルート鍵
    rk: [u8; 32],
    /// 送信チェーン鍵
    cks: Option<[u8; 32]>,
    /// 受信チェーン鍵
    ckr: Option<[u8; 32]>,
    /// 送信メッセージ番号
    ns: u32,
    /// 受信メッセージ番号
    nr: u32,
    /// 前送信チェーンの長さ
    pn: u32,
    /// 取りこぼした message key: (相手ラチェット公開鍵, n) -> mk
    skipped: HashMap<([u8; 32], u32), [u8; 32]>,
}

/// 新しいラチェット鍵ペア `(secret, public)` を生成する
///
/// Bob 役は最初にこれで初期ラチェット鍵を作り、`public` を相手へ公開（プレキー）、
/// `secret` を [`Ratchet::init_bob`] に渡す。Alice 役は相手の `public` を
/// [`Ratchet::init_alice`] に渡す。
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    generate_dh()
}

/// 新しいラチェット鍵ペアを生成する（内部用）
fn generate_dh() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

fn dh(secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*secret)
        .diffie_hellman(&PublicKey::from(*peer_public))
        .to_bytes()
}

/// KDF_RK: ルート鍵と DH 出力から新しい (ルート鍵, チェーン鍵)
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(b"aether_ratchet_rk_v1", &mut okm)
        .expect("64 <= 255*32");
    let mut new_rk = [0u8; 32];
    let mut new_ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[0..32]);
    new_ck.copy_from_slice(&okm[32..64]);
    (new_rk, new_ck)
}

/// KDF_CK: チェーン鍵から新しい (チェーン鍵, メッセージ鍵)
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("HMAC any key length");
    mac.update(&[0x01]);
    let mk: [u8; 32] = mac.finalize().into_bytes().into();

    let mut mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("HMAC any key length");
    mac.update(&[0x02]);
    let next_ck: [u8; 32] = mac.finalize().into_bytes().into();

    (next_ck, mk)
}

/// メッセージ鍵から (暗号鍵, nonce) を導出する
fn message_keys(mk: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(None, mk);
    let mut okm = [0u8; 44];
    hk.expand(b"aether_ratchet_msg_v1", &mut okm)
        .expect("44 <= 255*32");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[0..32]);
    nonce.copy_from_slice(&okm[32..44]);
    (key, nonce)
}

fn encrypt(mk: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    let (key, nonce) = message_keys(mk);
    cipher::encrypt_with_aad(&key, &nonce, plaintext, ad)
}

fn decrypt(mk: &[u8; 32], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    let (key, nonce) = message_keys(mk);
    cipher::decrypt_with_aad(&key, &nonce, ciphertext, ad)
}

impl Ratchet {
    /// 送信側（Alice）を初期化する
    ///
    /// `sk` は初期共有秘密（X3DH or 事前共有）。`bob_public` は相手が公開している
    /// 初期ラチェット公開鍵。Alice は最初の送信でこの鍵に向けて DH ラチェットする。
    pub fn init_alice(sk: &[u8; 32], bob_public: &[u8; 32]) -> Self {
        let (dhs_secret, _dhs_public) = generate_dh();
        let (rk, cks) = kdf_rk(sk, &dh(&dhs_secret, bob_public));
        Self {
            dhs_secret,
            dhr: Some(*bob_public),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    /// 受信側（Bob）を初期化する
    ///
    /// `sk` は初期共有秘密、`bob_keypair` は Alice に渡した初期ラチェット鍵ペアの秘密。
    /// Bob は最初の受信で Alice の公開鍵を受け取って DH ラチェットを回す。
    pub fn init_bob(sk: &[u8; 32], bob_secret: &[u8; 32]) -> Self {
        Self {
            dhs_secret: *bob_secret,
            dhr: None,
            rk: *sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    /// この状態の現在のラチェット公開鍵（Bob 初期鍵の公開・相手への広告に使う）
    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(self.dhs_secret)).to_bytes()
    }

    /// 暗号化して (ヘッダ, 暗号文) を返す
    ///
    /// **使ったメッセージ鍵はここで破棄される**（チェーン鍵だけ前進し、mk は残さない）。
    /// これが前方秘匿の要。
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<(Header, Vec<u8>)> {
        let cks = self
            .cks
            .ok_or_else(|| AetherError::Crypto("ratchet has no sending chain".into()))?;
        let (next_cks, mk) = kdf_ck(&cks);
        self.cks = Some(next_cks);

        let header = Header {
            dh: self.public_key(),
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;

        let mut ad = associated_data.to_vec();
        ad.extend_from_slice(&header.encode());
        let ciphertext = encrypt(&mk, plaintext, &ad)?;
        Ok((header, ciphertext))
    }

    /// 復号する（順不同・DH ラチェット跨ぎを含む）
    pub fn decrypt(
        &mut self,
        header: &Header,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ad = associated_data.to_vec();
        ad.extend_from_slice(&header.encode());

        // 1) 既に取りこぼしとして控えてある鍵で開けるか
        if let Some(pt) = self.try_skipped(header, ciphertext, &ad)? {
            return Ok(pt);
        }

        // 2) 新しい相手ラチェット鍵なら DH ラチェットを回す（前チェーンの取りこぼしも埋める）
        if self.dhr.as_ref() != Some(&header.dh) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header)?;
        }

        // 3) このチェーン上でヘッダの n まで取りこぼしを埋める
        self.skip_message_keys(header.n)?;

        // 4) 受信チェーンを1つ前進させて開く
        let ckr = self
            .ckr
            .ok_or_else(|| AetherError::Crypto("ratchet has no receiving chain".into()))?;
        let (next_ckr, mk) = kdf_ck(&ckr);
        self.ckr = Some(next_ckr);
        self.nr += 1;

        decrypt(&mk, ciphertext, &ad)
    }

    fn try_skipped(
        &mut self,
        header: &Header,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let key = (header.dh, header.n);
        if let Some(mk) = self.skipped.get(&key).copied() {
            let pt = decrypt(&mk, ciphertext, ad)?;
            self.skipped.remove(&key);
            return Ok(Some(pt));
        }
        Ok(None)
    }

    /// 受信チェーンを `until` まで進め、飛ばした鍵を控える
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if self.nr + MAX_SKIP < until {
            return Err(AetherError::Crypto(format!(
                "ratchet skip too large: {} (nr={}, max={})",
                until, self.nr, MAX_SKIP
            )));
        }
        if let Some(mut ckr) = self.ckr {
            let dhr = self.dhr.expect("ckr implies dhr is set");
            while self.nr < until {
                let (next_ckr, mk) = kdf_ck(&ckr);
                self.skipped.insert((dhr, self.nr), mk);
                ckr = next_ckr;
                self.nr += 1;
            }
            self.ckr = Some(ckr);
        }
        Ok(())
    }

    /// DH ラチェットを1段回す（往復ごとに新しい X25519 鍵）
    fn dh_ratchet(&mut self, header: &Header) -> Result<()> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dh);

        let (rk, ckr) = kdf_rk(&self.rk, &dh(&self.dhs_secret, &header.dh));
        self.rk = rk;
        self.ckr = Some(ckr);

        let (new_secret, _new_public) = generate_dh();
        self.dhs_secret = new_secret;

        let (rk, cks) = kdf_rk(&self.rk, &dh(&self.dhs_secret, &header.dh));
        self.rk = rk;
        self.cks = Some(cks);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Alice/Bob を初期共有秘密から立ち上げる。Bob の初期鍵ペアを Alice へ渡す想定。
    fn pair() -> (Ratchet, Ratchet) {
        let sk = [0x42u8; 32];
        let (bob_secret, bob_public) = generate_dh();
        let alice = Ratchet::init_alice(&sk, &bob_public);
        let bob = Ratchet::init_bob(&sk, &bob_secret);
        (alice, bob)
    }

    #[test]
    fn basic_send_and_receive() {
        let (mut alice, mut bob) = pair();
        let (h, ct) = alice.encrypt(b"hello bob", b"ad").unwrap();
        let pt = bob.decrypt(&h, &ct, b"ad").unwrap();
        assert_eq!(pt, b"hello bob");
    }

    #[test]
    fn back_and_forth_conversation() {
        let (mut alice, mut bob) = pair();

        let (h1, c1) = alice.encrypt(b"a1", b"").unwrap();
        assert_eq!(bob.decrypt(&h1, &c1, b"").unwrap(), b"a1");

        let (h2, c2) = bob.encrypt(b"b1", b"").unwrap();
        assert_eq!(alice.decrypt(&h2, &c2, b"").unwrap(), b"b1");

        let (h3, c3) = alice.encrypt(b"a2", b"").unwrap();
        assert_eq!(bob.decrypt(&h3, &c3, b"").unwrap(), b"a2");

        let (h4, c4) = bob.encrypt(b"b2", b"").unwrap();
        assert_eq!(alice.decrypt(&h4, &c4, b"").unwrap(), b"b2");
    }

    #[test]
    fn out_of_order_delivery_within_a_chain() {
        // 同じ送信チェーンの 3 通を逆順で受け取っても、skipped key で全部開ける
        let (mut alice, mut bob) = pair();
        let (h0, c0) = alice.encrypt(b"m0", b"").unwrap();
        let (h1, c1) = alice.encrypt(b"m1", b"").unwrap();
        let (h2, c2) = alice.encrypt(b"m2", b"").unwrap();

        assert_eq!(bob.decrypt(&h2, &c2, b"").unwrap(), b"m2");
        assert_eq!(bob.decrypt(&h0, &c0, b"").unwrap(), b"m0");
        assert_eq!(bob.decrypt(&h1, &c1, b"").unwrap(), b"m1");
    }

    #[test]
    fn out_of_order_across_dh_ratchet() {
        // Alice→Bob(m0)、Bob→Alice、Alice→Bob(m1: 新チェーン) を順不同で
        let (mut alice, mut bob) = pair();
        let (h0, c0) = alice.encrypt(b"m0", b"").unwrap();
        assert_eq!(bob.decrypt(&h0, &c0, b"").unwrap(), b"m0");

        let (hb, cb) = bob.encrypt(b"reply", b"").unwrap();
        assert_eq!(alice.decrypt(&hb, &cb, b"").unwrap(), b"reply");

        // Alice が DH ラチェット後に 2 通
        let (h1, c1) = alice.encrypt(b"n0", b"").unwrap();
        let (h2, c2) = alice.encrypt(b"n1", b"").unwrap();
        // 逆順で届く
        assert_eq!(bob.decrypt(&h2, &c2, b"").unwrap(), b"n1");
        assert_eq!(bob.decrypt(&h1, &c1, b"").unwrap(), b"n0");
    }

    #[test]
    fn dh_public_key_changes_each_round_break_in_recovery() {
        // 往復ごとに送信ラチェット公開鍵が変わる = DH ラチェットが回っている証拠
        let (mut alice, mut bob) = pair();

        let (h1, c1) = alice.encrypt(b"a1", b"").unwrap();
        bob.decrypt(&h1, &c1, b"").unwrap();

        let (h2, c2) = bob.encrypt(b"b1", b"").unwrap();
        alice.decrypt(&h2, &c2, b"").unwrap(); // Alice が Bob の新鍵で DH ラチェット

        let (h3, _c3) = alice.encrypt(b"a2", b"").unwrap();

        assert_ne!(h1.dh, h2.dh, "Alice と Bob のラチェット鍵は別物");
        assert_ne!(
            h1.dh, h3.dh,
            "往復後、Alice の送信鍵は DH ラチェットで更新される（break-in recovery）"
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut alice, mut bob) = pair();
        let (h, mut ct) = alice.encrypt(b"secret", b"ad").unwrap();
        ct[0] ^= 0xFF;
        assert!(bob.decrypt(&h, &ct, b"ad").is_err(), "改竄は AEAD が弾く");
    }

    #[test]
    fn wrong_associated_data_is_rejected() {
        let (mut alice, mut bob) = pair();
        let (h, ct) = alice.encrypt(b"secret", b"ad-1").unwrap();
        assert!(bob.decrypt(&h, &ct, b"ad-2").is_err(), "AD 不一致は弾く");
    }

    #[test]
    fn excessive_skip_is_rejected() {
        // 巨大な n を送りつけて鍵導出させる DoS を拒否する
        let (mut alice, mut bob) = pair();
        // まず1通で受信チェーンを立てる
        let (h0, c0) = alice.encrypt(b"m0", b"").unwrap();
        assert_eq!(bob.decrypt(&h0, &c0, b"").unwrap(), b"m0");

        // 同チェーンで n を極端に飛ばしたヘッダを捏造
        let mut evil = h0.clone();
        evil.n = MAX_SKIP + 10;
        assert!(
            bob.decrypt(&evil, &c0, b"").is_err(),
            "MAX_SKIP を超える取りこぼし要求は拒否する"
        );
    }

    #[test]
    fn state_survives_serde_roundtrip() {
        // 連絡先ごとの永続化（KeyStore）に必要
        let (mut alice, mut bob) = pair();
        let (h1, c1) = alice.encrypt(b"before", b"").unwrap();
        bob.decrypt(&h1, &c1, b"").unwrap();

        let bytes = bincode::serialize(&bob).unwrap();
        let mut restored: Ratchet = bincode::deserialize(&bytes).unwrap();

        let (h2, c2) = alice.encrypt(b"after", b"").unwrap();
        assert_eq!(
            restored.decrypt(&h2, &c2, b"").unwrap(),
            b"after",
            "永続化から復元したラチェットで復号が続けられる"
        );
    }

    #[test]
    fn forward_secrecy_old_message_keys_are_gone() {
        // 送信後、ラチェットの状態からは過去のメッセージ鍵を再構成できない。
        // 具体的には送信チェーン鍵が前進し、古い ck が残っていないことを確認する。
        let (mut alice, _bob) = pair();
        let cks_before = alice.cks;
        let (_h, _c) = alice.encrypt(b"m", b"").unwrap();
        let cks_after = alice.cks;
        assert_ne!(cks_before, cks_after, "送信のたびにチェーン鍵は前進する");
        // KDF は一方向なので after から before は復元できない（= 過去鍵に遡れない）
    }
}
