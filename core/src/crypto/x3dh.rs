//! X3DH — 非同期の初期鍵合意 (Phase 3-1)
//!
//! # 何のためか
//!
//! Double Ratchet を始めるには両者が共有する初期秘密 `SK` が要る。今は `--secret` を
//! **手渡し**しているが、これは運用が苦しく、鍵配送そのものが攻撃面になる。
//! X3DH は「相手がオフラインでも」初期秘密を安全に確立する（Signal の初回鍵合意）。
//!
//! - Bob は事前に**プレキー束**（署名付きプレキー＋任意の使い捨てプレキー）を公開しておく。
//! - Alice はそれを取ってきて `SK` を計算し、最初のメッセージに自分の公開鍵を添える。
//! - Bob は後からそれを見て同じ `SK` を復元する。
//!
//! # 得られる性質
//!
//! - **相互認証**: 双方の**恒久 ID 鍵**（AETHER の NodeId 由来 X25519）が DH に入る。
//! - **前方秘匿**: Alice の一時鍵 / Bob の使い捨てプレキーが入るので、恒久鍵が後で
//!   漏れても、この初回秘密は復元されない。
//! - **否認可能性**: 署名は SK でなく**プレキー**にだけ掛かる。会話内容の署名は残らない。
//!
//! # AETHER への組み込み（配線側）
//!
//! Bob のプレキー束は索引/連絡先発見で配る。得た `SK` を
//! [`crate::crypto::ratchet::Ratchet::init_alice`] / `init_bob` に渡し、Bob の
//! **署名付きプレキー**をそのままラチェットの初期鍵として使う（Signal と同じ）。

use crate::crypto::identity::{verify_signature, Identity, NodeId};
use crate::error::{AetherError, Result};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Bob が公開するプレキー束
///
/// `signed_prekey` は Bob の NodeId（Ed25519）で署名されている。これがラチェットの
/// 初期鍵も兼ねる。`one_time_prekey` は1回使い切りで前方秘匿を強める（任意）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// Bob の恒久 ID 鍵（X25519 公開・NodeId から導出）
    pub identity_key: [u8; 32],
    /// Bob の NodeId（署名検証に使う）
    pub node_id: NodeId,
    /// 署名付きプレキー（X25519 公開）。ラチェット初期鍵も兼ねる
    pub signed_prekey: [u8; 32],
    /// **署名付きプレキー・KEM 公開鍵・ID 鍵をまとめて覆う** Ed25519 署名（署名者 = `node_id`）
    ///
    /// KEM 公開鍵まで署名で縛らないと、MITM が KEM 公開鍵だけ差し替えて
    /// 耐量子の片肺を無力化できる。3つ全部を1つの署名で認証する。
    pub signed_prekey_sig: Vec<u8>,
    /// 使い捨てプレキー（X25519 公開・任意）
    pub one_time_prekey: Option<[u8; 32]>,
    /// ML-KEM (Kyber768) 公開鍵 ── 耐量子ハイブリッドの片肺（3-1 ④）
    pub kem_public: Vec<u8>,
}

/// Bob が手元に保持するプレキーの秘密鍵（KeyStore に置く）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeySecrets {
    /// 署名付きプレキーの秘密（＝ラチェット初期鍵の秘密）
    pub signed_prekey_secret: [u8; 32],
    /// 使い捨てプレキーの秘密（使ったら消す）
    pub one_time_prekey_secret: Option<[u8; 32]>,
    /// ML-KEM (Kyber768) 秘密鍵（耐量子ハイブリッド用）
    pub kem_secret: Vec<u8>,
}

/// Alice が最初のメッセージに添える鍵情報
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialMessage {
    /// Alice の NodeId（Ed25519）。Bob が差出人を特定し ID 鍵の整合を検証する
    pub initiator_node_id: NodeId,
    /// Alice の恒久 ID 鍵（X25519 公開）
    pub identity_key: [u8; 32],
    /// Alice の一時鍵（X25519 公開）
    pub ephemeral_key: [u8; 32],
    /// どの使い捨てプレキーを使ったか（Bob が特定して消すため）
    pub used_one_time_prekey: Option<[u8; 32]>,
    /// Bob の ML-KEM 公開鍵へ encapsulate した暗号文（耐量子ハイブリッド用）
    pub kem_ciphertext: Vec<u8>,
}

fn new_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    (secret.to_bytes(), PublicKey::from(&secret).to_bytes())
}

fn dh(secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*secret)
        .diffie_hellman(&PublicKey::from(*peer_public))
        .to_bytes()
}

/// DH 群を KDF して SK を出す
///
/// Signal に倣い、曲線を跨いだ混同を防ぐため先頭に `F = 0xFF * 32` を置く。
fn kdf_sk(dhs: &[[u8; 32]]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + dhs.len() * 32);
    ikm.extend_from_slice(&[0xFFu8; 32]);
    for d in dhs {
        ikm.extend_from_slice(d);
    }
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut sk = [0u8; 32];
    hk.expand(b"aether_x3dh_v1", &mut sk).expect("32 <= 255*32");
    sk
}

/// 署名で認証する対象：署名付きプレキー ‖ KEM 公開鍵 ‖ ID 鍵
///
/// この3つはすべて DH / KEM に入る。どれか1つでも MITM に差し替えられると
/// 認証・耐量子が崩れるので、まとめて1つの署名で縛る。
fn signed_transcript(signed_prekey: &[u8; 32], kem_public: &[u8], identity_key: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(32 + kem_public.len() + 32);
    t.extend_from_slice(b"aether_x3dh_prekeys_v1");
    t.extend_from_slice(signed_prekey);
    t.extend_from_slice(kem_public);
    t.extend_from_slice(identity_key);
    t
}

/// Bob 役：プレキー束と、その秘密を生成する
///
/// `with_one_time` が true なら使い捨てプレキーも1つ含める（前方秘匿が強まる）。
pub fn generate_prekeys(identity: &Identity, with_one_time: bool) -> (PreKeyBundle, PreKeySecrets) {
    let (spk_secret, spk_public) = new_keypair();

    let (opk_secret, opk_public) = if with_one_time {
        let (s, p) = new_keypair();
        (Some(s), Some(p))
    } else {
        (None, None)
    };

    // 耐量子ハイブリッドの片肺：ML-KEM (Kyber768) 鍵ペア
    let (kem_pk, kem_sk) = kyber768::keypair();

    let identity_key = identity_x25519_public(identity);
    // 署名付きプレキー・KEM 公開鍵・ID 鍵をまとめて署名する（KEM も認証する）
    let signed_prekey_sig = identity.sign(&signed_transcript(
        &spk_public,
        kem_pk.as_bytes(),
        &identity_key,
    ));

    let bundle = PreKeyBundle {
        identity_key,
        node_id: identity.public_id(),
        signed_prekey: spk_public,
        signed_prekey_sig,
        one_time_prekey: opk_public,
        kem_public: kem_pk.as_bytes().to_vec(),
    };
    let secrets = PreKeySecrets {
        signed_prekey_secret: spk_secret,
        one_time_prekey_secret: opk_secret,
        kem_secret: kem_sk.as_bytes().to_vec(),
    };
    (bundle, secrets)
}

/// Alice 役：Bob の束から `SK` と最初のメッセージ用鍵情報を作る
///
/// `expected` は**こちらが繋ぎたい相手の NodeId**。束が自称する `node_id` ではなく
/// これで検証する（自称を信じると MITM が自己署名した束を通せる）。
/// 署名は署名付きプレキー・KEM 公開鍵・ID 鍵の3点を覆う。1つでも合わなければ拒否。
pub fn initiate(
    alice: &Identity,
    expected: &NodeId,
    bundle: &PreKeyBundle,
) -> Result<([u8; 32], InitialMessage)> {
    if bundle.node_id != *expected {
        return Err(AetherError::Crypto(
            "X3DH: prekey bundle is for a different NodeId".into(),
        ));
    }
    let transcript =
        signed_transcript(&bundle.signed_prekey, &bundle.kem_public, &bundle.identity_key);
    verify_signature(expected, &transcript, &bundle.signed_prekey_sig)
        .map_err(|_| AetherError::Crypto("X3DH: prekey bundle signature invalid".into()))?;

    let ik_a_secret = alice.x25519_secret().to_bytes();
    let (ek_secret, ek_public) = new_keypair();

    // DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B), DH4 = DH(EK_A, OPK_B)
    let mut secrets = vec![
        dh(&ik_a_secret, &bundle.signed_prekey),
        dh(&ek_secret, &bundle.identity_key),
        dh(&ek_secret, &bundle.signed_prekey),
    ];
    if let Some(opk) = bundle.one_time_prekey {
        secrets.push(dh(&ek_secret, &opk));
    }

    // 耐量子ハイブリッド：Bob の ML-KEM 公開鍵へ encapsulate し、共有秘密を混ぜる。
    // X25519 が量子で破れても、この KEM 秘密が残るので SK は守られる（逆も然り）。
    let kem_pk = kyber768::PublicKey::from_bytes(&bundle.kem_public)
        .map_err(|_| AetherError::Crypto("X3DH: invalid KEM public key".into()))?;
    let (kem_ss, kem_ct) = kyber768::encapsulate(&kem_pk);
    secrets.push(kem_ss.as_bytes().try_into().expect("kyber768 ss は 32 バイト"));

    let sk = kdf_sk(&secrets);

    let msg = InitialMessage {
        initiator_node_id: alice.public_id(),
        identity_key: identity_x25519_public(alice),
        ephemeral_key: ek_public,
        used_one_time_prekey: bundle.one_time_prekey,
        kem_ciphertext: kem_ct.as_bytes().to_vec(),
    };
    Ok((sk, msg))
}

/// Bob 役：Alice の最初のメッセージから同じ `SK` を復元する
///
/// Alice の恒久 ID 鍵（X25519）が自称 NodeId から導出したものと一致するか検証する
/// （NodeId と ID 鍵の食い違いを弾く）。DH2/DH4 に入るのはこの `identity_key` なので、
/// MITM が差し替えても最終的に SK が食い違い Bob の復号は失敗する ── ここで先に弾く。
pub fn respond(bob: &Identity, secrets: &PreKeySecrets, msg: &InitialMessage) -> Result<[u8; 32]> {
    let claimed_ik = crate::crypto::identity::x25519_public_from_node_id(&msg.initiator_node_id)?;
    if claimed_ik != msg.identity_key {
        return Err(AetherError::Crypto(
            "X3DH: initiator identity key does not match its NodeId".into(),
        ));
    }

    let ik_b_secret = bob.x25519_secret().to_bytes();

    // Alice と同じ DH を対称に計算する
    let mut shared = vec![
        dh(&secrets.signed_prekey_secret, &msg.identity_key), // DH1
        dh(&ik_b_secret, &msg.ephemeral_key),                 // DH2
        dh(&secrets.signed_prekey_secret, &msg.ephemeral_key), // DH3
    ];
    if msg.used_one_time_prekey.is_some() {
        let opk_secret = secrets.one_time_prekey_secret.ok_or_else(|| {
            AetherError::Crypto("X3DH: initiator used a one-time prekey Bob does not have".into())
        })?;
        shared.push(dh(&opk_secret, &msg.ephemeral_key)); // DH4
    }

    // 耐量子ハイブリッド：Alice の暗号文を自分の ML-KEM 秘密鍵で decapsulate
    let kem_sk = kyber768::SecretKey::from_bytes(&secrets.kem_secret)
        .map_err(|_| AetherError::Crypto("X3DH: invalid KEM secret key".into()))?;
    let kem_ct = kyber768::Ciphertext::from_bytes(&msg.kem_ciphertext)
        .map_err(|_| AetherError::Crypto("X3DH: invalid KEM ciphertext".into()))?;
    let kem_ss = kyber768::decapsulate(&kem_ct, &kem_sk);
    shared.push(kem_ss.as_bytes().try_into().expect("kyber768 ss は 32 バイト"));

    Ok(kdf_sk(&shared))
}

/// Identity の X25519 公開鍵
fn identity_x25519_public(identity: &Identity) -> [u8; 32] {
    PublicKey::from(&identity.x25519_secret()).to_bytes()
}

/// 私信本体のフレーム tag：初回接触（X3DH の InitialMessage を同梱）
const FRAME_INITIAL: u8 = 0x01;
/// 私信本体のフレーム tag：継続（ラチェットのみ）
const FRAME_CONTINUATION: u8 = 0x00;

/// 初回接触の本体をフレーム化する: `[0x01][InitialMessage][sealed]`
///
/// mailbox が運ぶ本体の先頭に、受信者が `SK` を復元するための [`InitialMessage`] を前置する。
/// `sealed` は [`Session::seal`](crate::crypto::session::Session::seal) の出力。
pub fn frame_initial(init: &InitialMessage, sealed: &[u8]) -> Result<Vec<u8>> {
    let init_bytes =
        bincode::serialize(init).map_err(|e| AetherError::Serialization(e.to_string()))?;
    let mut out = Vec::with_capacity(1 + init_bytes.len() + sealed.len());
    out.push(FRAME_INITIAL);
    out.extend_from_slice(&init_bytes);
    out.extend_from_slice(sealed);
    Ok(out)
}

/// 継続の本体をフレーム化する: `[0x00][sealed]`
pub fn frame_continuation(sealed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + sealed.len());
    out.push(FRAME_CONTINUATION);
    out.extend_from_slice(sealed);
    out
}

/// 私信本体のフレームを分解する
///
/// 返り値は `(初回接触なら Some(InitialMessage), sealed 本体)`。継続なら `None`。
pub fn parse_frame(body: &[u8]) -> Result<(Option<InitialMessage>, &[u8])> {
    let (&tag, rest) = body
        .split_first()
        .ok_or_else(|| AetherError::Protocol("empty private body frame".into()))?;
    match tag {
        FRAME_CONTINUATION => Ok((None, rest)),
        FRAME_INITIAL => {
            let mut cursor = std::io::Cursor::new(rest);
            let init: InitialMessage = bincode::deserialize_from(&mut cursor)
                .map_err(|e| AetherError::Protocol(format!("invalid InitialMessage: {}", e)))?;
            let consumed = cursor.position() as usize;
            Ok((Some(init), &rest[consumed..]))
        }
        other => Err(AetherError::Protocol(format!(
            "unknown private body frame tag 0x{:02x}",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ratchet::Ratchet;

    #[test]
    fn alice_and_bob_derive_the_same_secret_with_one_time_prekey() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (bundle, secrets) = generate_prekeys(&bob, true);
        let (sk_a, msg) = initiate(&alice, &bob.public_id(), &bundle).unwrap();
        let sk_b = respond(&bob, &secrets, &msg).unwrap();

        assert_eq!(sk_a, sk_b, "X3DH の両者が同じ初期秘密に到達する");
    }

    #[test]
    fn works_without_one_time_prekey() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (bundle, secrets) = generate_prekeys(&bob, false);
        assert!(bundle.one_time_prekey.is_none());

        let (sk_a, msg) = initiate(&alice, &bob.public_id(), &bundle).unwrap();
        let sk_b = respond(&bob, &secrets, &msg).unwrap();
        assert_eq!(sk_a, sk_b);
    }

    #[test]
    fn different_pairs_get_different_secrets() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();

        let (bundle_b, _) = generate_prekeys(&bob, true);
        let (bundle_c, _) = generate_prekeys(&carol, true);

        let (sk_ab, _) = initiate(&alice, &bob.public_id(), &bundle_b).unwrap();
        let (sk_ac, _) = initiate(&alice, &carol.public_id(), &bundle_c).unwrap();
        assert_ne!(sk_ab, sk_ac, "相手が違えば初期秘密も違う");
    }

    #[test]
    fn forged_signed_prekey_is_rejected() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (mut bundle, _) = generate_prekeys(&bob, true);
        // 署名付きプレキーを差し替える（中間者が別の鍵を挿す想定）
        bundle.signed_prekey = [0x13; 32];

        assert!(
            initiate(&alice, &bob.public_id(), &bundle).is_err(),
            "署名の合わないプレキーは拒否する（中間者対策）"
        );
    }

    #[test]
    fn tampered_kem_public_is_rejected() {
        // KEM 公開鍵を差し替えると署名が合わなくなる（耐量子の片肺を守る）
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (mut bundle, _) = generate_prekeys(&bob, true);

        // 別の Kyber 公開鍵に差し替える
        let (other_pk, _) = kyber768::keypair();
        bundle.kem_public = other_pk.as_bytes().to_vec();

        assert!(
            initiate(&alice, &bob.public_id(), &bundle).is_err(),
            "署名で覆われた KEM 公開鍵の差し替えは拒否する"
        );
    }

    #[test]
    fn bundle_claiming_a_different_node_is_rejected() {
        // 自称 node_id ではなく、こちらが意図した相手で検証する
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();

        // Mallory が自分の束を「Bob 宛て」として渡してくる（自己署名は valid）
        let (bundle, _) = generate_prekeys(&mallory, true);

        assert!(
            initiate(&alice, &bob.public_id(), &bundle).is_err(),
            "意図した相手(Bob)でない束は拒否する（自己署名 MITM 対策）"
        );
    }

    #[test]
    fn respond_rejects_a_mismatched_initiator_node_id() {
        // init_msg の NodeId と ID 鍵が食い違えば弾く（NodeId と鍵の付け替え対策）
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();

        let (bundle, secrets) = generate_prekeys(&bob, true);
        let (_sk, mut msg) = initiate(&alice, &bob.public_id(), &bundle).unwrap();

        // NodeId だけ別人にすり替える（ID 鍵はそのまま）
        msg.initiator_node_id = mallory.public_id();

        assert!(
            respond(&bob, &secrets, &msg).is_err(),
            "NodeId と ID 鍵が食い違う初回メッセージは拒否する"
        );
    }

    #[test]
    fn bundle_survives_wire_roundtrip() {
        let bob = Identity::generate();
        let (bundle, _) = generate_prekeys(&bob, true);
        let bytes = bincode::serialize(&bundle).unwrap();
        let decoded: PreKeyBundle = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.signed_prekey, bundle.signed_prekey);
        assert_eq!(decoded.node_id, bundle.node_id);
    }

    #[test]
    fn kem_contributes_to_the_shared_secret() {
        // 耐量子ハイブリッド：KEM 暗号文を差し替えると SK が食い違う
        // （＝ KEM の共有秘密が確かに SK に混ざっている）
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (bundle, secrets) = generate_prekeys(&bob, true);
        let (sk_a, mut msg) = initiate(&alice, &bob.public_id(), &bundle).unwrap();

        // まず正規は一致
        assert_eq!(sk_a, respond(&bob, &secrets, &msg).unwrap());

        // KEM 暗号文を別の encapsulate 結果に差し替える → decapsulate 結果が変わり不一致
        let (bundle2, _) = generate_prekeys(&bob, true);
        let kem_pk2 = kyber768::PublicKey::from_bytes(&bundle2.kem_public).unwrap();
        let (_ss2, ct2) = kyber768::encapsulate(&kem_pk2);
        msg.kem_ciphertext = ct2.as_bytes().to_vec();

        assert_ne!(
            sk_a,
            respond(&bob, &secrets, &msg).unwrap(),
            "KEM 暗号文の差し替えで SK が変わる = KEM が SK に寄与している"
        );
    }

    #[test]
    fn bundle_carries_kyber_public_key() {
        let bob = Identity::generate();
        let (bundle, _) = generate_prekeys(&bob, true);
        // Kyber768 公開鍵は 1184 バイト
        assert_eq!(bundle.kem_public.len(), 1184, "Kyber768 公開鍵のサイズ");
    }

    #[test]
    fn private_body_frames_roundtrip() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (bundle, _) = generate_prekeys(&bob, false);
        let (_sk, init) = initiate(&alice, &bob.public_id(), &bundle).unwrap();

        // 初回接触フレーム: InitialMessage と sealed 本体が分離して戻る
        let sealed = b"sealed ratchet body";
        let framed = frame_initial(&init, sealed).unwrap();
        let (got_init, got_sealed) = parse_frame(&framed).unwrap();
        assert!(got_init.is_some(), "初回接触は InitialMessage を含む");
        assert_eq!(got_init.unwrap().initiator_node_id, alice.public_id());
        assert_eq!(got_sealed, sealed);

        // 継続フレーム: InitialMessage 無し
        let cont = frame_continuation(sealed);
        let (none_init, cont_sealed) = parse_frame(&cont).unwrap();
        assert!(none_init.is_none(), "継続は InitialMessage を含まない");
        assert_eq!(cont_sealed, sealed);
    }

    #[test]
    fn full_x3dh_over_frames_establishes_a_forward_secret_session() {
        // 送信〜受信の丸ごと：X3DH → SK → Session::initiator/responder → frame → 相手が復元
        use crate::crypto::session::Session;

        let alice = Identity::generate();
        let bob = Identity::generate();
        let (bundle, secrets) = generate_prekeys(&bob, false);

        // Alice: initiate → SK → Session、初回本文をフレーム化
        let (sk_a, init) = initiate(&alice, &bob.public_id(), &bundle).unwrap();
        let mut alice_session = Session::initiator(&sk_a, &bundle.signed_prekey, init.clone());
        let sealed1 = alice_session.seal(b"hello via x3dh", b"").unwrap();
        let framed1 = frame_initial(&init, &sealed1).unwrap();

        // Bob: フレームを分解 → respond で SK → Session → 復元
        let (got_init, got_sealed) = parse_frame(&framed1).unwrap();
        let init = got_init.unwrap();
        let sk_b = respond(&bob, &secrets, &init).unwrap();
        assert_eq!(sk_a, sk_b, "両者が同じ X3DH SK に到達");
        let mut bob_session =
            Session::responder(&sk_b, &secrets.signed_prekey_secret, init.ephemeral_key);
        assert_eq!(bob_session.open(got_sealed, b"").unwrap(), b"hello via x3dh");

        // 継続（2 通目）は Bob→Alice も含めて双方向に流れる
        let sealed2 = bob_session.seal(b"reply", b"").unwrap();
        let framed2 = frame_continuation(&sealed2);
        let (none, s2) = parse_frame(&framed2).unwrap();
        assert!(none.is_none());
        assert_eq!(alice_session.open(s2, b"").unwrap(), b"reply");
    }

    #[test]
    fn x3dh_bootstraps_a_ratchet_conversation() {
        // X3DH で SK を確立 → Bob の署名付きプレキーをラチェット初期鍵にして会話開始
        // これで「事前共有 --secret」を排除できる（3-1 の全体像）
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (bundle, secrets) = generate_prekeys(&bob, true);
        let bob_spk_pub = bundle.signed_prekey;
        let bob_spk_secret = secrets.signed_prekey_secret;

        let (sk_a, _msg) = initiate(&alice, &bob.public_id(), &bundle).unwrap();
        let sk_b = respond(&bob, &secrets, &_msg).unwrap();
        assert_eq!(sk_a, sk_b);

        // 署名付きプレキーがラチェットの初期鍵を兼ねる（Signal と同じ）
        let mut alice_ratchet = Ratchet::init_alice(&sk_a, &bob_spk_pub);
        let mut bob_ratchet = Ratchet::init_bob(&sk_b, &bob_spk_secret);

        let (h1, c1) = alice_ratchet.encrypt(b"first from x3dh", b"").unwrap();
        assert_eq!(bob_ratchet.decrypt(&h1, &c1, b"").unwrap(), b"first from x3dh");

        let (h2, c2) = bob_ratchet.encrypt(b"reply", b"").unwrap();
        assert_eq!(alice_ratchet.decrypt(&h2, &c2, b"").unwrap(), b"reply");
    }
}
