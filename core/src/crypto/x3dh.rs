//! X3DH — 非同期の初期鍵合意 (Phase 3-1)
//!
//! # 何のためか
//!
//! Double Ratchet を始めるには両者が共有する初期秘密 `SK` が要る。X3DH は「相手が
//! オフラインでも」初期秘密を安全に確立する（Signal の初回鍵合意）。
//!
//! - Bob は**招待**（署名付きプレキー＋ML-KEM 公開鍵）を作り、友だちコードに入れて手渡す。
//! - Alice はそれで `SK` を計算し、最初のメッセージに自分の公開鍵を添える。
//! - Bob は後からそれを見て同じ `SK` を復元し、使った招待の秘密を消す。
//!
//! # 招待は網に置かない
//!
//! 以前は Bob がプレキー束を網に置き、場所を NodeId から誰でも計算できた。束を作れるのは
//! 本人だけなので、束が現れた時刻は「本人が起動していた時刻」になる。公開のリレー一覧の
//! 出入りと突き合わせると、NodeId と IP が 1〜2 回の起動でつながった（Part 24 の L1）。
//! 置く時刻をずらしても情報は対数でしか減らない。
//!
//! 招待は友だちの NodeId を網の外で交換するときに一緒に渡す。網に置く出来事そのものが
//! 無いので、観測できるものが無い。初回の後は Double Ratchet が鍵を回すので、招待は二度と
//! 要らない。
//!
//! # 得られる性質
//!
//! - **相互認証**: 双方の**恒久 ID 鍵**（AETHER の NodeId 由来 X25519）が DH に入る。
//! - **初回メッセージの前方秘匿**: 招待の鍵は招待ごとに作り、受け取ったら消す（使い捨て）。
//!   恒久鍵が後で漏れても、この初回秘密は復元されない。
//! - **耐量子**: ML-KEM (Kyber768) の共有秘密も `SK` に混ぜる。KEM の鍵も招待ごとに使い捨て。
//! - **否認可能性**: 署名は `SK` でなく**招待**にだけ掛かる。会話内容の署名は残らない。

use crate::crypto::identity::{verify_signature, x25519_public_from_node_id, Identity, NodeId};
use crate::error::{AetherError, Result};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// 招待の形式の版
const INVITE_VERSION: u8 = 1;
/// ML-KEM (Kyber768) 公開鍵の長さ
const KEM_PUBLIC_LEN: usize = 1184;
/// Ed25519 署名の長さ
const SIGNATURE_LEN: usize = 64;
/// 招待のバイト列の長さ: 版 ‖ NodeId ‖ 署名付きプレキー ‖ 期限 ‖ KEM 公開鍵 ‖ 署名
pub const INVITE_LEN: usize = 1 + 32 + 32 + 8 + KEM_PUBLIC_LEN + SIGNATURE_LEN;

/// Bob が友だちコードに入れて手渡す招待（X3DH のプレキー束に当たる）
///
/// 鍵は招待ごとに作る。`signed_prekey` は招待を見分ける ID とラチェットの初期鍵を兼ねる。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// Bob の NodeId（署名者。ID 鍵もここから導く）
    pub node_id: NodeId,
    /// 署名付きプレキー（X25519 公開）
    pub signed_prekey: [u8; 32],
    /// ML-KEM (Kyber768) 公開鍵 ── 耐量子ハイブリッドの片肺
    pub kem_public: Vec<u8>,
    /// 期限（UNIX 秒）。過ぎた招待では初回接触を始めない
    pub expires_at: u64,
    /// NodeId ・署名付きプレキー・期限・KEM 公開鍵をまとめて覆う Ed25519 署名
    ///
    /// KEM 公開鍵まで署名で縛らないと、MITM が KEM 公開鍵だけ差し替えて
    /// 耐量子の片肺を無力化できる。
    pub signature: Vec<u8>,
}

/// Bob が手元に保持する招待の秘密（KeyStore に置き、受け取ったら消す）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteSecrets {
    /// 署名付きプレキーの秘密（＝ラチェット初期鍵の秘密）
    pub signed_prekey_secret: [u8; 32],
    /// ML-KEM (Kyber768) 秘密鍵
    pub kem_secret: Vec<u8>,
    /// 招待の期限（期限を過ぎても、届くのが遅れた初回メッセージのために少し残す）
    pub expires_at: u64,
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
    /// どの招待を使ったか（招待の署名付きプレキー。Bob が秘密を引いて消すため）
    pub invite_key: [u8; 32],
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
    hk.expand(b"aether_x3dh_v2", &mut sk).expect("32 <= 255*32");
    sk
}

impl Invite {
    /// 署名で認証する対象：NodeId ‖ 署名付きプレキー ‖ 期限 ‖ KEM 公開鍵
    fn transcript(&self) -> Vec<u8> {
        let mut t = Vec::with_capacity(32 + 32 + 8 + self.kem_public.len() + 32);
        t.extend_from_slice(b"aether_x3dh_invite_v1");
        t.extend_from_slice(self.node_id.as_bytes());
        t.extend_from_slice(&self.signed_prekey);
        t.extend_from_slice(&self.expires_at.to_be_bytes());
        t.extend_from_slice(&self.kem_public);
        t
    }

    /// 署名と期限を確かめる
    ///
    /// `expected` は**こちらが繋ぎたい相手の NodeId**。招待が自称する `node_id` ではなく
    /// これで検証する（自称を信じると MITM が自己署名した招待を通せる）。
    pub fn verify(&self, expected: &NodeId, now: u64) -> Result<()> {
        if self.node_id != *expected {
            return Err(AetherError::Crypto("X3DH: invite is for a different NodeId".into()));
        }
        verify_signature(expected, &self.transcript(), &self.signature)
            .map_err(|_| AetherError::Crypto("X3DH: invite signature invalid".into()))?;
        if now >= self.expires_at {
            return Err(AetherError::Crypto("X3DH: invite expired".into()));
        }
        Ok(())
    }

    /// 友だちコードに入れるバイト列（固定長 [`INVITE_LEN`]）
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INVITE_LEN);
        out.push(INVITE_VERSION);
        out.extend_from_slice(self.node_id.as_bytes());
        out.extend_from_slice(&self.signed_prekey);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.kem_public);
        out.extend_from_slice(&self.signature);
        out
    }

    /// [`to_bytes`](Self::to_bytes) の逆。形だけ確かめる（署名は [`verify`](Self::verify) で）
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != INVITE_LEN {
            return Err(AetherError::Protocol(format!(
                "invite must be {} bytes, got {}",
                INVITE_LEN,
                bytes.len()
            )));
        }
        if bytes[0] != INVITE_VERSION {
            return Err(AetherError::Protocol(format!("unknown invite version {}", bytes[0])));
        }
        let take32 = |at: usize| -> [u8; 32] { bytes[at..at + 32].try_into().expect("32 バイト") };
        let kem_at = 1 + 32 + 32 + 8;
        Ok(Self {
            node_id: NodeId(take32(1)),
            signed_prekey: take32(33),
            expires_at: u64::from_be_bytes(bytes[65..73].try_into().expect("8 バイト")),
            kem_public: bytes[kem_at..kem_at + KEM_PUBLIC_LEN].to_vec(),
            signature: bytes[kem_at + KEM_PUBLIC_LEN..].to_vec(),
        })
    }
}

/// Bob 役：招待と、その秘密を作る（招待ごとに新しい鍵）
pub fn create_invite(identity: &Identity, expires_at: u64) -> (Invite, InviteSecrets) {
    let (spk_secret, spk_public) = new_keypair();
    let (kem_pk, kem_sk) = kyber768::keypair();

    let mut invite = Invite {
        node_id: identity.public_id(),
        signed_prekey: spk_public,
        kem_public: kem_pk.as_bytes().to_vec(),
        expires_at,
        signature: Vec::new(),
    };
    invite.signature = identity.sign(&invite.transcript());

    let secrets = InviteSecrets {
        signed_prekey_secret: spk_secret,
        kem_secret: kem_sk.as_bytes().to_vec(),
        expires_at,
    };
    (invite, secrets)
}

/// Alice 役：Bob の招待から `SK` と最初のメッセージ用鍵情報を作る
///
/// 招待は `expected`（こちらが繋ぎたい相手）で検証し、期限切れなら拒否する。
pub fn initiate(
    alice: &Identity,
    expected: &NodeId,
    invite: &Invite,
    now: u64,
) -> Result<([u8; 32], InitialMessage)> {
    invite.verify(expected, now)?;
    let ik_b = x25519_public_from_node_id(expected)?;

    let ik_a_secret = alice.x25519_secret().to_bytes();
    let (ek_secret, ek_public) = new_keypair();

    // DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B)
    // SPK は招待ごとの使い捨てなので、DH3 が Signal の使い捨てプレキー (DH4) の役も果たす
    let mut secrets = vec![
        dh(&ik_a_secret, &invite.signed_prekey),
        dh(&ek_secret, &ik_b),
        dh(&ek_secret, &invite.signed_prekey),
    ];

    // 耐量子ハイブリッド：Bob の ML-KEM 公開鍵へ encapsulate し、共有秘密を混ぜる。
    // X25519 が量子で破れても、この KEM 秘密が残るので SK は守られる（逆も然り）。
    let kem_pk = kyber768::PublicKey::from_bytes(&invite.kem_public)
        .map_err(|_| AetherError::Crypto("X3DH: invalid KEM public key".into()))?;
    let (kem_ss, kem_ct) = kyber768::encapsulate(&kem_pk);
    secrets.push(kem_ss.as_bytes().try_into().expect("kyber768 ss は 32 バイト"));

    let sk = kdf_sk(&secrets);

    let msg = InitialMessage {
        initiator_node_id: alice.public_id(),
        identity_key: identity_x25519_public(alice),
        ephemeral_key: ek_public,
        invite_key: invite.signed_prekey,
        kem_ciphertext: kem_ct.as_bytes().to_vec(),
    };
    Ok((sk, msg))
}

/// Bob 役：Alice の最初のメッセージから同じ `SK` を復元する
///
/// `secrets` は `msg.invite_key` の招待の秘密。Alice の恒久 ID 鍵（X25519）が自称 NodeId
/// から導出したものと一致するか検証する（NodeId と ID 鍵の食い違いを弾く）。
/// 期限はここでは見ない（期限の前に送られて遅れて届いた初回メッセージを開けるように）。
pub fn respond(bob: &Identity, secrets: &InviteSecrets, msg: &InitialMessage) -> Result<[u8; 32]> {
    let claimed_ik = x25519_public_from_node_id(&msg.initiator_node_id)?;
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

    const NOW: u64 = 1_800_000_000;
    const LATER: u64 = NOW + 3600;

    fn invite_of(bob: &Identity) -> (Invite, InviteSecrets) {
        create_invite(bob, LATER)
    }

    #[test]
    fn alice_and_bob_derive_the_same_secret() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (invite, secrets) = invite_of(&bob);
        let (sk_a, msg) = initiate(&alice, &bob.public_id(), &invite, NOW).unwrap();
        let sk_b = respond(&bob, &secrets, &msg).unwrap();

        assert_eq!(sk_a, sk_b, "X3DH の両者が同じ初期秘密に到達する");
        assert_eq!(msg.invite_key, invite.signed_prekey, "使った招待を Bob が引ける");
    }

    #[test]
    fn each_invite_has_fresh_keys() {
        // 招待ごとに鍵が違う ＝ 1 つの招待の秘密を消せば、その初回秘密は二度と復元できない
        let bob = Identity::generate();
        let (a, _) = invite_of(&bob);
        let (b, _) = invite_of(&bob);
        assert_ne!(a.signed_prekey, b.signed_prekey);
        assert_ne!(a.kem_public, b.kem_public);
    }

    #[test]
    fn another_invites_secrets_cannot_open_the_message() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (invite, _) = invite_of(&bob);
        let (_, other_secrets) = invite_of(&bob);

        let (sk_a, msg) = initiate(&alice, &bob.public_id(), &invite, NOW).unwrap();
        assert_ne!(sk_a, respond(&bob, &other_secrets, &msg).unwrap());
    }

    #[test]
    fn different_pairs_get_different_secrets() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();

        let (invite_b, _) = invite_of(&bob);
        let (invite_c, _) = invite_of(&carol);

        let (sk_ab, _) = initiate(&alice, &bob.public_id(), &invite_b, NOW).unwrap();
        let (sk_ac, _) = initiate(&alice, &carol.public_id(), &invite_c, NOW).unwrap();
        assert_ne!(sk_ab, sk_ac, "相手が違えば初期秘密も違う");
    }

    #[test]
    fn forged_signed_prekey_is_rejected() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (mut invite, _) = invite_of(&bob);
        // 署名付きプレキーを差し替える（中間者が別の鍵を挿す想定）
        invite.signed_prekey = [0x13; 32];

        assert!(
            initiate(&alice, &bob.public_id(), &invite, NOW).is_err(),
            "署名の合わないプレキーは拒否する（中間者対策）"
        );
    }

    #[test]
    fn tampered_kem_public_is_rejected() {
        // KEM 公開鍵を差し替えると署名が合わなくなる（耐量子の片肺を守る）
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (mut invite, _) = invite_of(&bob);

        let (other_pk, _) = kyber768::keypair();
        invite.kem_public = other_pk.as_bytes().to_vec();

        assert!(
            initiate(&alice, &bob.public_id(), &invite, NOW).is_err(),
            "署名で覆われた KEM 公開鍵の差し替えは拒否する"
        );
    }

    #[test]
    fn extended_expiry_is_rejected() {
        // 期限も署名で覆う（延ばした招待は通らない）
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (mut invite, _) = invite_of(&bob);
        invite.expires_at += 365 * 24 * 3600;
        assert!(initiate(&alice, &bob.public_id(), &invite, NOW).is_err());
    }

    #[test]
    fn expired_invite_is_rejected() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (invite, _) = invite_of(&bob);
        assert!(invite.verify(&bob.public_id(), LATER - 1).is_ok());
        assert!(
            initiate(&alice, &bob.public_id(), &invite, LATER).is_err(),
            "期限を過ぎた招待では初回接触を始めない"
        );
    }

    #[test]
    fn invite_claiming_a_different_node_is_rejected() {
        // 自称 node_id ではなく、こちらが意図した相手で検証する
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();

        // Mallory が自分の招待を「Bob の招待」として渡してくる（自己署名は valid）
        let (invite, _) = invite_of(&mallory);

        assert!(
            initiate(&alice, &bob.public_id(), &invite, NOW).is_err(),
            "意図した相手(Bob)でない招待は拒否する（自己署名 MITM 対策）"
        );
    }

    #[test]
    fn respond_rejects_a_mismatched_initiator_node_id() {
        // init_msg の NodeId と ID 鍵が食い違えば弾く（NodeId と鍵の付け替え対策）
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();

        let (invite, secrets) = invite_of(&bob);
        let (_sk, mut msg) = initiate(&alice, &bob.public_id(), &invite, NOW).unwrap();

        // NodeId だけ別人にすり替える（ID 鍵はそのまま）
        msg.initiator_node_id = mallory.public_id();

        assert!(
            respond(&bob, &secrets, &msg).is_err(),
            "NodeId と ID 鍵が食い違う初回メッセージは拒否する"
        );
    }

    #[test]
    fn invite_bytes_roundtrip_with_a_fixed_length() {
        let bob = Identity::generate();
        let (invite, _) = invite_of(&bob);
        let bytes = invite.to_bytes();
        assert_eq!(bytes.len(), INVITE_LEN);
        assert_eq!(INVITE_LEN, 1321, "友だちコードの大きさ（base64 で約 1,760 文字）");

        let decoded = Invite::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, invite);
        assert!(decoded.verify(&bob.public_id(), NOW).is_ok());
    }

    #[test]
    fn malformed_invite_bytes_are_rejected() {
        let bob = Identity::generate();
        let bytes = invite_of(&bob).0.to_bytes();
        assert!(Invite::from_bytes(&bytes[..bytes.len() - 1]).is_err(), "短い");
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(Invite::from_bytes(&longer).is_err(), "長い");
        let mut other_version = bytes;
        other_version[0] = 0xEE;
        assert!(Invite::from_bytes(&other_version).is_err(), "知らない版");
    }

    #[test]
    fn kem_contributes_to_the_shared_secret() {
        // 耐量子ハイブリッド：KEM 暗号文を差し替えると SK が食い違う
        // （＝ KEM の共有秘密が確かに SK に混ざっている）
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (invite, secrets) = invite_of(&bob);
        let (sk_a, mut msg) = initiate(&alice, &bob.public_id(), &invite, NOW).unwrap();

        // まず正規は一致
        assert_eq!(sk_a, respond(&bob, &secrets, &msg).unwrap());

        // KEM 暗号文を別の encapsulate 結果に差し替える → decapsulate 結果が変わり不一致
        let (invite2, _) = invite_of(&bob);
        let kem_pk2 = kyber768::PublicKey::from_bytes(&invite2.kem_public).unwrap();
        let (_ss2, ct2) = kyber768::encapsulate(&kem_pk2);
        msg.kem_ciphertext = ct2.as_bytes().to_vec();

        assert_ne!(
            sk_a,
            respond(&bob, &secrets, &msg).unwrap(),
            "KEM 暗号文の差し替えで SK が変わる = KEM が SK に寄与している"
        );
    }

    #[test]
    fn private_body_frames_roundtrip() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (invite, _) = invite_of(&bob);
        let (_sk, init) = initiate(&alice, &bob.public_id(), &invite, NOW).unwrap();

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
        let (invite, secrets) = invite_of(&bob);

        // Alice: initiate → SK → Session、初回本文をフレーム化
        let (sk_a, init) = initiate(&alice, &bob.public_id(), &invite, NOW).unwrap();
        let mut alice_session = Session::initiator(&sk_a, &invite.signed_prekey, init.clone());
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
        // X3DH で SK を確立 → 招待の署名付きプレキーをラチェット初期鍵にして会話開始
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (invite, secrets) = invite_of(&bob);
        let (sk_a, msg) = initiate(&alice, &bob.public_id(), &invite, NOW).unwrap();
        let sk_b = respond(&bob, &secrets, &msg).unwrap();
        assert_eq!(sk_a, sk_b);

        // 署名付きプレキーがラチェットの初期鍵を兼ねる（Signal と同じ）
        let mut alice_ratchet = Ratchet::init_alice(&sk_a, &invite.signed_prekey);
        let mut bob_ratchet = Ratchet::init_bob(&sk_b, &secrets.signed_prekey_secret);

        let (h1, c1) = alice_ratchet.encrypt(b"first from x3dh", b"").unwrap();
        assert_eq!(bob_ratchet.decrypt(&h1, &c1, b"").unwrap(), b"first from x3dh");

        let (h2, c2) = bob_ratchet.encrypt(b"reply", b"").unwrap();
        assert_eq!(alice_ratchet.decrypt(&h2, &c2, b"").unwrap(), b"reply");
    }
}
