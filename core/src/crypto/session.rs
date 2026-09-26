//! 前方秘匿セッション — 連絡先ごとの双方向 Double Ratchet (Phase 3-1 配線)
//!
//! X3DH の出力 `SK` から、**1 本の双方向** Double Ratchet を立てる。
//! 開始側（X3DH の initiator）が Alice、応答側が Bob。Bob の初期ラチェット鍵は
//! X3DH の署名付きプレキー（SPK）を使う（Signal と同じ）。
//!
//! # なぜ 1 本か（以前の方向別 2 本をやめた理由）
//!
//! 以前は事前共有秘密と双方の NodeId から、方向ごとに一方向のラチェットを 2 本立てていた。
//! 一方向のラチェットには相手から新しい DH 公開鍵が届かないので、**DH ラチェットが
//! 一度も回らず**、対称鍵のチェーンだけが進んでいた。端末を密かに複製されると（押収して
//! 返却するなど）、以後のメッセージを永久に読まれた（侵害からの回復が無い）。
//! 1 本にすれば、往復のたびに新しい DH 鍵が混ざり、複製された状態は次の往復で無効になる。
//!
//! # 初回メッセージの取りこぼし
//!
//! 相手から 1 通も受け取るまで、送るすべてのメッセージに X3DH の初回メッセージ
//! （[`InitialMessage`]）を添える（[`Session::pending_initial`]）。最初の 1 通が
//! 届かなくても、後の 1 通で相手はセッションを立てられる。
//!
//! 受け取った側は、初回メッセージの一時鍵を覚えておく（[`Session::peer_initial_ek`]）。
//! 同じ一時鍵の初回メッセージが再び来ても、セッションを作り直さない。
//!
//! [`InitialMessage`]: crate::crypto::x3dh::InitialMessage

use crate::crypto::ratchet::{Header, Ratchet};
use crate::crypto::x3dh::InitialMessage;
use crate::error::{AetherError, Result};
use serde::{Deserialize, Serialize};

/// 前方秘匿された1通ぶんのワイヤ本体（ヘッダ＋暗号文）
#[derive(Serialize, Deserialize)]
struct SealedBody {
    header: Header,
    ciphertext: Vec<u8>,
}

/// 連絡先1人ぶんの前方秘匿セッション（KeyStore に永続化する）
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    ratchet: Ratchet,
    /// 開始側で、まだ相手から 1 通も受け取っていない間は、送るたびに添える初回メッセージ
    pub pending_initial: Option<InitialMessage>,
    /// 応答側で、このセッションを立てた初回メッセージの一時鍵
    pub peer_initial_ek: Option<[u8; 32]>,
}

impl Session {
    /// 開始側（X3DH の initiator）のセッション
    ///
    /// `peer_signed_prekey` は相手のプレキー束の SPK 公開鍵。`initial` は相手へ添える
    /// 初回メッセージで、相手から 1 通受け取るまで送るたびに添える。
    pub fn initiator(sk: &[u8; 32], peer_signed_prekey: &[u8; 32], initial: InitialMessage) -> Self {
        Self {
            ratchet: Ratchet::init_alice(sk, peer_signed_prekey),
            pending_initial: Some(initial),
            peer_initial_ek: None,
        }
    }

    /// 応答側（X3DH の responder）のセッション
    ///
    /// `my_signed_prekey_secret` は自分の SPK 秘密鍵、`initial_ek` は受け取った初回メッセージの一時鍵。
    pub fn responder(sk: &[u8; 32], my_signed_prekey_secret: &[u8; 32], initial_ek: [u8; 32]) -> Self {
        Self {
            ratchet: Ratchet::init_bob(sk, my_signed_prekey_secret),
            pending_initial: None,
            peer_initial_ek: Some(initial_ek),
        }
    }

    /// 相手から 1 通でも受け取ったか（開始側で、初回メッセージを添えなくてよくなったか）
    pub fn has_heard_from_peer(&self) -> bool {
        self.pending_initial.is_none()
    }

    /// 1 通を封じる
    pub fn seal(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        let (header, ciphertext) = self.ratchet.encrypt(plaintext, associated_data)?;
        bincode::serialize(&SealedBody { header, ciphertext })
            .map_err(|e| AetherError::Serialization(e.to_string()))
    }

    /// 1 通を開く
    ///
    /// **開けたときだけ状態を進める。** ラチェットは復号の途中で DH ラチェットや
    /// 取りこぼし鍵の生成を行うので、壊れた・偽の本文で状態が進むと以後の会話が壊れる。
    pub fn open(&mut self, body: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        let sealed: SealedBody = bincode::deserialize(body)
            .map_err(|e| AetherError::Protocol(format!("Invalid sealed body: {}", e)))?;
        let mut next = self.ratchet.clone();
        let plaintext = next.decrypt(&sealed.header, &sealed.ciphertext, associated_data)?;
        self.ratchet = next;
        // 相手から届いた ＝ 相手はセッションを立てた。以後は初回メッセージを添えない
        self.pending_initial = None;
        Ok(plaintext)
    }
}

/// 試験用: X3DH を通した開始側・応答側のセッション
#[cfg(test)]
pub(crate) fn test_pair() -> (Session, Session) {
    use crate::crypto::identity::Identity;
    use crate::crypto::x3dh;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let (bundle, secrets) = x3dh::generate_prekeys(&bob, false);
    let (sk_a, init) = x3dh::initiate(&alice, &bob.public_id(), &bundle).unwrap();
    let sk_b = x3dh::respond(&bob, &secrets, &init).unwrap();
    let ek = init.ephemeral_key;
    (
        Session::initiator(&sk_a, &bundle.signed_prekey, init),
        Session::responder(&sk_b, &secrets.signed_prekey_secret, ek),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Session, Session) {
        test_pair()
    }

    #[test]
    fn both_sides_can_send_and_receive_many_times() {
        let (mut a, mut b) = pair();
        for i in 0..3u8 {
            let m = a.seal(&[i; 4], b"").unwrap();
            assert_eq!(b.open(&m, b"").unwrap(), [i; 4]);
            let r = b.seal(&[i + 100; 4], b"").unwrap();
            assert_eq!(a.open(&r, b"").unwrap(), [i + 100; 4]);
        }
    }

    #[test]
    fn a_copied_state_stops_working_after_a_round_trip() {
        // 端末を密かに複製された想定。往復で新しい DH 鍵が混ざれば、複製は以後を読めない
        let (mut a, mut b) = pair();
        let m = a.seal(b"one", b"").unwrap();
        b.open(&m, b"").unwrap();
        let stolen_bob = b.clone();

        let r = b.seal(b"two", b"").unwrap();
        a.open(&r, b"").unwrap();
        let m2 = a.seal(b"three", b"").unwrap();
        b.open(&m2, b"").unwrap();
        let r2 = b.seal(b"four", b"").unwrap();
        a.open(&r2, b"").unwrap();

        let later = a.seal(b"after recovery", b"").unwrap();
        let mut thief = stolen_bob;
        assert!(thief.open(&later, b"").is_err(), "複製した状態で往復後のメッセージが読めた");
        assert_eq!(b.open(&later, b"").unwrap(), b"after recovery");
    }

    #[test]
    fn initiator_keeps_the_initial_message_until_it_hears_back() {
        let (mut a, mut b) = pair();
        assert!(a.pending_initial.is_some());
        let m1 = a.seal(b"lost", b"").unwrap();
        let m2 = a.seal(b"arrives", b"").unwrap();
        assert!(a.pending_initial.is_some(), "返事が来るまで初回メッセージを添え続ける");

        // 1 通目を取りこぼしても 2 通目で開ける
        assert_eq!(b.open(&m2, b"").unwrap(), b"arrives");
        assert_eq!(b.open(&m1, b"").unwrap(), b"lost");

        let r = b.seal(b"reply", b"").unwrap();
        a.open(&r, b"").unwrap();
        assert!(a.pending_initial.is_none(), "返事が来たら添えない");
    }

    #[test]
    fn a_failed_open_does_not_advance_the_state() {
        let (mut a, mut b) = pair();
        let good = a.seal(b"good", b"").unwrap();

        let mut forged = good.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF;
        assert!(b.open(&forged, b"").is_err());
        assert!(b.open(b"garbage", b"").is_err());

        assert_eq!(b.open(&good, b"").unwrap(), b"good");
    }

    #[test]
    fn session_survives_serde_roundtrip() {
        let (mut a, mut b) = pair();
        b.open(&a.seal(b"before", b"").unwrap(), b"").unwrap();

        let bytes = bincode::serialize(&b).unwrap();
        let mut b2: Session = bincode::deserialize(&bytes).unwrap();
        assert_eq!(b2.open(&a.seal(b"after", b"").unwrap(), b"").unwrap(), b"after");
    }
}
