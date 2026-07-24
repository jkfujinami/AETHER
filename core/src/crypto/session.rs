//! 前方秘匿セッション — 連絡先ごとの方向別 Double Ratchet (Phase 3-1 配線)
//!
//! 事前共有秘密（`--secret`。将来は X3DH の出力）と**双方の NodeId** から、
//! 方向ごとに Double Ratchet を**決定論的**に立てる。両者が独立に同じ状態へ到達する。
//!
//! - `send`: 自分が initiator（相手が受信者 = responder）。相手の responder 公開鍵へ `init_alice`。
//! - `recv`: 自分が responder。自分の responder 秘密鍵で `init_bob`。
//!
//! 相手の Session はちょうど鏡像になる（相手の send = こちらの recv と噛み合う）。
//!
//! # なぜ方向別に2本か
//!
//! 事前共有秘密だけだと「どちらが会話を始めるか」が決まらず、単一の双方向ラチェットを
//! 立てられない（Double Ratchet は開始側が最初に送る必要がある）。方向別に一方向チェーンを
//! 2本持てば、**どちらからでも送れて前方秘匿が成立する**（break-in recovery は弱まるが、
//! 押収に対する主眼＝過去メッセージの秘匿は満たす）。完全な双方向 DH ラチェットは
//! X3DH 配線時に開始方向が定まってから移行する。

use crate::crypto::identity::NodeId;
use crate::crypto::ratchet::{Header, Ratchet};
use crate::error::{AetherError, Result};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// 前方秘匿された1通ぶんのワイヤ本体（ヘッダ＋暗号文）
#[derive(Serialize, Deserialize)]
struct SealedBody {
    header: Header,
    ciphertext: Vec<u8>,
}

/// 連絡先1人ぶんの前方秘匿セッション（KeyStore に永続化する）
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    /// 自分 → 相手（自分が initiator）
    pub send: Ratchet,
    /// 相手 → 自分（自分が responder）
    pub recv: Ratchet,
}

fn derive32(secret: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("32 <= 255*32");
    out
}

/// 受信者ノードごとの responder 初期鍵の秘密（両者が同じ値を計算できる）
fn responder_secret(secret: &[u8; 32], receiver: &NodeId) -> [u8; 32] {
    let mut info = b"aether_session_resp_v1".to_vec();
    info.extend_from_slice(receiver.as_bytes());
    derive32(secret, &info)
}

impl Session {
    /// 事前共有秘密から自分↔相手のセッションを立てる（決定論的・両者が同じに到達）
    pub fn bootstrap(secret: &[u8; 32], me: &NodeId, peer: &NodeId) -> Self {
        let sk = derive32(secret, b"aether_session_root_v1");

        // 送信: 相手が受信者 = responder。相手の responder 公開鍵へ init_alice。
        let peer_resp = responder_secret(secret, peer);
        let peer_resp_pub = PublicKey::from(&StaticSecret::from(peer_resp)).to_bytes();
        let send = Ratchet::init_alice(&sk, &peer_resp_pub);

        // 受信: 自分が responder。自分の responder 秘密鍵で init_bob。
        let my_resp = responder_secret(secret, me);
        let recv = Ratchet::init_bob(&sk, &my_resp);

        Self { send, recv }
    }

    /// 平文を封じてワイヤ本体を返す（**送信ラチェットを前進**・使った鍵は破棄）
    pub fn seal(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        let (header, ciphertext) = self.send.encrypt(plaintext, associated_data)?;
        bincode::serialize(&SealedBody { header, ciphertext })
            .map_err(|e| AetherError::Serialization(e.to_string()))
    }

    /// ワイヤ本体を開いて平文を返す（**受信ラチェットを前進**・順不同も可）
    pub fn open(&mut self, body: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        let sealed: SealedBody = bincode::deserialize(body)
            .map_err(|e| AetherError::Protocol(format!("Invalid sealed body: {}", e)))?;
        self.recv.decrypt(&sealed.header, &sealed.ciphertext, associated_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    #[test]
    fn both_sides_can_send_and_receive() {
        let secret = [0x33u8; 32];
        let alice_id = node(1);
        let bob_id = node(2);

        let mut alice = Session::bootstrap(&secret, &alice_id, &bob_id);
        let mut bob = Session::bootstrap(&secret, &bob_id, &alice_id);

        // Alice → Bob
        let (h, c) = alice.send.encrypt(b"hi bob", b"").unwrap();
        assert_eq!(bob.recv.decrypt(&h, &c, b"").unwrap(), b"hi bob");

        // Bob → Alice（別方向のチェーン）
        let (h2, c2) = bob.send.encrypt(b"hi alice", b"").unwrap();
        assert_eq!(alice.recv.decrypt(&h2, &c2, b"").unwrap(), b"hi alice");
    }

    #[test]
    fn multiple_messages_each_direction() {
        let secret = [0x7u8; 32];
        let mut a = Session::bootstrap(&secret, &node(1), &node(2));
        let mut b = Session::bootstrap(&secret, &node(2), &node(1));

        for i in 0..5u8 {
            let msg = [i; 4];
            let (h, c) = a.send.encrypt(&msg, b"").unwrap();
            assert_eq!(b.recv.decrypt(&h, &c, b"").unwrap(), msg);
        }
        for i in 0..5u8 {
            let msg = [i + 100; 4];
            let (h, c) = b.send.encrypt(&msg, b"").unwrap();
            assert_eq!(a.recv.decrypt(&h, &c, b"").unwrap(), msg);
        }
    }

    #[test]
    fn different_secret_cannot_decrypt() {
        let mut a = Session::bootstrap(&[1u8; 32], &node(1), &node(2));
        let mut wrong = Session::bootstrap(&[2u8; 32], &node(2), &node(1));

        let (h, c) = a.send.encrypt(b"secret", b"").unwrap();
        assert!(
            wrong.recv.decrypt(&h, &c, b"").is_err(),
            "別の事前共有秘密では復号できない"
        );
    }

    #[test]
    fn seal_and_open_roundtrip() {
        // mailbox が運ぶのはこの不透明な body。seal/open が対称であること
        let secret = [0x55u8; 32];
        let mut a = Session::bootstrap(&secret, &node(1), &node(2));
        let mut b = Session::bootstrap(&secret, &node(2), &node(1));

        let body = a.seal(b"forward-secret body", b"mailbox_key").unwrap();
        assert!(
            !body.windows(19).any(|w| w == b"forward-secret body"),
            "本体は暗号化されている"
        );
        assert_eq!(b.open(&body, b"mailbox_key").unwrap(), b"forward-secret body");
    }

    #[test]
    fn session_survives_serde_roundtrip() {
        let secret = [0x9u8; 32];
        let mut a = Session::bootstrap(&secret, &node(1), &node(2));
        let mut b = Session::bootstrap(&secret, &node(2), &node(1));

        let (h1, c1) = a.send.encrypt(b"before", b"").unwrap();
        b.recv.decrypt(&h1, &c1, b"").unwrap();

        // Bob 側を永続化して復元
        let bytes = bincode::serialize(&b).unwrap();
        let mut b2: Session = bincode::deserialize(&bytes).unwrap();

        let (h2, c2) = a.send.encrypt(b"after", b"").unwrap();
        assert_eq!(b2.recv.decrypt(&h2, &c2, b"").unwrap(), b"after");
    }
}
