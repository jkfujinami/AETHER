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
//! # Hint の鍵も日ごとに進める
//!
//! 宛先の認識（Hint の blind_tag・Hint の暗号・本体の置き場所）は、以前は身元鍵同士の
//! 静的な DH（`Identity::agree`）だけで作っていた。Broadcast Veil では監視ノードも全 Hint を
//! 受け取って保存できるので、端末を押収されて身元鍵を取られると、保存されていた過去の
//! 全 Hint から「誰と・いつ」やり取りしたかを復元できた（本文はラチェットで守られていても、
//! メタデータに前方秘匿が無かった）。
//!
//! そこで会話が立ったら、Hint 用の秘密を X3DH の `SK` から作る**日ごとのハッシュチェーン**
//! （[`HintChain`]）に切り替える。`K_{d+1} = H(K_d)` なので、両者は日付だけから同じ鍵を
//! 計算でき、網のやり取りは増えない。前の日の鍵は捨てるので、押収されても読めるのは
//! その日以降だけ。`SK` 自体は保存しない。
//!
//! 静的な DH が残るのは、相手がまだ `SK` を持っていない初回接触の間
//! （[`Session::pending_initial`] がある間）だけ。
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

/// 1 日の長さ（Hint 鍵チェーンの刻み）
pub const HINT_DAY_SECS: u64 = 24 * 3600;

/// Hint 用の秘密の日ごとのハッシュチェーン（モジュール先頭の説明を参照）
///
/// 手元に残すのは今日と昨日の鍵だけ。昨日の鍵は、日付をまたいで届いた Hint
/// （backlog の 24 時間の窓・時計のずれ）を認識するため。
#[derive(Clone, Serialize, Deserialize)]
pub struct HintChain {
    day: u64,
    today: [u8; 32],
    yesterday: [u8; 32],
}

impl HintChain {
    /// `SK` から、`now` の日の鍵まで進めたチェーンを作る
    ///
    /// 日番号 0 から数えるので、両者は作った日が違っても同じ鍵に到達する
    /// （数万回の SHA-256 で、作るときに 1 回だけ）。
    fn new(sk: &[u8; 32], now: u64) -> Self {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, sk);
        let mut key = [0u8; 32];
        hk.expand(b"aether_hint_chain_v1", &mut key)
            .expect("32 バイトは HKDF の上限内");
        let day = now / HINT_DAY_SECS;
        let mut yesterday = key;
        for _ in 0..day {
            yesterday = key;
            key = Self::step(&key);
        }
        Self { day, today: key, yesterday }
    }

    fn step(key: &[u8; 32]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::new()
            .chain_update(b"aether_hint_chain_step_v1")
            .chain_update(key)
            .finalize()
            .into()
    }

    /// `now` の日まで進める（戻らない）。進めたら true
    fn advance(&mut self, now: u64) -> bool {
        let target = now / HINT_DAY_SECS;
        let moved = target > self.day;
        while self.day < target {
            self.yesterday = self.today;
            self.today = Self::step(&self.today);
            self.day += 1;
        }
        moved
    }
}

/// 連絡先1人ぶんの前方秘匿セッション（KeyStore に永続化する）
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    ratchet: Ratchet,
    /// Hint 用の秘密のチェーン（[`HintChain`]）
    hint: HintChain,
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
            hint: HintChain::new(sk, crate::protocol::hint::current_timestamp()),
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
            hint: HintChain::new(sk, crate::protocol::hint::current_timestamp()),
            pending_initial: None,
            peer_initial_ek: Some(initial_ek),
        }
    }

    /// 相手から 1 通でも受け取ったか（開始側で、初回メッセージを添えなくてよくなったか）
    pub fn has_heard_from_peer(&self) -> bool {
        self.pending_initial.is_none()
    }

    /// 送信する Hint に使う秘密。相手がまだ `SK` を持っていない（初回接触の）間は `None`
    ///
    /// `None` のときは呼び出し側が静的な DH の秘密を使う。日が変わっていればチェーンを
    /// 進めるので、呼び出し側はこの後セッションを保存すること。
    pub fn hint_secret_for_send(&mut self, now: u64) -> Option<[u8; 32]> {
        self.hint.advance(now);
        self.pending_initial.is_none().then_some(self.hint.today)
    }

    /// 受信で認識に使う Hint の秘密（昨日・今日・明日）。進めたら第 2 要素が true
    ///
    /// 明日の鍵は今日の鍵から計算できるので、手元に残しても前方秘匿は損なわない。
    /// 相手の時計が進んでいる・日付の境目で送られた Hint を取りこぼさないために含める。
    pub fn hint_secrets_for_receive(&mut self, now: u64) -> ([[u8; 32]; 3], bool) {
        let moved = self.hint.advance(now);
        let tomorrow = HintChain::step(&self.hint.today);
        ([self.hint.yesterday, self.hint.today, tomorrow], moved)
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
    fn hint_chain_agrees_on_both_sides_and_only_after_hearing_back() {
        let (mut a, mut b) = pair();
        let now = crate::protocol::hint::current_timestamp();
        assert!(a.hint_secret_for_send(now).is_none(), "初回接触の間は静的な秘密を使う");
        let bob_today = b.hint_secret_for_send(now).expect("応答側は SK を持っている");
        let (alice_keys, _) = a.hint_secrets_for_receive(now);
        assert!(alice_keys.contains(&bob_today));

        b.open(&a.seal(b"x", b"").unwrap(), b"").ok();
        a.open(&b.seal(b"y", b"").unwrap(), b"").unwrap();
        assert_eq!(a.hint_secret_for_send(now), Some(bob_today));
    }

    #[test]
    fn hint_chain_forgets_older_days() {
        let (mut a, _) = pair();
        let now = crate::protocol::hint::current_timestamp();
        let (before, _) = a.hint_secrets_for_receive(now);
        let (after, moved) = a.hint_secrets_for_receive(now + 3 * HINT_DAY_SECS);
        assert!(moved);
        for old in &before {
            assert!(!after.contains(old), "3 日後に 3 日前の鍵が残っている");
        }
        // 一方通行: 前の日へは戻らない
        let (again, moved) = a.hint_secrets_for_receive(now);
        assert!(!moved);
        assert_eq!(again, after);
    }

    #[test]
    fn hint_chains_created_on_different_days_meet() {
        let sk = [7u8; 32];
        let day = HINT_DAY_SECS;
        let mut early = HintChain::new(&sk, 20_000 * day);
        let late = HintChain::new(&sk, 20_002 * day);
        early.advance(20_002 * day);
        assert_eq!(early.today, late.today);
        assert_eq!(early.yesterday, late.yesterday);
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
