//! Hole Punching (ICE 相当のサブセット)
//!
//! # スキャンはしない
//!
//! プローブ先は**相手が教えてくれた候補アドレスだけ**で、数個〜十数個。
//! ICE の connectivity check と同じ構造であり、ポートスキャンにはならない。
//!
//! symmetric NAT (EDM) を力ずくで抜く birthday paradox は**採用しない**。
//! ICE も同じ判断で、EDM は TURN（中継）へ落とす。
//! AETHER は全通信がリレー経由なうえ Connection Reversal もあるので、
//! EDM ノードもそちらで保持者になれる。IDS に引っかかるリスクを
//! 負ってまで得るものがない。
//!
//! # プローブに STUN を使う理由
//!
//! - アドレス発見と同じプロトコルで済み、実装が減る
//! - **匿名性で得**。STUN binding request はビデオ会議や Discord が
//!   常時撃っているパケットで、punch が普通の WebRTC 接続確立と
//!   見分けがつかなくなる。独自マジックだと「AETHER のノードである」
//!   という指紋になる
//!
//! # 時刻同期はしない
//!
//! 双方が「通知を受けたら一定時間プローブし続ける」だけにする。
//! 時計を合わせる必要がなく、開始が多少ずれても窓が重なれば成立する。
//!
//! # 誰と punch してよいか
//!
//! **リレー↔リレー間だけ。** punch には仲介役が要り、
//! 仲介役は「誰が誰に繋ごうとしているか」を学ぶ。
//! リレー同士の接続グラフはディレクトリで公開済みなので漏れるものがないが、
//! クライアント→ガードで使うと、ガード方式が守ろうとしているペアそのものが
//! 第三者に漏れる。クライアントは無条件到達可能なノードをガードに選ぶこと。

use crate::error::{AetherError, Result};
use crate::net::addr::normalize;
use crate::net::shared_socket::SharedSocket;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use stun::agent::TransactionId;
use stun::message::{Getter, Message, BINDING_REQUEST, BINDING_SUCCESS};
use stun::xoraddr::XorMappedAddress;

/// プローブの送出間隔
pub const PROBE_INTERVAL: Duration = Duration::from_millis(100);

/// プローブを続ける時間
///
/// 双方の開始時刻がこの範囲でずれていても窓が重なる。
/// 時計合わせが要らないのはこのため。
pub const PROBE_WINDOW: Duration = Duration::from_secs(2);

/// 1回の punch で扱う候補数の上限
///
/// ICE 相当なので少数。ここが膨らむとスキャンに近づく。
pub const MAX_CANDIDATES: usize = 8;

/// NAT のマッピング挙動
///
/// **フィルタ挙動とは独立の軸**であることに注意。
/// これは「宛先ごとに外部ポートが変わるか」だけを表す。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatMapping {
    /// 観測点が足りず判定できない
    Unknown,
    /// 宛先によらず同じ外部アドレス。**punch できる**
    EndpointIndependent,
    /// 宛先ごとに変わる (symmetric)。**punch は実質不可**
    EndpointDependent,
}

impl NatMapping {
    pub fn can_punch(&self) -> bool {
        matches!(self, NatMapping::EndpointIndependent)
    }
}

/// NAT のフィルタ挙動
///
/// **マッピング挙動とは独立の軸。**
/// マッピングが EIM でも、フィルタが制限ありなら
/// 「送った相手からしか入れない」ので punch が要る。
///
/// EIM + EIF なら**どこか1箇所に送っておくだけで誰でも入れる**ので、
/// punch なしで完全に到達可能（Tier 0）になる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatFiltering {
    /// 判定していない
    Unknown,
    /// 送っていない相手からも入れる。**punch 不要**
    EndpointIndependent,
    /// 送った相手からしか入れない。punch が要る
    Restricted,
}

impl NatFiltering {
    /// 見知らぬ相手からの inbound を punch なしで受けられるか
    pub fn accepts_unsolicited(&self) -> bool {
        matches!(self, NatFiltering::EndpointIndependent)
    }
}

/// 複数の観測点から得た自分のアドレスを突き合わせて判定する
///
/// **観測点が2つ以上必要。** 1つでは「宛先が変われば変わるか」を
/// 確かめようがない。ブートストラップ時は公開 STUN を2台、
/// 定常時はピアを2台使う。
pub fn classify_mapping(observations: &[SocketAddr]) -> NatMapping {
    let mut unique = observations.iter().map(|a| normalize(*a));

    let Some(first) = unique.next() else {
        return NatMapping::Unknown;
    };

    let mut count = 1;
    let mut all_same = true;
    for addr in unique {
        count += 1;
        if addr != first {
            all_same = false;
        }
    }

    if count < 2 {
        return NatMapping::Unknown;
    }

    if all_same {
        NatMapping::EndpointIndependent
    } else {
        NatMapping::EndpointDependent
    }
}

/// 「一度も話していない相手から自分へプローブを撃たせてほしい」
///
/// これが届けばフィルタは EIF。punch なしで到達可能と分かる。
///
/// # 増幅の踏み台にしない
///
/// **プローブ先は要求者が申告したアドレスではなく、
/// 受信側が観測した送信元アドレスにすること。**
/// 申告を信じると、第三者のアドレスを書いて他人にパケットを
/// 撃たせる踏み台になる。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterCheckRequest;

/// 仲介役から third party への依頼: 「このアドレスへプローブを1発」
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterProbeOrder {
    /// **観測された**送信元アドレス（申告値ではない）
    pub target: SocketAddr,
}

impl FilterProbeOrder {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| AetherError::Serialization(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| AetherError::Protocol(format!("Invalid FilterProbeOrder: {}", e)))
    }
}

/// 仲介役へ「この相手と punch したい」と依頼する
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunchRequest {
    /// 要求者自身
    pub requester: crate::crypto::identity::NodeId,
    /// 繋ぎたい相手
    pub target: crate::crypto::identity::NodeId,
    /// 自分の候補アドレス（相手が撃つ先）
    pub candidates: Vec<SocketAddr>,
}

/// 仲介役から「この相手が punch したがっている」と伝えられる
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunchNotify {
    /// 相手
    pub peer: crate::crypto::identity::NodeId,
    /// 相手の候補アドレス
    pub candidates: Vec<SocketAddr>,
}

impl PunchRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| AetherError::Serialization(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let req: Self = bincode::deserialize(bytes)
            .map_err(|e| AetherError::Protocol(format!("Invalid PunchRequest: {}", e)))?;
        req.validate()?;
        Ok(req)
    }

    fn validate(&self) -> Result<()> {
        if self.candidates.len() > MAX_CANDIDATES {
            return Err(AetherError::Protocol(format!(
                "Too many candidates: {} (max {})",
                self.candidates.len(),
                MAX_CANDIDATES
            )));
        }
        Ok(())
    }
}

impl PunchNotify {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| AetherError::Serialization(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let notify: Self = bincode::deserialize(bytes)
            .map_err(|e| AetherError::Protocol(format!("Invalid PunchNotify: {}", e)))?;

        if notify.candidates.len() > MAX_CANDIDATES {
            return Err(AetherError::Protocol("Too many candidates".into()));
        }
        Ok(notify)
    }
}

/// STUN binding request を組み立てる
pub fn build_probe(transaction: TransactionId) -> Result<Vec<u8>> {
    let mut msg = Message::new();
    msg.build(&[Box::new(BINDING_REQUEST), Box::new(transaction)])
        .map_err(|e| AetherError::Protocol(format!("Failed to build probe: {}", e)))?;
    Ok(msg.raw)
}

/// 受け取った binding request への応答を組み立てる
///
/// 送信元を XOR-MAPPED-ADDRESS に載せて返す。
/// これで相手は「自分がどう見えているか」も同時に知れる。
pub fn build_probe_response(transaction: TransactionId, from: SocketAddr) -> Result<Vec<u8>> {
    let mut msg = Message::new();
    msg.transaction_id = transaction;
    msg.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(XorMappedAddress {
            ip: from.ip(),
            port: from.port(),
        }),
    ])
    .map_err(|e| AetherError::Protocol(format!("Failed to build probe response: {}", e)))?;
    Ok(msg.raw)
}

/// 受信した STUN メッセージの種別
#[derive(Debug, PartialEq)]
pub enum ProbeMessage {
    /// 相手からのプローブ。**応答を返すこと**（これで相手側の穴が確認できる）
    Request { transaction: TransactionId },
    /// 自分のプローブへの応答。この候補は通った
    Response {
        transaction: TransactionId,
        /// 相手から見た自分のアドレス
        observed: Option<SocketAddr>,
    },
    /// punch とは関係ない STUN
    Other,
}

/// side channel に流れてきた STUN を解釈する
pub fn parse_probe(data: &[u8]) -> Result<ProbeMessage> {
    let mut msg = Message::new();
    msg.raw = data.to_vec();
    msg.decode()
        .map_err(|e| AetherError::Protocol(format!("Invalid STUN: {}", e)))?;

    let transaction = msg.transaction_id;

    if msg.typ == BINDING_REQUEST {
        return Ok(ProbeMessage::Request { transaction });
    }

    if msg.typ == BINDING_SUCCESS {
        let mut xor = XorMappedAddress::default();
        let observed = xor
            .get_from(&msg)
            .ok()
            .map(|_| SocketAddr::new(xor.ip, xor.port));

        return Ok(ProbeMessage::Response {
            transaction,
            observed,
        });
    }

    Ok(ProbeMessage::Other)
}

/// 1回の punch 試行
pub struct PunchSession {
    /// 送ったプローブ: transaction -> 宛先
    sent: HashMap<[u8; 12], SocketAddr>,
    /// 応答が返ってきた候補
    confirmed: Option<SocketAddr>,
    /// 相手からプローブが届いた候補（相手側の穴が開いた証拠）
    inbound_seen: Vec<SocketAddr>,
}

impl Default for PunchSession {
    fn default() -> Self {
        Self::new()
    }
}

impl PunchSession {
    pub fn new() -> Self {
        Self {
            sent: HashMap::new(),
            confirmed: None,
            inbound_seen: Vec::new(),
        }
    }

    /// 候補全てへプローブを1巡撃つ
    ///
    /// **QUIC と同じソケットから撃つこと。** 別ソケットで開けた穴は
    /// QUIC の通り道にならない。
    pub async fn probe_round(
        &mut self,
        socket: &Arc<SharedSocket>,
        candidates: &[SocketAddr],
    ) -> Result<()> {
        for candidate in candidates.iter().take(MAX_CANDIDATES) {
            let transaction = TransactionId::new();
            let probe = build_probe(transaction)?;

            self.sent.insert(transaction.0, *candidate);

            // 1つ失敗しても他の候補は試す
            let _ = socket.send_raw(*candidate, &probe).await;
        }
        Ok(())
    }

    /// 受信した STUN を処理する
    ///
    /// 戻り値が `true` なら応答を返す必要がある（呼び出し側が送る）。
    pub fn handle_incoming(&mut self, from: SocketAddr, message: &ProbeMessage) -> bool {
        let from = normalize(from);

        match message {
            ProbeMessage::Request { .. } => {
                // 相手のプローブが届いた = こちら向きの穴が開いている
                if !self.inbound_seen.contains(&from) {
                    self.inbound_seen.push(from);
                }
                true
            }
            ProbeMessage::Response { transaction, .. } => {
                if let Some(target) = self.sent.get(&transaction.0) {
                    // 自分が撃った先から返ってきた = 双方向に通った
                    self.confirmed = Some(*target);
                }
                false
            }
            ProbeMessage::Other => false,
        }
    }

    /// 双方向に通った候補
    pub fn confirmed(&self) -> Option<SocketAddr> {
        self.confirmed
    }

    /// 相手からプローブが届いた候補
    pub fn inbound_seen(&self) -> &[SocketAddr] {
        &self.inbound_seen
    }

    /// punch が成立したか
    ///
    /// 応答が返ってくれば双方向確認済み。
    /// 相手のプローブだけ届いている場合も、こちら向きの穴は開いている。
    pub fn is_open(&self) -> bool {
        self.confirmed.is_some() || !self.inbound_seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::NodeId;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    // ---- NAT 判定 ----

    #[test]
    fn one_observation_is_not_enough() {
        // 宛先が変われば変わるかを1点では確かめようがない
        assert_eq!(
            classify_mapping(&[addr("203.0.113.1:9000")]),
            NatMapping::Unknown
        );
        assert_eq!(classify_mapping(&[]), NatMapping::Unknown);
    }

    #[test]
    fn same_address_from_two_observers_means_eim() {
        let obs = [addr("203.0.113.1:9000"), addr("203.0.113.1:9000")];
        assert_eq!(classify_mapping(&obs), NatMapping::EndpointIndependent);
        assert!(classify_mapping(&obs).can_punch());
    }

    #[test]
    fn differing_ports_mean_edm() {
        // symmetric NAT。punch は実質不可
        let obs = [addr("203.0.113.1:9000"), addr("203.0.113.1:41234")];
        assert_eq!(classify_mapping(&obs), NatMapping::EndpointDependent);
        assert!(!classify_mapping(&obs).can_punch());
    }

    #[test]
    fn classification_normalises_mapped_addresses() {
        // デュアルスタックでは片方が ::ffff: 形式で来ることがある。
        // 正規化しないと同じアドレスを EDM と誤判定する
        let obs = [addr("[::ffff:203.0.113.1]:9000"), addr("203.0.113.1:9000")];
        assert_eq!(classify_mapping(&obs), NatMapping::EndpointIndependent);
    }

    // ---- メッセージ ----

    // ---- フィルタ挙動 ----

    #[test]
    fn eif_accepts_unsolicited_traffic() {
        // ここが EIF なら punch すら要らない
        assert!(NatFiltering::EndpointIndependent.accepts_unsolicited());
        assert!(!NatFiltering::Restricted.accepts_unsolicited());
        assert!(!NatFiltering::Unknown.accepts_unsolicited());
    }

    #[test]
    fn filter_probe_order_survives_wire_roundtrip() {
        let order = FilterProbeOrder {
            target: addr("203.0.113.5:9000"),
        };
        let decoded = FilterProbeOrder::decode(&order.encode().unwrap()).unwrap();
        assert_eq!(decoded.target, order.target);
    }

    #[test]
    fn punch_request_survives_wire_roundtrip() {
        let req = PunchRequest {
            requester: NodeId([1u8; 32]),
            target: NodeId([7u8; 32]),
            candidates: vec![addr("203.0.113.1:9000"), addr("192.168.1.5:9000")],
        };

        let decoded = PunchRequest::decode(&req.encode().unwrap()).unwrap();
        assert_eq!(decoded.candidates, req.candidates);
    }

    #[test]
    fn rejects_too_many_candidates() {
        // 候補が膨らむとスキャンに近づく
        let req = PunchRequest {
            requester: NodeId([1u8; 32]),
            target: NodeId([7u8; 32]),
            candidates: (0..=MAX_CANDIDATES)
                .map(|n| addr(&format!("203.0.113.1:{}", 9000 + n)))
                .collect(),
        };

        assert!(PunchRequest::decode(&req.encode().unwrap()).is_err());
    }

    // ---- STUN プローブ ----

    #[test]
    fn probe_is_recognised_as_stun() {
        // SharedSocket が横取りできなければ side channel に流れてこない
        let probe = build_probe(TransactionId::new()).unwrap();
        assert!(crate::net::shared_socket::is_stun(&probe));
    }

    #[test]
    fn probe_response_is_recognised_as_stun() {
        let resp =
            build_probe_response(TransactionId::new(), addr("203.0.113.9:1234")).unwrap();
        assert!(crate::net::shared_socket::is_stun(&resp));
    }

    #[test]
    fn parses_request_and_response() {
        let tx = TransactionId::new();

        let probe = build_probe(tx).unwrap();
        assert_eq!(
            parse_probe(&probe).unwrap(),
            ProbeMessage::Request { transaction: tx }
        );

        let observed = addr("203.0.113.9:1234");
        let resp = build_probe_response(tx, observed).unwrap();
        match parse_probe(&resp).unwrap() {
            ProbeMessage::Response {
                transaction,
                observed: got,
            } => {
                assert_eq!(transaction, tx);
                assert_eq!(got, Some(observed), "送信元が載っていない");
            }
            other => panic!("応答として解釈されない: {:?}", other),
        }
    }

    #[test]
    fn response_carries_the_transaction_back() {
        // トランザクションを取り違えると、通っていない候補を通ったと誤認する
        let mine = TransactionId::new();
        let theirs = TransactionId::new();

        let mut session = PunchSession::new();
        session.sent.insert(mine.0, addr("203.0.113.1:9000"));

        session.handle_incoming(
            addr("203.0.113.1:9000"),
            &ProbeMessage::Response {
                transaction: theirs,
                observed: None,
            },
        );
        assert_eq!(session.confirmed(), None, "別のトランザクションで確定している");

        session.handle_incoming(
            addr("203.0.113.1:9000"),
            &ProbeMessage::Response {
                transaction: mine,
                observed: None,
            },
        );
        assert_eq!(session.confirmed(), Some(addr("203.0.113.1:9000")));
    }

    #[test]
    fn incoming_request_needs_a_reply() {
        let mut session = PunchSession::new();

        let needs_reply = session.handle_incoming(
            addr("203.0.113.2:9000"),
            &ProbeMessage::Request {
                transaction: TransactionId::new(),
            },
        );

        assert!(needs_reply, "相手のプローブには応答を返す必要がある");
        assert_eq!(session.inbound_seen(), &[addr("203.0.113.2:9000")]);
        assert!(session.is_open(), "相手のプローブが届いた時点で穴は開いている");
    }

    #[test]
    fn duplicate_inbound_probes_are_not_double_counted() {
        let mut session = PunchSession::new();
        let peer = addr("203.0.113.2:9000");

        for _ in 0..5 {
            session.handle_incoming(
                peer,
                &ProbeMessage::Request {
                    transaction: TransactionId::new(),
                },
            );
        }

        assert_eq!(session.inbound_seen().len(), 1);
    }

    // ---- 実際に穴を開ける ----

    #[tokio::test]
    async fn two_sockets_punch_each_other() {
        use quinn::default_runtime;

        let runtime = default_runtime().unwrap();

        let (a, mut a_rx) =
            SharedSocket::from_std(std::net::UdpSocket::bind("127.0.0.1:0").unwrap(), &*runtime)
                .unwrap();
        let (b, mut b_rx) =
            SharedSocket::from_std(std::net::UdpSocket::bind("127.0.0.1:0").unwrap(), &*runtime)
                .unwrap();

        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        tokio::spawn(a.clone().pump());
        tokio::spawn(b.clone().pump());

        // B 側: プローブが来たら応答を返す
        let b_socket = b.clone();
        tokio::spawn(async move {
            let mut session = PunchSession::new();
            while let Some(datagram) = b_rx.recv().await {
                let Ok(msg) = parse_probe(&datagram.data) else {
                    continue;
                };
                if session.handle_incoming(datagram.from, &msg)
                    && let ProbeMessage::Request { transaction } = msg
                    && let Ok(resp) = build_probe_response(transaction, datagram.from)
                {
                    let _ = b_socket.send_raw(datagram.from, &resp).await;
                }
            }
        });

        // A 側: B へプローブを撃ち、応答を待つ
        let mut session = PunchSession::new();
        session.probe_round(&a, &[b_addr]).await.unwrap();

        let datagram = tokio::time::timeout(Duration::from_secs(5), a_rx.recv())
            .await
            .expect("応答が返ってこない")
            .unwrap();

        let msg = parse_probe(&datagram.data).unwrap();
        session.handle_incoming(datagram.from, &msg);

        assert_eq!(
            session.confirmed(),
            Some(b_addr),
            "双方向の疎通が確認できていない"
        );
        assert!(session.is_open());

        // 応答には A から見えるアドレスが載っている
        if let ProbeMessage::Response { observed, .. } = msg {
            assert_eq!(observed.map(normalize), Some(normalize(a_addr)));
        } else {
            panic!("応答ではない");
        }
    }
}
