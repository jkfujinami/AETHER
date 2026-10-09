//! Peer Exchange — リレーリストの自律的な配布
//!
//! Kademlia を廃止した (18.5.2) ため、各ノードはリレーリスト全体を
//! ローカルに持つ必要がある。その入手経路がこれ。
//!
//! # 方式
//!
//! Pull 型。「知っているリレーを教えて」と要求し、相手が知っている分を返す。
//! 要求には**自分の記述子を同梱**するので、要求した時点で相手にも自分が伝わる。
//! 種ノード1台さえ知っていれば、そこから網全体へ収束していく。
//!
//! # 増幅を避ける
//!
//! 応答は [`MAX_DESCRIPTORS_PER_RESPONSE`] 件で頭打ちにする。
//! 100万リレーを知っているノードが 66MB を投げ返すと、
//! 小さな要求で大きな応答を引き出す増幅攻撃になる。
//!
//! # PoW 検証は受け取り側の責務
//!
//! 記述子は [`RelayDirectory::insert`] 経由で入れること。
//! 素通しすると、攻撃者が Ed25519 鍵を量産して
//! 狙った mailbox_key の隣に着地する NodeId を選べてしまう (18.5.3)。

use crate::error::{AetherError, Result};
use crate::net::lease_set::{LeaseSet, MAX_LEASE_SETS_PER_RESPONSE};
use crate::net::relay_list::{RelayDescriptor, RelayDirectory, DESCRIPTOR_TTL_SECS};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

/// 1回の応答で返す記述子の上限
///
/// 66 バイト × 64 = 約 4.2KB。増幅率を抑えるための上限。
pub const MAX_DESCRIPTORS_PER_RESPONSE: usize = 64;

/// これを下回ったら PEX を仕掛ける
pub const MIN_HEALTHY_DIRECTORY: usize = 32;

/// 「知っているリレーを教えて」
///
/// リレーは自分の記述子を同梱するので、要求した時点で相手にも自分が伝わる。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexRequest {
    /// 要求者自身の記述子。`None` は「自分を登録しないで」（一回限りのクライアント）
    ///
    /// 一回限りのクライアントが記述子を載せると、種ノードとその先の網に
    /// 「この IP の誰かが AETHER を使った」記録が残り、回路の候補にも混ざる
    /// （リレーではないので中継できない）。応答は観測した送信元へ返るので、
    /// 記述子が無くても受け取れる。
    pub requester: Option<RelayDescriptor>,
    /// 欲しい件数（上限は [`MAX_DESCRIPTORS_PER_RESPONSE`] で頭打ち）
    pub want: u16,
}

/// 既知のリレー一覧と、保持者の leaseSet の一覧
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexResponse {
    pub relays: Vec<RelayDescriptor>,
    /// 保持者の leaseSet（上限は [`MAX_LEASE_SETS_PER_RESPONSE`]）
    pub lease_sets: Vec<LeaseSet>,
}

impl PexRequest {
    /// 自分をリレーとして登録してもらう要求
    pub fn new(requester: RelayDescriptor) -> Self {
        Self {
            requester: Some(requester),
            want: MAX_DESCRIPTORS_PER_RESPONSE as u16,
        }
    }

    /// 自分を登録させない要求（一回限りのクライアント）
    pub fn anonymous() -> Self {
        Self {
            requester: None,
            want: MAX_DESCRIPTORS_PER_RESPONSE as u16,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| AetherError::Serialization(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| AetherError::Protocol(format!("Invalid PexRequest: {}", e)))
    }
}

impl PexResponse {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| AetherError::Serialization(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let response: Self = bincode::deserialize(bytes)
            .map_err(|e| AetherError::Protocol(format!("Invalid PexResponse: {}", e)))?;

        if response.relays.len() > MAX_DESCRIPTORS_PER_RESPONSE {
            return Err(AetherError::Protocol(format!(
                "PexResponse too large: {} (max {})",
                response.relays.len(),
                MAX_DESCRIPTORS_PER_RESPONSE
            )));
        }
        if response.lease_sets.len() > MAX_LEASE_SETS_PER_RESPONSE {
            return Err(AetherError::Protocol(format!(
                "PexResponse carries too many lease sets: {} (max {})",
                response.lease_sets.len(),
                MAX_LEASE_SETS_PER_RESPONSE
            )));
        }
        Ok(response)
    }
}

/// 要求に対して返す記述子を選ぶ
///
/// ランダムに選ぶ。近い順に返すと、リング上の特定領域の情報だけが
/// 濃く伝播してリストが偏る。
pub fn select_response(
    directory: &RelayDirectory,
    request: &PexRequest,
    self_descriptor: Option<&RelayDescriptor>,
) -> PexResponse {
    let want = (request.want as usize).min(MAX_DESCRIPTORS_PER_RESPONSE);
    let requester = request.requester.as_ref().map(|r| r.node_id);
    let now = crate::protocol::hint::current_timestamp();
    let cutoff = now.saturating_sub(DESCRIPTOR_TTL_SECS);

    let mut pool: Vec<RelayDescriptor> = directory
        .all()
        .into_iter()
        // 要求者自身を返しても情報にならない
        .filter(|r| Some(r.node_id) != requester)
        // 期限切れの記述子は配らない（死んだノードを網に広め続けない）
        .filter(|r| r.issued_at >= cutoff)
        .cloned()
        .collect();

    // 自分自身も候補に含める（そうしないと自分の存在が広まらない）
    if let Some(me) = self_descriptor
        && Some(me.node_id) != requester
        && !pool.iter().any(|r| r.node_id == me.node_id)
    {
        pool.push(me.clone());
    }

    pool.shuffle(&mut rand::thread_rng());
    pool.truncate(want);

    // leaseSet もランダムに選ぶ（近い順に返すと一部の領域だけが濃く伝わる）
    // 自分が保持者として出した leaseSet は配らない。自分のリレーが真っ先に配ると
    // 「この SID はこのリレー（IP）」と結びつく。他の経路から十分に広がる
    let mut lease_sets: Vec<LeaseSet> = directory
        .lease_sets()
        .into_iter()
        .filter(|l| !directory.is_own_sid(&l.sid))
        .cloned()
        .collect();
    lease_sets.shuffle(&mut rand::thread_rng());
    lease_sets.truncate(MAX_LEASE_SETS_PER_RESPONSE);

    PexResponse {
        relays: pool,
        lease_sets,
    }
}

/// 応答を取り込む。戻り値は新規に追加できた件数
///
/// PoW 検証に落ちた記述子は黙って捨てる。leaseSet も同じ（検証に落ちたものだけを捨てる）。
/// 1件の不正で応答全体を捨てると、攻撃者が1件混ぜるだけで
/// PEX を妨害できてしまう。
pub fn absorb_response(directory: &mut RelayDirectory, response: PexResponse) -> usize {
    absorb_response_with_conflicts(directory, response).0
}

/// 応答を取り込み、`(新しく増えた数, 既存の記述子と衝突して入れられなかったもの)` を返す
///
/// 衝突したもの（同じ IP:port・IP ごとの上限）は、呼び出し側が到達確認で決着させる
/// （[`RelayDirectory::blocking_claims`]）。
pub fn absorb_response_with_conflicts(
    directory: &mut RelayDirectory,
    response: PexResponse,
) -> (usize, Vec<(RelayDescriptor, Vec<crate::crypto::identity::NodeId>)>) {
    let before = directory.len();
    let mut conflicts = Vec::new();

    for descriptor in response.relays {
        if directory.insert(descriptor.clone()).is_err() {
            let blockers = directory.blocking_claims(&descriptor);
            if !blockers.is_empty() {
                conflicts.push((descriptor, blockers));
            }
        }
    }

    // leaseSet は検証（署名・枠の PoW・丸め・期限）に通ったものだけが入る。
    // 落ちたものは黙って捨てる（1 件の不正で応答全体を捨てない）。
    for lease in response.lease_sets {
        let _ = directory.insert_lease_set(lease);
    }

    (directory.len().saturating_sub(before), conflicts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::NodeId;
    use crate::net::ring;

    fn descriptor(n: u8) -> RelayDescriptor {
        RelayDescriptor {
            node_id: NodeId([n; 32]),
            addr: format!("127.0.0.1:{}", 9000 + u16::from(n)).parse().unwrap(),
            x25519_pub: [n; 32],
            pow_nonce: 0,
            uptime_secs: 3600,
            tier: crate::net::reachability::Tier::Open,
            issued_at: crate::protocol::hint::current_timestamp(),
            signature: Vec::new(),
        }
    }

    /// 署名済みの記述子（取り込みの検証を通るもの）
    fn signed(identity: &crate::crypto::identity::Identity, pow_nonce: u64) -> RelayDescriptor {
        RelayDescriptor::new_signed(
            identity,
            "127.0.0.1:9000".parse().unwrap(),
            pow_nonce,
            crate::net::reachability::Tier::Open,
        )
    }

    /// 選択ロジック用のディレクトリ（検証は absorb 系のテストで見る）
    fn directory(count: u8) -> RelayDirectory {
        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 0);
        for n in 1..=count {
            dir.insert_unchecked(descriptor(n));
        }
        dir
    }

    #[test]
    fn request_survives_wire_roundtrip() {
        let req = PexRequest::new(descriptor(1));
        let decoded = PexRequest::decode(&req.encode().unwrap()).unwrap();
        assert_eq!(decoded.requester.unwrap().node_id, req.requester.unwrap().node_id);
    }

    #[test]
    fn response_is_capped_on_the_wire() {
        // 増幅攻撃を防ぐため、受信側でも上限を確認する
        let oversized = PexResponse {
            relays: (0..=MAX_DESCRIPTORS_PER_RESPONSE)
                .map(|n| descriptor(n as u8))
                .collect(),
            lease_sets: Vec::new(),
        };
        let bytes = oversized.encode().unwrap();

        assert!(
            PexResponse::decode(&bytes).is_err(),
            "上限超えの応答を受け入れると増幅攻撃の踏み台になる"
        );
    }

    #[test]
    fn response_is_capped_on_send() {
        let dir = directory(200);
        let response = select_response(&dir, &PexRequest::new(descriptor(250)), None);

        assert_eq!(response.relays.len(), MAX_DESCRIPTORS_PER_RESPONSE);
    }

    #[test]
    fn honours_a_smaller_want() {
        let dir = directory(100);
        let mut req = PexRequest::new(descriptor(250));
        req.want = 5;

        assert_eq!(select_response(&dir, &req, None).relays.len(), 5);
    }

    #[test]
    fn never_returns_the_requester_to_itself() {
        let dir = directory(10);
        let req = PexRequest::new(descriptor(3));

        let response = select_response(&dir, &req, None);
        assert!(!response.relays.iter().any(|r| r.node_id == NodeId([3u8; 32])));
    }

    #[test]
    fn includes_itself_so_its_existence_spreads() {
        // 自分を返さないと、種ノード以外は誰にも知られないまま
        let dir = directory(3);
        let me = descriptor(200);

        let response = select_response(&dir, &PexRequest::new(descriptor(250)), Some(&me));
        assert!(response.relays.iter().any(|r| r.node_id == me.node_id));
    }

    #[test]
    fn selection_is_randomised() {
        // 近い順に返すとリング上の特定領域だけが濃く伝播して偏る
        let dir = directory(200);
        let req = PexRequest::new(descriptor(250));

        let a: Vec<_> = select_response(&dir, &req, None)
            .relays
            .iter()
            .map(|r| r.node_id)
            .collect();
        let b: Vec<_> = select_response(&dir, &req, None)
            .relays
            .iter()
            .map(|r| r.node_id)
            .collect();

        assert_ne!(a, b, "毎回同じ集合を返している");
    }

    #[test]
    fn does_not_hand_out_expired_descriptors() {
        // 死んだノードや大昔の記述子を PEX で配り続けない
        let mut dir = directory(3);
        let mut stale = descriptor(9);
        stale.issued_at = 0; // TTL より十分古い
        dir.insert_unchecked(stale);

        let response = select_response(&dir, &PexRequest::new(descriptor(250)), None);
        assert!(!response.relays.iter().any(|r| r.node_id == NodeId([9u8; 32])));
    }

    #[test]
    fn absorb_counts_new_entries() {
        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 0);
        // 別ノードなのでアドレスも別にする（同じ addr を別 NodeId が名乗ると弾かれる）
        let response = PexResponse {
            relays: (0..5u16)
                .map(|port| {
                    RelayDescriptor::new_signed(
                        &crate::crypto::identity::Identity::generate(),
                        format!("127.0.0.1:{}", 9100 + port).parse().unwrap(),
                        0,
                        crate::net::reachability::Tier::Open,
                    )
                })
                .collect(),
            lease_sets: Vec::new(),
        };

        assert_eq!(absorb_response(&mut dir, response.clone()), 5);
        assert_eq!(absorb_response(&mut dir, response), 0, "既知は増えない");
    }

    #[test]
    fn one_bad_descriptor_does_not_poison_the_batch() {
        // 1件の不正で応答全体を捨てると、攻撃者が1件混ぜるだけで PEX を止められる
        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 8); // PoW 必須

        let id = crate::crypto::identity::Identity::generate();
        let nonce =
            crate::crypto::pow::node_id::solve(id.public_id().as_bytes(), 8, 1_000_000).unwrap();
        let good = signed(&id, nonce);

        let bad = descriptor(2); // pow_nonce = 0 のまま・署名なし

        let added = absorb_response(
            &mut dir,
            PexResponse {
                relays: vec![bad, good.clone()],
                lease_sets: Vec::new(),
            },
        );

        assert_eq!(added, 1, "不正な1件だけを捨てて、正当な分は取り込むこと");
        assert!(dir.get(&good.node_id).is_some());
    }

    // ---- leaseSet ----

    fn lease(id: &crate::crypto::identity::Identity) -> LeaseSet {
        use crate::net::lease_set::{solve_slots, LeaseGateway};
        LeaseSet::new_signed(
            id,
            solve_slots(&id.public_id().0, 2, 0, 1).unwrap(),
            vec![LeaseGateway {
                gateway: NodeId([1; 32]),
                tunnel_id: [2; 32],
            }],
            crate::protocol::hint::current_timestamp(),
        )
        .unwrap()
    }

    #[test]
    fn response_with_lease_sets_survives_wire_roundtrip() {
        let id = crate::crypto::identity::Identity::generate();
        let response = PexResponse {
            relays: vec![descriptor(1)],
            lease_sets: vec![lease(&id)],
        };
        let decoded = PexResponse::decode(&response.encode().unwrap()).unwrap();
        assert_eq!(decoded.lease_sets, response.lease_sets);
        assert_eq!(decoded.relays.len(), 1);
    }

    #[test]
    fn lease_sets_are_capped_on_the_wire() {
        let id = crate::crypto::identity::Identity::generate();
        let oversized = PexResponse {
            relays: Vec::new(),
            lease_sets: vec![lease(&id); MAX_LEASE_SETS_PER_RESPONSE + 1],
        };
        assert!(PexResponse::decode(&oversized.encode().unwrap()).is_err());

        let at_limit = PexResponse {
            relays: Vec::new(),
            lease_sets: vec![lease(&id); MAX_LEASE_SETS_PER_RESPONSE],
        };
        assert!(PexResponse::decode(&at_limit.encode().unwrap()).is_ok());
    }

    #[test]
    fn own_lease_set_is_never_served_over_pex() {
        let mine = crate::crypto::identity::Identity::generate();
        let other = crate::crypto::identity::Identity::generate();
        let mut dir = directory(3);
        dir.insert_lease_set(lease(&mine)).unwrap();
        dir.insert_lease_set(lease(&other)).unwrap();
        dir.mark_own_sid(mine.public_id().0);
        let response = select_response(&dir, &PexRequest::new(descriptor(250)), None);
        assert_eq!(response.lease_sets.len(), 1);
        assert_eq!(response.lease_sets[0].sid, other.public_id().0, "自分の SID は配らない");
    }

    #[test]
    fn lease_sets_are_capped_on_send() {
        let mut dir = directory(3);
        for _ in 0..MAX_LEASE_SETS_PER_RESPONSE + 10 {
            dir.insert_lease_set(lease(&crate::crypto::identity::Identity::generate())).unwrap();
        }
        let response = select_response(&dir, &PexRequest::new(descriptor(250)), None);
        assert_eq!(response.lease_sets.len(), MAX_LEASE_SETS_PER_RESPONSE);
    }

    #[test]
    fn absorb_takes_valid_lease_sets_and_drops_bad_ones() {
        let good_id = crate::crypto::identity::Identity::generate();
        let good = lease(&good_id);
        let mut bad = lease(&crate::crypto::identity::Identity::generate());
        bad.gateways[0].tunnel_id = [9; 32]; // 署名が合わない

        let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 0);
        absorb_response(
            &mut dir,
            PexResponse {
                relays: Vec::new(),
                lease_sets: vec![bad, good.clone()],
            },
        );
        assert_eq!(dir.lease_set_count(), 1, "不正な 1 件だけを捨てる");
        assert!(dir.lease_set(&good.sid).is_some());
    }

    #[test]
    fn lease_sets_travel_between_directories() {
        let mut a = directory(3);
        let id = crate::crypto::identity::Identity::generate();
        a.insert_lease_set(lease(&id)).unwrap();

        let response = select_response(&a, &PexRequest::new(descriptor(250)), None);
        let mut b = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 0);
        absorb_response(&mut b, PexResponse::decode(&response.encode().unwrap()).unwrap());
        assert!(b.lease_set(&id.public_id().0).is_some());
    }
}
