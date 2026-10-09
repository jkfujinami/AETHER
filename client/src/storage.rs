//! 保持者の役割 ── 受け口のトンネルを張り、leaseSet を出し続ける（Part 23 の 5.2、Part 24 の L1・L2）
//!
//! 常駐のときだけ動く。保持者 H は IP と切り離した身元（SID = `storage.key`）で枠を取り、
//! 自分宛ての**受け口のトンネル**を 3 本張って、その入口を leaseSet にして配る。
//!
//! ```text
//! 受け口:  GW_h ──→ M_h ──→ G_h ──(H が張った接続)──→ H
//!          一様に選ぶ  60 日固定  自分のガード
//! ```
//!
//! # 役割の流れ
//!
//! 1. 枠: 容量から枠の数を決め、網の難易度で PoW を解く（`spawn_blocking`）。解は
//!    `storage_slots.bin` に残し、SID・難易度・枠の数が変わらない限り解き直さない。
//!    解けるまで leaseSet は出さない。
//! 2. 受け口: 3 本張る。形は返信トンネル（[`crate::pull`]）と同じで、構築の指示は
//!    **自分の回路の出口経由**で届ける。
//! 3. leaseSet: 3 本がそろい、一周の確認が通ったら作る。自分のディレクトリに入れ、
//!    ランダムなリレー 3 台へ出口経由で渡す（以後は PEX が広げる）。
//! 4. 延長: 中継側の登録は 30 分で切れるので、同じ指示を 10 分ごとに同じ経路で送り直す。
//! 5. 出し直し: 発行から寿命の 1/3〜2/3 の間のランダムな時刻に、**新しい 3 本**で次の
//!    leaseSet を出す。古い受け口は、古い leaseSet の期限 + 10 分まで延長し続ける。
//! 6. 一周の確認: 5 分ごとに各受け口へ自分の回路から目印を送り、戻るかを見る。
//!    2 回続けて戻らない受け口は作り直し、leaseSet を早めに出し直す。
//!
//! # 誰にも見せないもの
//!
//! **H から M_h・GW_h・リレーへ直接送らない。** 直接送ってよいのは自分のガード G_h だけ
//! （ガードは元々こちらの IP を知っている）。構築・延長・leaseSet の配布・一周の確認は、
//! すべて自分の回路の出口経由で送る。ログにも、受け口やリレーのアドレスは `debug!` までにしか出さない。
//!
//! このタスクで処理する受け口の中身は `HOLDER_PROBE` だけ。`HOLDER_PUT`・`HOLDER_GET` は
//! 今は捨てる（置く・取るの経路は後の段で足す）。

use crate::circuit::Circuit;
use crate::client::AetherClient;
use crate::error::{ClientError, Result};
use crate::events;
use crate::keys::KeyFiles;
use aether_core::crypto::identity::{Identity, NodeId};
use aether_core::net::guard::GUARD_ROTATION_SECS;
use aether_core::net::holder::{
    build_holder_message, parse_holder_message, parse_probe_marker, HOLDER_GET, HOLDER_PROBE, HOLDER_PUT,
};
use aether_core::net::lease_set::{
    slot_count_for_capacity, solve_slots, LeaseGateway, LeaseSet, SlotProof, ISSUED_AT_GRANULARITY_SECS,
    LEASE_SET_TTL_SECS, MAX_GATEWAYS_PER_LEASE_SET,
};
use aether_core::net::relay::RelayClient;
use aether_core::net::relay_list::RelayDescriptor;
use aether_core::net::tunnel::InboundTunnel;
use aether_core::protocol::hint::current_timestamp;
use aether_core::protocol::wire::PacketType;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tracing::debug;

/// 張る受け口の数（leaseSet に載せられる上限と同じ）
const HOLDER_TUNNELS: usize = MAX_GATEWAYS_PER_LEASE_SET;

/// 構築の指示を各ホップへ送り直す間隔
///
/// 中継側の登録の寿命（`TUNNEL_TTL` 30 分）の 1/3。2 回続けて失敗しても切れない。
const TUNNEL_REFRESH: Duration = Duration::from_secs(10 * 60);
/// 延長に失敗したときに次を試すまでの間隔
const REFRESH_RETRY: Duration = Duration::from_secs(60);

/// 受け口の一周の確認の間隔
const PROBE_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// 目印が戻るのを待つ時間
const PROBE_WAIT: Duration = Duration::from_secs(8);
/// この回数続けて戻らない受け口は作り直す
const PROBE_FAILS_TO_REBUILD: u32 = 2;
/// 全部の受け口が戻らなかった確認の回がこの回数続いたら、中間（vanguard）を選び直す
///
/// 受け口が全部落ちるのは、共有の中間かガードが落ちたとき。
const VANGUARD_MAX_FAILED_ROUNDS: u32 = 2;

/// 中間（vanguard）を固定する期間。ガードと同じ 60 日
///
/// 短いと、中間がランダムに近づいて保持者のガードが割られやすくなる（Part 24）。
const VANGUARD_ROTATION_SECS: u64 = GUARD_ROTATION_SECS;

/// 古い leaseSet の期限の後も、受け口を延長し続ける余裕（秒）
///
/// 期限ぎりぎりに古い leaseSet を使っている相手の中身を取りこぼさない。
const RETIRED_GRACE_SECS: u64 = 600;

/// 見回りの間隔
const TICK: Duration = Duration::from_secs(10);
/// 構築の指示が各ホップへ行き渡るのを待つ時間
const TUNNEL_SETTLE: Duration = Duration::from_millis(500);
/// 送った後、回路を閉じる前に書き出しを待つ時間（書いた直後に閉じると中身が失われる）
const SEND_FLUSH: Duration = Duration::from_secs(2);

/// 受け口を作れなかったときの待ち（倍々に延ばす）
const BUILD_BACKOFF_MIN: Duration = Duration::from_secs(30);
const BUILD_BACKOFF_MAX: Duration = Duration::from_secs(5 * 60);

/// 枠の PoW を探す回数の上限（NodeId の PoW と同じ）
const SLOT_MAX_ATTEMPTS: u64 = 1 << 24;

/// leaseSet を配るリレーの数
const PUBLISH_FANOUT: usize = 3;

/// 自分宛てではない目印（試験と診断用）を覚えておく数
const EXTERNAL_PROBES_KEPT: usize = 64;

// ---------------------------------------------------------------------------
// 純粋な部分（選び方・時刻・保存）
// ---------------------------------------------------------------------------

/// 受け口の gateway を選ぶ（Part 24 の L2）
///
/// **到達可能なリレーから一様に選び、除外しない。** ガード・中間と同じリレーでも、
/// ガードと同じネットワークのリレーでも、そのまま使う。除外規則は除外された側
/// （ガードのネットワーク）を、時間をかけて浮かび上がらせてしまう。
/// 選ばないのは自分自身だけ（自分を gateway にすると受け口の意味が無い）。
pub(crate) fn pick_gateway<'a>(relays: &'a [RelayDescriptor], me: &NodeId) -> Option<&'a RelayDescriptor> {
    let pool: Vec<&RelayDescriptor> = relays
        .iter()
        .filter(|r| r.tier.accepts_strangers() && r.node_id != *me)
        .collect();
    pool.choose(&mut rand::thread_rng()).copied()
}

/// 保持者の中間（vanguard）。一度選んだら 60 日使い続ける
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct Vanguard {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub x25519_pub: [u8; 32],
    /// 選んだ時刻 (UNIX秒)
    pub selected_at: u64,
    /// 全部の受け口が戻らなかった確認の回が続いた数
    pub failed_rounds: u32,
}

impl Vanguard {
    fn new(d: &RelayDescriptor, now: u64) -> Self {
        Self {
            node_id: d.node_id,
            addr: d.addr,
            x25519_pub: d.x25519_pub,
            selected_at: now,
            failed_rounds: 0,
        }
    }

    pub(crate) fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.selected_at) >= VANGUARD_ROTATION_SECS
    }

    /// 期限内で、確認の失敗が続いていない
    pub(crate) fn is_usable(&self, now: u64) -> bool {
        !self.is_expired(now) && self.failed_rounds < VANGUARD_MAX_FAILED_ROUNDS
    }
}

/// 中間を選ぶ。到達可能なリレーから一様に選び、自分と今のガードは使わない
///
/// 中間とガードが同じだと、ガードが受け口の 2 ホップを見られる。
pub(crate) fn pick_vanguard(relays: &[RelayDescriptor], me: &NodeId, guard: &NodeId, now: u64) -> Option<Vanguard> {
    let pool: Vec<&RelayDescriptor> = relays
        .iter()
        .filter(|r| r.tier.accepts_strangers() && r.node_id != *me && r.node_id != *guard)
        .collect();
    pool.choose(&mut rand::thread_rng()).map(|d| Vanguard::new(d, now))
}

/// 保存した中間を読む（無ければ `None`）
///
/// **壊れていても黙って選び直さず、エラーにする**（ガードと同じ。起動のたびに選び直すと
/// 固定の意味が消える）。
pub(crate) fn load_vanguard(keys: &KeyFiles) -> Result<Option<Vanguard>> {
    let Some(bytes) = keys.read_secure(&keys.storage_vanguard_path())? else {
        return Ok(None);
    };
    bincode::deserialize(&bytes)
        .map(Some)
        .map_err(|e| ClientError::invalid(format!("storage_vanguard.bin が壊れています: {}", e)))
}

pub(crate) fn save_vanguard(keys: &KeyFiles, v: &Vanguard) -> Result<()> {
    let bytes = bincode::serialize(v).map_err(|e| ClientError::invalid(e.to_string()))?;
    keys.write_secure(&keys.storage_vanguard_path(), &bytes)
}

/// 次の leaseSet を出す時刻（UNIX秒）。**発行から寿命の 1/3〜2/3 の間のランダムな時刻**
///
/// 毎回同じ時刻に出し直すと、更新の周期から同じ SID が結びつく（Part 24 の L1）。
pub(crate) fn reissue_at(issued_at: u64, rng: &mut impl rand::Rng) -> u64 {
    issued_at + rng.gen_range(LEASE_SET_TTL_SECS / 3..=LEASE_SET_TTL_SECS * 2 / 3)
}

/// 保存する枠の解
#[derive(Serialize, Deserialize)]
struct StoredSlots {
    sid: [u8; 32],
    difficulty: u32,
    slots: Vec<SlotProof>,
}

/// 保存した枠の解を読む。SID・難易度・枠の数のどれかが違えば `None`（解き直し）
pub(crate) fn load_slots(keys: &KeyFiles, sid: &[u8; 32], difficulty: u32, count: u32) -> Result<Option<Vec<SlotProof>>> {
    let Some(bytes) = keys.read_secure(&keys.storage_slots_path())? else {
        return Ok(None);
    };
    // 読めなければ解き直せばよい（解は SID から作り直せる。ガードと違い、固定が意味を持つ記録ではない）
    let Ok(stored) = bincode::deserialize::<StoredSlots>(&bytes) else {
        return Ok(None);
    };
    let in_order = stored.slots.iter().enumerate().all(|(i, s)| s.index as usize == i);
    Ok((stored.sid == *sid && stored.difficulty == difficulty && stored.slots.len() == count as usize && in_order)
        .then_some(stored.slots))
}

pub(crate) fn save_slots(keys: &KeyFiles, sid: &[u8; 32], difficulty: u32, slots: &[SlotProof]) -> Result<()> {
    let stored = StoredSlots {
        sid: *sid,
        difficulty,
        slots: slots.to_vec(),
    };
    let bytes = bincode::serialize(&stored).map_err(|e| ClientError::invalid(e.to_string()))?;
    keys.write_secure(&keys.storage_slots_path(), &bytes)
}

/// 枠の解を用意する。保存済みで合っていればそれを使い、無ければ解いて保存する
///
/// PoW は重いので `spawn_blocking` で解く（非同期ランタイムのスレッドを塞がない）。
async fn ensure_slots(keys: &KeyFiles, sid: &Identity, difficulty: u32, count: u32) -> Result<Vec<SlotProof>> {
    let pk = sid.public_id().0;
    if let Some(slots) = load_slots(keys, &pk, difficulty, count)? {
        return Ok(slots);
    }
    let slots = tokio::task::spawn_blocking(move || solve_slots(&pk, count, difficulty, SLOT_MAX_ATTEMPTS))
        .await
        .map_err(|e| ClientError::invalid(format!("枠の PoW の計算に失敗しました: {}", e)))??;
    save_slots(keys, &pk, difficulty, &slots)?;
    Ok(slots)
}

// ---------------------------------------------------------------------------
// 受け口に届いたものの振り分け
// ---------------------------------------------------------------------------

/// 保持者と、外（試験・診断）に見せる状態の共有部分
#[derive(Default)]
pub(crate) struct HolderShared {
    /// 自分が送った一周の確認で、戻りを待っている目印
    pending: Mutex<HashMap<[u8; 32], tokio::sync::oneshot::Sender<()>>>,
    /// 自分のものではない目印（別のクライアントが `HOLDER_PROBE` で送ってきたもの）
    external: Mutex<VecDeque<[u8; 32]>>,
    /// 最後に出した leaseSet
    lease: Mutex<Option<LeaseSet>>,
}

/// 保持者の役割の状態（試験と診断用）
#[derive(Debug, Clone)]
pub struct HolderStatus {
    /// 最後に出した leaseSet（まだ出していなければ `None`）
    pub lease_set: Option<LeaseSet>,
    /// 受け口に届いた、自分の確認ではない `HOLDER_PROBE` の目印
    pub probes_received: Vec<[u8; 32]>,
}

impl HolderShared {
    /// 受け口で開いた中身を種別で振り分ける
    fn dispatch(&self, plain: &[u8]) {
        let (kind, body) = match parse_holder_message(plain) {
            Ok(v) => v,
            Err(e) => {
                debug!("holder: bad message: {}", e);
                return;
            }
        };
        match kind {
            HOLDER_PROBE => {
                let Ok(marker) = parse_probe_marker(body) else {
                    debug!("holder: bad probe marker");
                    return;
                };
                if let Some(waiter) = self.pending.lock().unwrap().remove(&marker) {
                    let _ = waiter.send(());
                } else {
                    let mut seen = self.external.lock().unwrap();
                    if seen.len() >= EXTERNAL_PROBES_KEPT {
                        seen.pop_front();
                    }
                    seen.push_back(marker);
                }
            }
            // 置く・取るの処理は後の段で足す。今は捨てる
            HOLDER_PUT => debug!("holder: PUT ({} bytes) is not handled yet; dropping", body.len()),
            HOLDER_GET => debug!("holder: GET ({} bytes) is not handled yet; dropping", body.len()),
            other => debug!("holder: unknown message kind {}; dropping", other),
        }
    }
}

// ---------------------------------------------------------------------------
// 受け口 1 本
// ---------------------------------------------------------------------------

/// 張った受け口 1 本と、延長のために覚えておく構築の指示
struct HolderTunnel {
    tunnel: Arc<InboundTunnel>,
    /// 受け口（leaseSet に載せる）
    gateway: RelayDescriptor,
    /// 中間（vanguard）の NodeId。vanguard が変わったら作り直す
    middle: NodeId,
    middle_addr: SocketAddr,
    guard_addr: SocketAddr,
    /// 各ホップへの構築の指示。延長では同じものを同じ経路で送り直す
    gw_build: Vec<u8>,
    mid_build: Vec<u8>,
    guard_build: Vec<u8>,
    self_build: Vec<u8>,
    next_refresh: Instant,
    /// 続けて戻らなかった確認の数
    probe_failures: u32,
}

impl HolderTunnel {
    fn lease_gateway(&self) -> LeaseGateway {
        LeaseGateway {
            gateway: self.gateway.node_id,
            tunnel_id: self.tunnel.endpoint.tunnel_id,
        }
    }
}

enum ProbeOutcome {
    Alive,
    Dead,
    /// 回路を組めない・送れないなど、受け口のせいではない失敗
    Skipped,
}

/// `[gateway の tunnel_id][中身]` を回路の出口経由で gateway へ渡す
///
/// 中身は 12 バイト以上であること（`TunnelData` は ID の後に最低 12 バイト要る）。
/// 保持者への中身（`HOLDER_*`）は種別 1 + 本文 32 以上なので常に満たす。
async fn send_tunnel_data(client: &RelayClient, gateway: SocketAddr, tunnel_id: &[u8; 32], message: &[u8]) -> Result<()> {
    let mut data = tunnel_id.to_vec();
    data.extend_from_slice(message);
    client
        .send_onion_message_typed(PacketType::TunnelData, &data, gateway)
        .await?;
    Ok(())
}

impl AetherClient {
    /// 保持者の役割を起こす。常駐のときだけ呼ぶ
    ///
    /// `Weak` で持ち、クライアントが無くなれば終わる。
    pub(crate) fn spawn_holder(self: &Arc<Self>, directory_pow_difficulty: u32, capacity_mb: u64) {
        let weak = Arc::downgrade(self);
        let events = self.events.clone();
        tokio::spawn(async move {
            if let Err(e) = run_holder(weak, directory_pow_difficulty, capacity_mb).await {
                debug!("holder stopped: {}", e);
                events::warning(&events, "保存の役割を始められませんでした（詳細はログ）");
            }
        });
    }

    /// 保持者の役割の状態（試験と診断用）
    #[doc(hidden)]
    pub fn holder_status(&self) -> HolderStatus {
        HolderStatus {
            lease_set: self.holder.lease.lock().unwrap().clone(),
            probes_received: self.holder.external.lock().unwrap().iter().copied().collect(),
        }
    }

    /// leaseSet の受け口へ、自分の回路の出口経由で中身を送る
    ///
    /// 受け口の gateway は、一覧の NodeId から引いたアドレスへ出口から渡される。
    /// 中身の形は [`aether_core::net::holder`]（種別 1 バイト + 本文）。
    #[doc(hidden)]
    pub async fn send_to_lease_gateway(&self, gateway: &LeaseGateway, message: &[u8]) -> Result<()> {
        let addr = self
            .node
            .directory()
            .read()
            .await
            .get(&gateway.gateway)
            .map(|d| d.addr)
            .ok_or_else(|| ClientError::network("受け口のリレーが一覧にありません"))?;
        let probed = self.take_probed_circuit(&[]).await?;
        send_tunnel_data(&probed.circuit.client, addr, &gateway.tunnel_id, message).await?;
        tokio::time::sleep(SEND_FLUSH).await;
        Ok(())
    }

    /// 受け口 1 本の目印を、自分の回路から送って、戻るかを見る
    async fn probe_holder_tunnel(&self, t: &HolderTunnel) -> ProbeOutcome {
        let Ok(probed) = self.take_probed_circuit(&[]).await else {
            return ProbeOutcome::Skipped;
        };
        let marker: [u8; 32] = rand::random();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.holder.pending.lock().unwrap().insert(marker, tx);
        let message = build_holder_message(HOLDER_PROBE, &marker);
        let sent = send_tunnel_data(&probed.circuit.client, t.gateway.addr, &t.tunnel.endpoint.tunnel_id, &message).await;
        if sent.is_err() {
            self.holder.pending.lock().unwrap().remove(&marker);
            return ProbeOutcome::Skipped;
        }
        let alive = matches!(tokio::time::timeout(PROBE_WAIT, rx).await, Ok(Ok(())));
        self.holder.pending.lock().unwrap().remove(&marker);
        if alive {
            ProbeOutcome::Alive
        } else {
            ProbeOutcome::Dead
        }
    }

    /// 構築の指示を各ホップへ送る（作るときも延長のときも同じ経路・同じ中身）
    ///
    /// - G_h（ガード）: 直接。ガードは元々こちらの IP を知っている。自分の待ち受けと同じ
    ///   ソケットから張った接続の上で渡し、ガードはその接続へ返す。
    /// - 自分の分: ネットワークを通さない。
    /// - M_h・GW_h: **回路の出口経由**。直接送ると、こちらの IP が見える。
    async fn send_builds(&self, t: &HolderTunnel, circuit: &Circuit) -> Result<()> {
        self.node.pin_connection(t.guard_addr).await?;
        self.node
            .send_direct(t.guard_addr, PacketType::TunnelBuild, &t.guard_build)
            .await?;
        self.node.accept_own_tunnel_build(&t.self_build).await?;
        circuit
            .client
            .send_onion_message_typed(PacketType::TunnelBuild, &t.mid_build, t.middle_addr)
            .await?;
        circuit
            .client
            .send_onion_message_typed(PacketType::TunnelBuild, &t.gw_build, t.gateway.addr)
            .await?;
        Ok(())
    }

    /// leaseSet をランダムなリレー数台へ、回路の出口経由で渡す
    ///
    /// 自分の IP から直接送ると、受けたリレーに SID と IP の対応が見える。
    async fn publish_lease_set(&self, lease: &LeaseSet) -> Result<()> {
        let probed = self.take_probed_circuit(&[]).await?;
        let me = self.node.descriptor.node_id;
        let targets: Vec<SocketAddr> = {
            let dir = self.node.directory();
            let dir = dir.read().await;
            let relays: Vec<&RelayDescriptor> = dir
                .all()
                .into_iter()
                .filter(|r| r.tier.accepts_strangers() && r.node_id != me)
                .collect();
            relays
                .choose_multiple(&mut rand::thread_rng(), PUBLISH_FANOUT)
                .map(|r| r.addr)
                .collect()
        };
        if targets.is_empty() {
            return Err(ClientError::network("leaseSet を渡せるリレーがありません"));
        }
        let bytes = bincode::serialize(lease).map_err(|e| ClientError::invalid(e.to_string()))?;
        for addr in targets {
            probed
                .circuit
                .client
                .send_onion_message_typed(PacketType::LeaseSetPublish, &bytes, addr)
                .await?;
        }
        tokio::time::sleep(SEND_FLUSH).await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 役割の本体
// ---------------------------------------------------------------------------

struct Holder {
    keys: KeyFiles,
    sid: Arc<Identity>,
    slots: Vec<SlotProof>,
    vanguard: Option<Vanguard>,
    /// 今の leaseSet に載せる（載せる予定の）受け口
    current: Vec<HolderTunnel>,
    /// 古い leaseSet にだけ載っている受け口と、延長をやめる時刻（UNIX秒）
    retired: Vec<(HolderTunnel, u64)>,
    /// 最後に出した leaseSet
    lease: Option<LeaseSet>,
    /// 受け口が変わって leaseSet を出し直す必要がある
    dirty: bool,
    /// 出した leaseSet を配り終えていない
    publish_pending: bool,
    /// 次に計画どおり出し直す時刻（UNIX秒）
    next_reissue_at: Option<u64>,
    next_probe: Instant,
    build_backoff: Duration,
    build_retry_at: Instant,
    announced: bool,
}

async fn run_holder(weak: Weak<AetherClient>, difficulty: u32, capacity_mb: u64) -> Result<()> {
    let (keys, shared) = {
        let Some(client) = weak.upgrade() else { return Ok(()) };
        (client.keys.clone(), client.holder.clone())
    };
    let sid = Arc::new(keys.load_or_create_storage_identity()?);
    let count = slot_count_for_capacity(capacity_mb.saturating_mul(1024 * 1024));
    // 解けるまで leaseSet は出さない
    let slots = ensure_slots(&keys, &sid, difficulty, count).await?;
    let vanguard = load_vanguard(&keys)?;

    let mut holder = Holder {
        keys,
        sid,
        slots,
        vanguard,
        current: Vec::new(),
        retired: Vec::new(),
        lease: None,
        dirty: true,
        publish_pending: false,
        next_reissue_at: None,
        next_probe: Instant::now() + PROBE_INTERVAL,
        build_backoff: BUILD_BACKOFF_MIN,
        build_retry_at: Instant::now(),
        announced: false,
    };

    loop {
        let Some(client) = weak.upgrade() else { return Ok(()) };
        // リレーが揃う前は組まない
        if client.node.directory_size().await > client.min_relays {
            holder.step(&client, &shared).await;
        }
        drop(client);
        tokio::time::sleep(TICK).await;
    }
}

impl Holder {
    /// 見回り 1 回分。期限の来たものから順に片付ける
    async fn step(&mut self, client: &Arc<AetherClient>, shared: &Arc<HolderShared>) {
        let now = current_timestamp();

        // 1. 延長をやめる受け口を捨てる
        let mut kept = Vec::new();
        for (t, keep_until) in std::mem::take(&mut self.retired) {
            if now >= keep_until {
                client.node.unregister_tunnel_sink(&t.tunnel.receive_tunnel_id);
            } else {
                kept.push((t, keep_until));
            }
        }
        self.retired = kept;

        // 2. 延長（今の受け口も、古い leaseSet にだけ載っている受け口も）
        for t in self.current.iter_mut().chain(self.retired.iter_mut().map(|(t, _)| t)) {
            if Instant::now() < t.next_refresh {
                continue;
            }
            let ok = match client.take_probed_circuit(&[]).await {
                Ok(probed) => {
                    let sent = client.send_builds(t, &probed.circuit).await;
                    tokio::time::sleep(SEND_FLUSH).await;
                    sent.is_ok()
                }
                Err(_) => false,
            };
            t.next_refresh = Instant::now() + if ok { TUNNEL_REFRESH } else { REFRESH_RETRY };
            if !ok {
                debug!("holder: tunnel refresh failed; retrying soon");
            }
        }

        // 3. 一周の確認
        if Instant::now() >= self.next_probe {
            self.probe_round(client).await;
            self.next_probe = Instant::now() + PROBE_INTERVAL;
        }

        // 4. 計画どおりの出し直し: 今の受け口を引退させ、新しい 3 本を張る
        if !self.dirty
            && self.current.len() == HOLDER_TUNNELS
            && self.next_reissue_at.is_some_and(|at| now >= at)
        {
            let keep_until = self.lease.as_ref().map_or(now, |l| l.expires_at) + RETIRED_GRACE_SECS;
            for t in self.current.drain(..) {
                self.retired.push((t, keep_until));
            }
            self.next_reissue_at = None;
            self.dirty = true;
        }

        // 5. 足りない受け口を張る
        while self.current.len() < HOLDER_TUNNELS && Instant::now() >= self.build_retry_at {
            match self.build_one(client, shared).await {
                Ok(t) => {
                    self.current.push(t);
                    self.build_backoff = BUILD_BACKOFF_MIN;
                    self.dirty = true;
                    // 中間が変わっていたら、前の中間の受け口はもう使わない
                    self.drop_stale(client);
                }
                Err(e) => {
                    debug!("holder: building a tunnel failed: {}", e);
                    self.build_retry_at = Instant::now() + self.build_backoff;
                    self.build_backoff = (self.build_backoff * 2).min(BUILD_BACKOFF_MAX);
                    break;
                }
            }
        }

        // 6. leaseSet を出す（3 本そろい、一周の確認が通っているときだけ）
        if self.dirty && self.current.len() == HOLDER_TUNNELS {
            match self.issue_lease(client, shared).await {
                Ok(()) => {}
                Err(e) => debug!("holder: issuing the lease set failed: {}", e),
            }
        }
        // 配り損ねた分は、次の見回りで配り直す
        if self.publish_pending
            && !self.dirty
            && let Some(lease) = self.lease.clone()
            && (lease.is_expired(now) || client.publish_lease_set(&lease).await.is_ok())
        {
            self.publish_pending = false;
        }
    }

    /// 受け口 1 本を張って、一周の確認に通す。通らなければ片付けてエラー
    async fn build_one(&mut self, client: &AetherClient, shared: &Arc<HolderShared>) -> Result<HolderTunnel> {
        let probed = client.take_probed_circuit(&[]).await?;
        let circuit = probed.circuit;
        let me = client.node.descriptor.node_id;
        let relays: Vec<RelayDescriptor> = {
            let dir = client.node.directory();
            let dir = dir.read().await;
            dir.all().into_iter().cloned().collect()
        };
        let now = current_timestamp();
        let vanguard = self.ensure_vanguard(&relays, &me, &circuit.guard.node_id, now)?;
        let gateway = pick_gateway(&relays, &me)
            .ok_or_else(|| ClientError::network("受け口にできるリレーがありません"))?
            .clone();

        let guard = circuit.guard.clone();
        let (tunnel, instructions) = InboundTunnel::build_to_builder(
            vec![gateway.addr, vanguard.addr, guard.addr, client.node.descriptor.addr],
            vec![
                gateway.x25519_pub,
                vanguard.x25519_pub,
                guard.x25519_pub,
                client.node.descriptor.x25519_pub,
            ],
        )?;
        let [gw_build, mid_build, guard_build, self_build]: [(SocketAddr, Vec<u8>); 4] = instructions
            .try_into()
            .map_err(|_| ClientError::invalid("unexpected tunnel instruction count"))?;

        let tunnel = Arc::new(tunnel);
        // 口は指示を出す前に登録する（最初の確認が受け箱に落ちないように）
        let mut rx = client.node.register_tunnel_sink(tunnel.receive_tunnel_id);
        {
            let (shared, tunnel) = (shared.clone(), tunnel.clone());
            tokio::spawn(async move {
                // 口が外されると rx が閉じて終わる
                while let Some(raw) = rx.recv().await {
                    match tunnel.decrypt(&raw) {
                        Ok(plain) => shared.dispatch(&plain),
                        Err(e) => debug!("holder: undecryptable tunnel data: {}", e),
                    }
                }
            });
        }

        let t = HolderTunnel {
            tunnel,
            gateway,
            middle: vanguard.node_id,
            middle_addr: vanguard.addr,
            guard_addr: guard.addr,
            gw_build: gw_build.1,
            mid_build: mid_build.1,
            guard_build: guard_build.1,
            self_build: self_build.1,
            next_refresh: Instant::now() + TUNNEL_REFRESH,
            probe_failures: 0,
        };
        let sent = client.send_builds(&t, &circuit).await;
        if sent.is_ok() {
            tokio::time::sleep(TUNNEL_SETTLE).await;
        }
        drop(circuit);
        let verified = match sent {
            Ok(()) => self.verify_new_tunnel(client, &t).await,
            Err(_) => false,
        };
        if !verified {
            client.node.unregister_tunnel_sink(&t.tunnel.receive_tunnel_id);
            return Err(ClientError::network("受け口の一周の確認が通りませんでした"));
        }
        Ok(t)
    }

    /// 張ったばかりの受け口を確かめる。登録が行き渡るのが遅いことがあるので、2 回まで
    async fn verify_new_tunnel(&self, client: &AetherClient, t: &HolderTunnel) -> bool {
        for attempt in 0..2 {
            if attempt > 0 {
                tokio::time::sleep(SEND_FLUSH).await;
            }
            match client.probe_holder_tunnel(t).await {
                ProbeOutcome::Alive => return true,
                ProbeOutcome::Dead | ProbeOutcome::Skipped => {}
            }
        }
        false
    }

    /// 使える中間を返す。無ければ（期限切れ・確認の失敗が続いた・ガードと同じ）選び直して保存する
    fn ensure_vanguard(&mut self, relays: &[RelayDescriptor], me: &NodeId, guard: &NodeId, now: u64) -> Result<Vanguard> {
        let usable = self
            .vanguard
            .as_ref()
            .is_some_and(|v| v.is_usable(now) && v.node_id != *guard);
        if !usable {
            let v = pick_vanguard(relays, me, guard, now)
                .ok_or_else(|| ClientError::network("中間にできるリレーがありません"))?;
            save_vanguard(&self.keys, &v)?;
            self.vanguard = Some(v);
        }
        Ok(self.vanguard.clone().expect("直前に選んだ"))
    }

    /// 今の中間でない（または使えない）中間の受け口を捨てる
    fn drop_stale(&mut self, client: &AetherClient) {
        let now = current_timestamp();
        let good = self.vanguard.as_ref().filter(|v| v.is_usable(now)).map(|v| v.node_id);
        let before = self.current.len();
        self.current.retain(|t| {
            let keep = good == Some(t.middle);
            if !keep {
                client.node.unregister_tunnel_sink(&t.tunnel.receive_tunnel_id);
            }
            keep
        });
        if self.current.len() != before {
            self.dirty = true;
        }
    }

    /// 全部の受け口を一周の確認にかける。結果で中間の様子と、作り直す受け口を決める
    async fn probe_round(&mut self, client: &AetherClient) {
        let mut alive = 0usize;
        let mut dead = 0usize;
        for i in 0..self.current.len() {
            match client.probe_holder_tunnel(&self.current[i]).await {
                ProbeOutcome::Alive => {
                    alive += 1;
                    self.current[i].probe_failures = 0;
                }
                ProbeOutcome::Dead => {
                    dead += 1;
                    self.current[i].probe_failures += 1;
                }
                ProbeOutcome::Skipped => {}
            }
        }

        // 中間の様子: 1 本でも戻れば中間は生きている。全部戻らない回が続けば選び直す
        if let Some(v) = self.vanguard.as_mut() {
            let before = v.failed_rounds;
            if alive > 0 {
                v.failed_rounds = 0;
            } else if dead > 0 {
                v.failed_rounds += 1;
            }
            if v.failed_rounds != before {
                let v = v.clone();
                if let Err(e) = save_vanguard(&self.keys, &v) {
                    debug!("holder: saving the vanguard failed: {}", e);
                }
            }
        }

        // 2 回続けて戻らない受け口は作り直す（leaseSet も早めに出し直す）
        let before = self.current.len();
        self.current.retain(|t| {
            let keep = t.probe_failures < PROBE_FAILS_TO_REBUILD;
            if !keep {
                client.node.unregister_tunnel_sink(&t.tunnel.receive_tunnel_id);
            }
            keep
        });
        if self.current.len() != before {
            self.dirty = true;
        }
        self.drop_stale(client);
    }

    /// leaseSet を作って、自分のディレクトリに入れ、リレーへ配る
    async fn issue_lease(&mut self, client: &AetherClient, shared: &Arc<HolderShared>) -> Result<()> {
        let now = current_timestamp();
        // 同じ 10 分の枠に 2 度出すと、受け手は新しさで勝てず捨てる。次の枠まで進める
        let floor = self.lease.as_ref().map_or(0, |l| l.issued_at + ISSUED_AT_GRANULARITY_SECS);
        // 未来の発行は受け手が許す幅（10 分）に収まる: floor <= 直近の発行 + 10 分 <= now + 10 分
        let gateways: Vec<LeaseGateway> = self.current.iter().map(HolderTunnel::lease_gateway).collect();
        let lease = LeaseSet::new_signed(&self.sid, self.slots.clone(), gateways, now.max(floor))?;

        {
            let directory = client.node.directory();
            let mut dir = directory.write().await;
            dir.mark_own_sid(lease.sid);
            dir.insert_lease_set(lease.clone())?;
        }
        *shared.lease.lock().unwrap() = Some(lease.clone());
        self.next_reissue_at = Some(reissue_at(lease.issued_at, &mut rand::thread_rng()));
        self.lease = Some(lease.clone());
        self.dirty = false;

        if !self.announced {
            self.announced = true;
            events::progress(&client.events, "保存の受け口を公開しました");
        }
        // 配り損ねたら、見回りのたびに配り直す
        self.publish_pending = client.publish_lease_set(&lease).await.is_err();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_core::net::reachability::Tier;
    use rand::SeedableRng;

    fn relay(n: u8, tier: Tier) -> RelayDescriptor {
        RelayDescriptor::new_signed(
            &Identity::generate(),
            format!("10.{}.0.1:9000", n).parse().unwrap(),
            0,
            tier,
        )
    }

    fn relays(n: u8) -> Vec<RelayDescriptor> {
        (1..=n).map(|i| relay(i, Tier::Open)).collect()
    }

    #[test]
    fn gateway_choice_is_uniform_and_excludes_only_self() {
        // ガード・中間と同じものも、同じネットワークのものも、そのまま選ばれうる
        let pool = relays(6);
        let me = pool[0].node_id;
        let mut counts: HashMap<NodeId, u32> = HashMap::new();
        const DRAWS: u32 = 10_000;
        for _ in 0..DRAWS {
            let g = pick_gateway(&pool, &me).unwrap();
            *counts.entry(g.node_id).or_default() += 1;
        }
        assert!(!counts.contains_key(&me), "自分自身を選んだ");
        assert_eq!(counts.len(), 5, "選ばれないリレーがある（除外している）");
        let expected = DRAWS / 5;
        for (id, c) in &counts {
            assert!(
                c.abs_diff(expected) < expected / 5,
                "一様でない: {:?} が {} 回（期待 {} 前後）",
                id,
                c,
                expected
            );
        }
    }

    #[test]
    fn gateway_choice_skips_unreachable_relays_and_handles_empty() {
        let mut pool = relays(2);
        pool.push(relay(9, Tier::Reversed));
        let me = pool[0].node_id;
        for _ in 0..50 {
            assert_eq!(pick_gateway(&pool, &me).unwrap().node_id, pool[1].node_id, "到達不能なリレーを選んだ");
        }
        assert!(pick_gateway(&[], &me).is_none());
        assert!(pick_gateway(&pool[..1], &me).is_none(), "自分しかいなければ選べない");
    }

    #[test]
    fn vanguard_choice_avoids_self_and_the_guard() {
        let pool = relays(4);
        let (me, guard) = (pool[0].node_id, pool[1].node_id);
        for _ in 0..100 {
            let v = pick_vanguard(&pool, &me, &guard, 1).unwrap();
            assert!(v.node_id != me && v.node_id != guard, "自分かガードを中間にした");
        }
        assert!(pick_vanguard(&pool[..2], &me, &guard, 1).is_none());
    }

    #[test]
    fn vanguard_is_stored_and_reloaded_identically() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        assert_eq!(load_vanguard(&keys).unwrap(), None, "無ければ None");
        let pool = relays(3);
        let v = pick_vanguard(&pool, &pool[0].node_id, &pool[1].node_id, 1_000).unwrap();
        save_vanguard(&keys, &v).unwrap();
        assert_eq!(load_vanguard(&keys).unwrap(), Some(v.clone()), "読み直すと同じ");

        // パスフレーズ付きでも往復し、平文では読めない
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), Some("pw".into()));
        save_vanguard(&keys, &v).unwrap();
        assert_eq!(load_vanguard(&keys).unwrap(), Some(v));
        assert!(KeyFiles::new(dir.path(), None).read_secure(&keys.storage_vanguard_path()).is_err());
    }

    #[test]
    fn corrupt_vanguard_file_is_an_error_not_a_silent_reselect() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        std::fs::write(keys.storage_vanguard_path(), b"garbage").unwrap();
        assert!(load_vanguard(&keys).is_err());
    }

    #[test]
    fn vanguard_is_reselected_after_sixty_days_or_repeated_failures() {
        let pool = relays(3);
        let start = 1_000_000;
        let v = pick_vanguard(&pool, &pool[0].node_id, &pool[1].node_id, start).unwrap();
        assert!(v.is_usable(start));
        assert!(v.is_usable(start + VANGUARD_ROTATION_SECS - 1), "60 日の手前はまだ使う");
        assert!(!v.is_usable(start + VANGUARD_ROTATION_SECS), "60 日で選び直す");
        let mut failing = v.clone();
        failing.failed_rounds = VANGUARD_MAX_FAILED_ROUNDS - 1;
        assert!(failing.is_usable(start), "1 回の失敗ではまだ使う");
        failing.failed_rounds = VANGUARD_MAX_FAILED_ROUNDS;
        assert!(!failing.is_usable(start), "確認の失敗が続いたら選び直す");
    }

    #[test]
    fn reissue_time_scatters_between_a_third_and_two_thirds_of_the_lifetime() {
        let issued = 1_800_000_000;
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let times: Vec<u64> = (0..500).map(|_| reissue_at(issued, &mut rng) - issued).collect();
        assert!(times.iter().all(|t| (LEASE_SET_TTL_SECS / 3..=LEASE_SET_TTL_SECS * 2 / 3).contains(t)));
        let (min, max) = (times.iter().min().unwrap(), times.iter().max().unwrap());
        assert!(max - min > LEASE_SET_TTL_SECS / 6, "散らばっていない: {}..{}", min, max);
        let distinct: std::collections::HashSet<_> = times.iter().collect();
        assert!(distinct.len() > 400, "毎回ほぼ同じ時刻になっている");
    }

    #[test]
    fn solved_slots_are_stored_and_reused_until_sid_difficulty_or_count_changes() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        let sid = Identity::generate().public_id().0;
        assert!(load_slots(&keys, &sid, 0, 2).unwrap().is_none(), "無ければ None");

        let slots = solve_slots(&sid, 2, 0, 1).unwrap();
        save_slots(&keys, &sid, 0, &slots).unwrap();
        assert_eq!(load_slots(&keys, &sid, 0, 2).unwrap(), Some(slots), "合っていれば再利用する");

        let other_sid = Identity::generate().public_id().0;
        assert!(load_slots(&keys, &other_sid, 0, 2).unwrap().is_none(), "SID が違えば解き直す");
        assert!(load_slots(&keys, &sid, 1, 2).unwrap().is_none(), "難易度が違えば解き直す");
        assert!(load_slots(&keys, &sid, 0, 4).unwrap().is_none(), "枠の数が違えば解き直す");
        assert!(load_slots(&keys, &sid, 0, 1).unwrap().is_none(), "枠の数が減っても解き直す");

        std::fs::write(keys.storage_slots_path(), b"garbage").unwrap();
        assert!(load_slots(&keys, &sid, 0, 2).unwrap().is_none(), "壊れていれば解き直す");
    }

    #[tokio::test]
    async fn ensure_slots_solves_once_and_then_reuses_the_saved_solution() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        let sid = Identity::generate();
        let first = ensure_slots(&keys, &sid, 0, 4).await.unwrap();
        assert_eq!(first.len(), 4);
        assert!(keys.storage_slots_path().exists(), "解を保存していない");
        assert_eq!(ensure_slots(&keys, &sid, 0, 4).await.unwrap(), first);
    }

    #[test]
    fn dispatch_routes_probe_markers_and_drops_put_and_get() {
        let shared = HolderShared::default();

        // 自分の確認の目印は、待っている側へ渡り、外の目印には数えない
        let marker = [5u8; 32];
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        shared.pending.lock().unwrap().insert(marker, tx);
        shared.dispatch(&build_holder_message(HOLDER_PROBE, &marker));
        assert!(rx.try_recv().is_ok(), "待っている側に渡っていない");
        assert!(shared.external.lock().unwrap().is_empty());

        // 待っていない目印は、外から届いたものとして覚える
        shared.dispatch(&build_holder_message(HOLDER_PROBE, &[6u8; 32]));
        assert_eq!(shared.external.lock().unwrap().iter().copied().collect::<Vec<_>>(), vec![[6u8; 32]]);

        // PUT・GET・壊れた中身・知らない種別は捨てる（落ちない）
        shared.dispatch(&build_holder_message(HOLDER_PUT, &[1u8; 40]));
        shared.dispatch(&build_holder_message(HOLDER_GET, &[1u8; 40]));
        shared.dispatch(&build_holder_message(HOLDER_PROBE, &[1u8; 5]));
        shared.dispatch(&build_holder_message(99, &[1u8; 5]));
        shared.dispatch(&[]);
        assert_eq!(shared.external.lock().unwrap().len(), 1, "捨てるはずのものを覚えた");
    }

    #[test]
    fn external_probes_are_capped() {
        let shared = HolderShared::default();
        for i in 0..(EXTERNAL_PROBES_KEPT + 10) {
            shared.dispatch(&build_holder_message(HOLDER_PROBE, &[i as u8; 32]));
        }
        assert_eq!(shared.external.lock().unwrap().len(), EXTERNAL_PROBES_KEPT);
    }
}
