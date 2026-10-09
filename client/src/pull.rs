//! Pull セッション ── 返信用 Inbound Tunnel と、要求を出す 3 ホップ回路
//!
//! ```text
//! 要求:  自分 → ガード → 中間1 → 出口 ──(MailboxGet / IndexQuery)──→ 保持者
//! 返信:  保持者 ──→ gateway → 中間2 → ガード ──(自分が張った接続)──→ 自分
//! ```
//!
//! - 保持者が見るのは gateway だけ。自分の IP を知るのはガードだけで、
//!   ガードは何を取りに行ったか（鍵）を知らない。
//! - **gateway と中間2 への構築指示は出口経由で届ける。** 直接送ると、
//!   構築者（＝受信者）の IP を gateway に晒して Inbound Tunnel の意味が消える。
//! - **ガードは返信を「自分が張った接続」の上で返す**（アドレス宛てにしない）。
//!   一回限りのクライアントは広告アドレスを持たず、NAT の内側にもいる。
//!
//! # 一周の疎通確認
//!
//! 中間・出口・gateway の生死は、直接確かめると IP を晒す。組んだ回路から自分の
//! 返信トンネルへ目印を送り、戻ってくるかで確かめる。戻らなければ、その回路の
//! 中継点をしばらく避けて組み直す。受信・検索・取得だけでなく送信の回路もこれを通す
//! （入口へ書けた時点で送信は成功扱いになるので、途中で消えても送り手には見えない）。

use crate::circuit::Circuit;
use crate::client::AetherClient;
use crate::error::{ClientError, Result};
use aether_core::crypto::identity::NodeId;
use aether_core::mailbox::schrodinger::SchrodingerMailbox;
use aether_core::net::gossip::GossipClient;
use aether_core::net::relay::RelayClient;
use aether_core::net::relay_list::RelayDescriptor;
use aether_core::net::tunnel::{InboundTunnel, TunnelEndpoint};
use aether_core::protocol::wire::PacketType;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 構築指示が各ホップへ行き渡るのを待つ時間
///
/// 指示より先に要求が保持者へ届き、返信が未登録の gateway で落ちるのを避ける。
const TUNNEL_SETTLE: Duration = Duration::from_millis(500);

/// 回路を組み直す回数の上限
const PULL_ATTEMPTS: usize = 3;
/// 疎通確認の目印が戻るのを待つ時間
const PROBE_WAIT: Duration = Duration::from_secs(5);

/// プールに待たせる回路の本数
const POOL_TARGET: usize = 2;
/// プールの回路の寿命。過ぎたら捨てる（返信トンネルの寿命 `TUNNEL_TTL` 30 分に収める）
const POOL_MAX_AGE: Duration = Duration::from_secs(10 * 60);
/// 組んでからこれを過ぎた回路は、渡す前にもう一度一周を確かめる
///
/// 待つ間に中継点が落ちると、送った中身が黙って消えるため。
const POOL_REPROBE_AFTER: Duration = Duration::from_secs(60);
/// 補充の見回りの間隔（失敗が続くと [`POOL_REFILL_MAX_BACKOFF`] まで倍々に延ばす）
const POOL_REFILL_INTERVAL: Duration = Duration::from_secs(5);
const POOL_REFILL_MAX_BACKOFF: Duration = Duration::from_secs(60);

pub(crate) struct PullSession {
    pub mailbox: SchrodingerMailbox,
    pub receive_tunnel_id: [u8; 32],
    pub reply_to: TunnelEndpoint,
    pub gateway: std::net::SocketAddr,
}

/// 一周の疎通確認に通った 3 ホップ回路と、その返信トンネル
pub(crate) struct ProbedCircuit {
    pub circuit: Circuit,
    pub tunnel: InboundTunnel,
    pub gateway: std::net::SocketAddr,
    /// 返信側の中間2・gateway（再確認で落ちたときに疑う相手）
    pub tunnel_hops: [NodeId; 2],
}

/// プールで待っている、一周確認済みの回路
///
/// 1 本は 1 回の操作で使い捨てる（返さない）。使い回すと、別々の操作が同じ出口で
/// 同じ人のものと結びつく。
pub(crate) struct PooledCircuit {
    pub probed: ProbedCircuit,
    pub built_at: Instant,
}

/// 寿命内で出口が `avoid_exit` に合わないもののうち、先頭の位置を返す
///
/// `pool` は (出口, 組んだ時刻)。
pub(crate) fn pick_pooled(pool: &[(NodeId, Instant)], avoid_exit: &[NodeId], now: Instant) -> Option<usize> {
    pool.iter().position(|(exit, built_at)| {
        now.saturating_duration_since(*built_at) < POOL_MAX_AGE && !avoid_exit.contains(exit)
    })
}

/// 渡す前に一周の再確認が要るか
pub(crate) fn needs_reprobe(built_at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(built_at) > POOL_REPROBE_AFTER
}

impl AetherClient {
    /// 返信トンネルと要求用の回路を張る
    ///
    /// `contacts` は Mailbox に載せる共有秘密。検索/取得は空、受信は購読中の秘密を渡す。
    pub(crate) async fn open_pull_session(
        &self,
        contacts: HashMap<NodeId, [u8; 32]>,
    ) -> Result<PullSession> {
        let ProbedCircuit {
            circuit,
            tunnel,
            gateway,
            ..
        } = self.take_probed_circuit(&[]).await?;

        let receive_tunnel_id = tunnel.receive_tunnel_id;
        let reply_to = tunnel.endpoint.clone();
        let mailbox = SchrodingerMailbox::with_directory(
            Arc::new(circuit.client),
            Arc::new(GossipClient::new(RelayClient::new()?)),
            Arc::new(Mutex::new(contacts)),
            self.node.directory(),
        );
        mailbox.register_inbound_tunnel(tunnel);

        Ok(PullSession {
            mailbox,
            receive_tunnel_id,
            reply_to,
            gateway,
        })
    }

    /// プールから一周確認済みの回路を取る。合うものが無ければ新しく組む
    ///
    /// 取り出した回路は返さない（使い捨て）。ロックを持つのは選んで抜くあいだだけで、
    /// 再確認や新規の構築はロックを手放してから行う。
    /// 失敗は黙って次へ進めず、中継点を `mark_suspects` して捨てる。
    pub(crate) async fn take_probed_circuit(&self, avoid_exit: &[NodeId]) -> Result<ProbedCircuit> {
        loop {
            let pooled = {
                let mut pool = self.circuit_pool.lock().await;
                let now = Instant::now();
                pool.retain(|p| now.saturating_duration_since(p.built_at) < POOL_MAX_AGE);
                let keys: Vec<(NodeId, Instant)> = pool
                    .iter()
                    .map(|p| (p.probed.circuit.exit.node_id, p.built_at))
                    .collect();
                pick_pooled(&keys, avoid_exit, now).map(|i| pool.remove(i))
            };
            let Some(PooledCircuit { probed, built_at }) = pooled else {
                return self.open_probed_circuit(avoid_exit).await;
            };
            if !needs_reprobe(built_at, Instant::now()) {
                return Ok(probed);
            }
            let hops = [
                probed.circuit.middle.node_id,
                probed.circuit.exit.node_id,
                probed.tunnel_hops[0],
                probed.tunnel_hops[1],
            ];
            match self.probe(&probed.circuit.client, &probed.tunnel, probed.gateway).await {
                Ok(()) => {
                    self.clear_suspects(&hops);
                    return Ok(probed);
                }
                Err(_) => self.mark_suspects(&hops),
            }
        }
    }

    /// プールを `POOL_TARGET` 本に保つ補充タスクを起こす
    ///
    /// `Weak` で持ち、クライアントが無くなれば終わる。一周確認の通信はガードにしか見えない。
    /// 失敗が続くときは待ち時間を延ばし、ログを溢れさせない。
    pub(crate) fn spawn_circuit_pool_refill(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut wait = POOL_REFILL_INTERVAL;
            loop {
                tokio::time::sleep(wait).await;
                let Some(client) = weak.upgrade() else { return };
                wait = match client.refill_circuit_pool_once().await {
                    Ok(()) => POOL_REFILL_INTERVAL,
                    Err(()) => (wait * 2).min(POOL_REFILL_MAX_BACKOFF),
                };
            }
        });
    }

    /// 足りなければ 1 本だけ組んで入れる。組めなかったら `Err`
    async fn refill_circuit_pool_once(&self) -> std::result::Result<(), ()> {
        // リレーが揃う前は組まない（失敗を重ねてログを溢れさせない）
        if self.node.directory_size().await <= self.min_relays {
            return Ok(());
        }
        {
            let mut pool = self.circuit_pool.lock().await;
            let now = Instant::now();
            pool.retain(|p| now.saturating_duration_since(p.built_at) < POOL_MAX_AGE);
            if pool.len() >= POOL_TARGET {
                return Ok(());
            }
        }
        // ロックを手放して組む（取り出しを止めない）
        let probed = self.try_probed_circuit(&[]).await.map_err(|_| ())?;
        let mut pool = self.circuit_pool.lock().await;
        if pool.len() < POOL_TARGET {
            pool.push(PooledCircuit {
                probed,
                built_at: Instant::now(),
            });
        }
        Ok(())
    }

    /// 3 ホップ回路と返信トンネルを組み、自分宛てに一周させて確かめる
    ///
    /// 戻らなければ、その回路の中継点を避けて組み直す（[`PULL_ATTEMPTS`] 回まで）。
    /// `avoid_exit` は出口にだけ使わない相手（回路分離）。
    pub(crate) async fn open_probed_circuit(&self, avoid_exit: &[NodeId]) -> Result<ProbedCircuit> {
        let mut last_err = None;
        for attempt in 1..=PULL_ATTEMPTS {
            match self.try_probed_circuit(avoid_exit).await {
                Ok(probed) => return Ok(probed),
                Err(e) => last_err = Some(e),
            }
            if attempt < PULL_ATTEMPTS {
                crate::events::progress(&self.events, "回路が応答しないので、別のリレーで組み直します");
            }
        }
        Err(last_err.unwrap_or_else(|| ClientError::network("回路を組めませんでした")))
    }

    async fn try_probed_circuit(&self, avoid_exit: &[NodeId]) -> Result<ProbedCircuit> {
        let circuit = self.build_circuit(avoid_exit).await?;
        let (tunnel, middle2, gateway) = self.build_reply_tunnel(&circuit).await?;
        let hops = [
            circuit.middle.node_id,
            circuit.exit.node_id,
            middle2.node_id,
            gateway.node_id,
        ];
        match self.probe(&circuit.client, &tunnel, gateway.addr).await {
            Ok(()) => {
                self.clear_suspects(&hops);
                Ok(ProbedCircuit {
                    circuit,
                    tunnel,
                    gateway: gateway.addr,
                    tunnel_hops: [middle2.node_id, gateway.node_id],
                })
            }
            Err(e) => {
                self.mark_suspects(&hops);
                Err(e)
            }
        }
    }

    /// 回路 → gateway → 中間 → ガード → 自分 と目印を一周させ、戻ってくるか確かめる
    async fn probe(&self, client: &RelayClient, tunnel: &InboundTunnel, gateway: std::net::SocketAddr) -> Result<()> {
        let marker: [u8; 32] = rand::random();
        let mut data = tunnel.endpoint.tunnel_id.to_vec();
        data.extend_from_slice(&marker);
        client
            .send_onion_message_typed(PacketType::TunnelData, &data, gateway)
            .await?;

        let until = tokio::time::Instant::now() + PROBE_WAIT;
        while tokio::time::Instant::now() < until {
            let raw = self.take_replies(&tunnel.receive_tunnel_id).await?;
            if raw
                .iter()
                .filter_map(|d| tunnel.decrypt(d).ok())
                .any(|m| m.as_slice() == marker)
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(ClientError::network("回路か返信トンネルが応答しません"))
    }

    /// 回路の返信トンネル（gateway → 中間2 → ガード → 自分）を張る
    async fn build_reply_tunnel(
        &self,
        circuit: &Circuit,
    ) -> Result<(InboundTunnel, RelayDescriptor, RelayDescriptor)> {
        let me = self.node.descriptor.node_id;
        let guard = circuit.guard.clone();

        // 返信側の中間・gateway。要求回路の中間・出口とは重ねない（小さな網では出口だけ避ける）
        let directory = self.node.directory();
        let (middle2, gateway) = {
            let dir = directory.read().await;
            self.pick_hops(
                &dir,
                &guard.node_id,
                &[guard.addr],
                &[me, circuit.middle.node_id, circuit.exit.node_id],
                &[],
            )
            .or_else(|| {
                self.pick_hops(&dir, &guard.node_id, &[guard.addr], &[me], &[circuit.exit.node_id])
            })
            .ok_or_else(|| {
                ClientError::network("返信トンネルを組めません（到達可能なリレーが足りません）")
            })?
        };

        let self_addr = self.node.descriptor.addr;
        let (tunnel, instructions) = InboundTunnel::build_to_builder(
            vec![gateway.addr, middle2.addr, guard.addr, self_addr],
            vec![
                gateway.x25519_pub,
                middle2.x25519_pub,
                guard.x25519_pub,
                self.node.descriptor.x25519_pub,
            ],
        )?;
        let [gw_build, mid_build, guard_build, self_build]: [(std::net::SocketAddr, Vec<u8>); 4] =
            instructions
                .try_into()
                .map_err(|_| ClientError::invalid("unexpected tunnel instruction count"))?;

        // ガード：自分の待ち受けと同じソケットから keepalive 付きで張り、その上で指示を渡す。
        // ガードは「この接続の相手」へ返信を届ける（next_hop = None）
        self.node.pin_connection(guard.addr).await?;
        self.node
            .send_direct(guard.addr, PacketType::TunnelBuild, &guard_build.1)
            .await?;
        // 自分の分はネットワークを通さない
        self.node.accept_own_tunnel_build(&self_build.1).await?;
        // 中間2・gateway：出口経由（自分の IP を見せない）
        circuit
            .client
            .send_onion_message_typed(PacketType::TunnelBuild, &mid_build.1, middle2.addr)
            .await?;
        circuit
            .client
            .send_onion_message_typed(PacketType::TunnelBuild, &gw_build.1, gateway.addr)
            .await?;

        tokio::time::sleep(TUNNEL_SETTLE).await;
        Ok((tunnel, middle2, gateway))
    }

    /// 自分宛てに届いた返信を取り出す（取り出したものは消える）
    pub(crate) async fn take_replies(&self, receive_tunnel_id: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
        let replies = self
            .node
            .mailbox()
            .fetch_tunnel_messages(receive_tunnel_id)
            .await?;
        let total: usize = replies.iter().map(Vec::len).sum();
        self.traffic
            .received
            .fetch_add(total as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(replies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    #[test]
    fn pick_pooled_skips_expired_and_avoided_exits() {
        let now = Instant::now();
        let old = now - POOL_MAX_AGE - Duration::from_secs(1);
        let pool = [(id(1), old), (id(2), now), (id(3), now)];
        assert_eq!(pick_pooled(&pool, &[], now), Some(1), "寿命切れは選ばず、残りの先頭を選ぶ");
        assert_eq!(pick_pooled(&pool, &[id(2)], now), Some(2), "避ける出口のものは選ばない");
        assert_eq!(pick_pooled(&pool, &[id(2), id(3)], now), None, "合うものが無ければ None");
        assert_eq!(pick_pooled(&[], &[], now), None, "空なら None");
    }

    #[test]
    fn needs_reprobe_flips_after_sixty_seconds() {
        let now = Instant::now();
        assert!(!needs_reprobe(now, now), "組んだ直後は再確認しない");
        assert!(!needs_reprobe(now - POOL_REPROBE_AFTER, now), "ちょうど 60 秒はまだ要らない");
        assert!(
            needs_reprobe(now - POOL_REPROBE_AFTER - Duration::from_millis(1), now),
            "60 秒を過ぎたら再確認する"
        );
    }
}
