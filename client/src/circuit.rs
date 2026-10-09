//! 3 ホップ Onion 回路（固定ガード → 中間 → 出口）
//!
//! # なぜ 3 ホップと固定ガードか
//!
//! - **1 ホップだと入口が出口を兼ね、「発信者の IP」と「復号した中身」が同じ 1 台に揃う。**
//!   中間を挟めば、IP を知る入口は中身を知らず、中身を知る出口は IP を知らない。
//! - **入口を毎回無作為に選ぶと、攻撃者のリレー占有率 f に対し
//!   「いつか敵の入口を引く」確率が 1 に収束する。** 入口はガードとして固定し、
//!   成否を記録して永続化する（[`GuardSet`](aether_core::net::guard::GuardSet)）。
//!
//! 中間・出口の生死は直接は確かめない。出口へ直接問い合わせると出口に発信者の IP を晒す。
//! 候補は「見知らぬ相手を受けられる」ノードに事前に絞る（[`RelayDirectory::circuit_hops`]）。
//! 生死は組んだ回路で自分宛てに一周させて確かめ（[`crate::pull`]）、戻らなかった回路の
//! 中継点はしばらく避ける（[`SUSPECT_TTL`]）。
//!
//! [`RelayDirectory::circuit_hops`]: aether_core::net::relay_list::RelayDirectory::circuit_hops

use crate::client::AetherClient;
use crate::error::{ClientError, Result};
use aether_core::crypto::identity::NodeId;
use aether_core::net::guard::Guard;
use aether_core::net::relay::RelayClient;
use aether_core::net::relay_list::{RelayDescriptor, RelayDirectory};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// 回路に足るリレーが揃うまで待つ上限
const HOPS_WAIT: Duration = Duration::from_secs(30);

/// 疎通確認に失敗した回路の中継点を避ける期間
///
/// 落ちたノードの記述子は一覧にしばらく残る（リレーが生死を確かめて外すまで）。
/// 避けずに組み直すと、同じ候補から引き直してまた落ちたノードを踏む。
/// どの中継点が落ちていたかは外からは分からないので、回路の全員の失敗を数える。
/// 落ちたノードは失敗のたびに数が積み上がり、巻き込まれただけの生きた中継点は
/// 次に一周に成功した回路に入れば疑いが晴れる。
pub(crate) const SUSPECT_TTL: Duration = Duration::from_secs(10 * 60);

/// 疎通確認に失敗した回路に入っていた中継点
#[derive(Clone, Copy)]
pub(crate) struct Suspect {
    /// 最後に一周が戻ってから、失敗した回路に入っていた回数
    failures: u32,
    last: Instant,
}

pub(crate) type Suspects = std::sync::Mutex<std::collections::HashMap<NodeId, Suspect>>;

/// 組み上がった回路
pub(crate) struct Circuit {
    /// ガードに接続済みで、3 ホップの経路を設定済み
    pub client: RelayClient,
    pub guard: Guard,
    pub middle: RelayDescriptor,
    pub exit: RelayDescriptor,
}

impl AetherClient {
    /// 3 ホップ回路を組む
    ///
    /// `avoid_exit` は出口にだけ使わない相手（回路分離：他の回路が使った出口）。
    /// 足りなければ**エラーにする**（短い回路へ黙って落とさない）。
    pub(crate) async fn build_circuit(&self, avoid_exit: &[NodeId]) -> Result<Circuit> {
        self.wait_for_relays().await?;
        let me = self.node.descriptor.node_id;
        let directory = self.node.directory();

        // --- 入口：固定ガード ---
        // 待ち受けと同じソケットから出す（自分の送受信を中継の通信に紛れさせる）
        let mut client = RelayClient::via_node(self.node.router.clone(), self.node.server.endpoint())
            .with_traffic(self.traffic.clone());
        let guard = {
            let candidates: Vec<_> = {
                let dir = directory.read().await;
                dir.guard_candidates()
                    .into_iter()
                    // 自分自身を自分のガードにしない
                    .filter(|c| c.node_id != me)
                    .collect()
            };
            let mut guards = self.guards.lock().await;
            client
                .connect_guard(&mut guards, &candidates, &self.keys.guard_path())
                .await
                .map_err(|e| {
                    ClientError::network(format!("ガードに接続できません: {}", e))
                })?
        };

        // --- 中間・出口 ---
        let deadline = tokio::time::Instant::now() + HOPS_WAIT;
        let (middle, exit) = loop {
            let picked = {
                let dir = directory.read().await;
                self.pick_hops(&dir, &guard.node_id, &[guard.addr], &[me], avoid_exit)
            };
            if let Some(hops) = picked {
                break hops;
            }
            if tokio::time::Instant::now() > deadline {
                return Err(ClientError::network(
                    "3 ホップ回路を組めません（ガード以外に、到達可能なリレーが 2 台以上必要です）",
                ));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };

        client.set_path(&[
            (guard.addr, guard.x25519_pub),
            (middle.addr, middle.x25519_pub),
            (exit.addr, exit.x25519_pub),
        ])?;

        Ok(Circuit {
            client,
            guard,
            middle,
            exit,
        })
    }

    /// 回路の 2 ホップを選ぶ。疑いのある中継点を避ける
    ///
    /// 小さな網では全員を避けると候補が尽きる。そのときは失敗の少ない中継点から順に
    /// 避けるのをやめ、失敗を重ねた中継点（落ちている見込みが高い）を最後まで避ける。
    /// 組めないよりは、疑いのある中継点を含めて組んで一周で確かめる方がよい。
    pub(crate) fn pick_hops(
        &self,
        dir: &RelayDirectory,
        guard: &NodeId,
        avoid_subnets_of: &[SocketAddr],
        exclude: &[NodeId],
        avoid_exit: &[NodeId],
    ) -> Option<(RelayDescriptor, RelayDescriptor)> {
        let suspects = self.suspects();
        let mut levels: Vec<u32> = suspects.iter().map(|(_, f)| *f).collect();
        levels.sort_unstable();
        levels.dedup();
        for min_failures in levels {
            let mut avoid: Vec<NodeId> = suspects
                .iter()
                .filter(|(_, f)| *f >= min_failures)
                .map(|(id, _)| *id)
                .collect();
            avoid.extend_from_slice(exclude);
            if let Some(hops) = dir.circuit_hops(guard, avoid_subnets_of, &avoid, avoid_exit) {
                return Some(hops);
            }
        }
        dir.circuit_hops(guard, avoid_subnets_of, exclude, avoid_exit)
    }

    /// 今避けている中継点と失敗の回数（期限の切れた疑いは捨てる）
    fn suspects(&self) -> Vec<(NodeId, u32)> {
        let mut suspects = self.suspects.lock().unwrap();
        suspects.retain(|_, s| s.last.elapsed() < SUSPECT_TTL);
        suspects.iter().map(|(id, s)| (*id, s.failures)).collect()
    }

    /// 一周が戻らなかった回路の中継点を覚える
    pub(crate) fn mark_suspects(&self, hops: &[NodeId]) {
        let now = Instant::now();
        let mut suspects = self.suspects.lock().unwrap();
        for id in hops {
            let s = suspects.entry(*id).or_insert(Suspect { failures: 0, last: now });
            s.failures += 1;
            s.last = now;
        }
    }

    /// 一周が戻った回路の中継点は生きている
    pub(crate) fn clear_suspects(&self, hops: &[NodeId]) {
        let mut suspects = self.suspects.lock().unwrap();
        for id in hops {
            suspects.remove(id);
        }
    }
}
