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
//! 中間・出口の生死は確かめない。出口へ直接問い合わせると出口に発信者の IP を晒す。
//! 候補は「見知らぬ相手を受けられる」ノードに事前に絞る（[`RelayDirectory::circuit_hops`]）。
//!
//! [`RelayDirectory::circuit_hops`]: aether_core::net::relay_list::RelayDirectory::circuit_hops

use crate::client::AetherClient;
use crate::error::{ClientError, Result};
use aether_core::crypto::identity::NodeId;
use aether_core::net::guard::Guard;
use aether_core::net::relay::RelayClient;
use aether_core::net::relay_list::RelayDescriptor;
use std::time::Duration;

/// 回路に足るリレーが揃うまで待つ上限
const HOPS_WAIT: Duration = Duration::from_secs(30);

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
        let mut client = RelayClient::new()?;
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
                dir.circuit_hops(&guard.node_id, &[guard.addr], &[me], avoid_exit)
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
}
