//! 保持者の受け口のトンネル
//!
//! リレー 6 台 + 常駐 1 台（保持者）を立て、
//! - 保持者の leaseSet がリレー全員のディレクトリに届く
//! - 別の一回限りのクライアントが、その leaseSet の受け口へ `HOLDER_PROBE` を送ると保持者に届く
//!
//! ことを確かめる。小さな網では受け口の gateway・中間・ガードが同じリレーに重なりうるが、
//! 除外しない設計なので、重なっても動くこと。

mod common;

use aether_client::{AetherClient, event_channel};
use aether_core::net::holder::{build_holder_message, HOLDER_PROBE};
use common::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "ノードを 8 台立てる重い試験。`cargo test -p aether-client --test e2e_holder_tunnel -- --ignored --nocapture`"]
async fn holder_publishes_its_lease_set_and_receives_probes_through_its_inlets() {
    let (relays, _dirs) = spawn_relays(6).await;
    let seed = relays[0].descriptor.addr;

    // 受け口 3 本がそろい、一周の確認が通ると leaseSet を出し、リレー全員に届くまで待つ
    let (holders, holder_dirs) = spawn_holders(&relays, 1).await;
    let (holder, holder_dir) = (holders[0].clone(), holder_dirs[0].path().to_path_buf());
    let lease = holder.holder_status().lease_set.unwrap();
    assert_eq!(lease.gateways.len(), 3, "受け口が 3 本そろっていない");
    assert!(
        holder_dir.join("storage_slots.bin").exists() && holder_dir.join("storage_vanguard.bin").exists(),
        "枠の解と中間を保存していない"
    );

    // 出口経由で渡されたリレーから PEX で広がり、リレー全員のディレクトリに届く
    wait_until("every relay learns the lease set", Duration::from_secs(120), || {
        let relays = relays.clone();
        let sid = lease.sid;
        async move {
            for node in &relays {
                if node.directory().read().await.lease_set(&sid).is_none() {
                    return false;
                }
            }
            true
        }
    })
    .await;

    // 別のクライアントが、leaseSet の各受け口へ目印を送る
    let sender_dir = tempfile::tempdir().unwrap();
    let sender = AetherClient::start(ephemeral(sender_dir.path(), seed), event_channel())
        .await
        .unwrap();
    wait_until("the sender learns the lease set", Duration::from_secs(60), || {
        let sender = sender.clone();
        let sid = lease.sid;
        async move { sender.node().directory().read().await.lease_set(&sid).is_some() }
    })
    .await;
    let learned = sender.node().directory().read().await.lease_set(&lease.sid).cloned().unwrap();
    assert_eq!(learned, lease, "受け取った leaseSet が出したものと違う");

    for (i, gateway) in learned.gateways.iter().enumerate() {
        let marker = [0xA0 + i as u8; 32];
        sender
            .send_to_lease_gateway(gateway, &build_holder_message(HOLDER_PROBE, &marker))
            .await
            .unwrap();
        wait_until(&format!("the probe through inlet {} reaches the holder", i), Duration::from_secs(30), || {
            let holder = holder.clone();
            async move { holder.holder_status().probes_received.contains(&marker) }
        })
        .await;
    }
}
