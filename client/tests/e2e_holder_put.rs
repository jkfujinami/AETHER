//! 置く経路が、隠れた保持者の受け口を通ること
//!
//! リレー 6 台 + 常駐の保持者 2 台 + 一回限りのクライアントで、
//! - 小さな投稿のシャードは保持者の `MailboxServer` に入り、リレーには（索引以外）入らない
//! - v2 の大きなファイルのシャードも保持者に入る
//! - 置く間、保持者の IP 宛てに受け口のトンネルでパケットを送ったのは、その保持者のガード（G_h）だけ
//!
//! を確かめる。今の試験網では常駐はリレーでもある。保持者がリレーとして受けるパケット（PEX・
//! 索引・他人の回路など）と区別するため、保持者の受け口の `tunnel_id` が先頭に付いた `TunnelData` と、
//! `MailboxPut`・`MailboxGet`（リレーの保存の旧い経路）だけを数える。

mod common;

use aether_client::{event_channel, AetherClient, PrivacyOptions, PublicPost};
use aether_core::mailbox::chunk;
use aether_core::protocol::wire::PacketType;
use common::*;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// `(送り手のノードのアドレス, 宛先, 種別, 中身の先頭 32 バイト)`
type Seen = Arc<Mutex<Vec<(SocketAddr, SocketAddr, PacketType, [u8; 32])>>>;

fn observe(seen: &Seen, sender: SocketAddr, router: &aether_core::node::router::Router) {
    let seen = seen.clone();
    router.set_send_observer(Arc::new(move |dest, packet_type, payload| {
        let mut head = [0u8; 32];
        let n = payload.len().min(32);
        head[..n].copy_from_slice(&payload[..n]);
        seen.lock().unwrap().push((sender, dest, packet_type, head));
    }));
}

async fn shard_entries(holders: &[Arc<AetherClient>]) -> Vec<usize> {
    holders.iter().map(|h| h.node().mailbox().shard_entries_len()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "ノードを 9 台立てる重い試験。`cargo test -p aether-client --test e2e_holder_put -- --ignored --nocapture`"]
async fn shards_go_to_holders_through_their_inlets_and_only_the_guard_sends_to_a_holder() {
    let (relays, _dirs) = spawn_relays(6).await;
    let seed = relays[0].descriptor.addr;

    // 常駐の保持者 2 台
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let holders = vec![
        resident(dir_a.path(), seed, event_channel()).await,
        resident(dir_b.path(), seed, event_channel()).await,
    ];
    for (i, holder) in holders.iter().enumerate() {
        wait_until(&format!("holder {} issues a lease set", i), Duration::from_secs(120), || {
            let holder = holder.clone();
            async move { holder.holder_status().lease_set.is_some() }
        })
        .await;
    }
    let sids: Vec<[u8; 32]> = holders.iter().map(|h| h.holder_status().lease_set.unwrap().sid).collect();

    // 置く人（一回限り）。遅延と切り上げは切る（試験を速く、シャードの数を数えやすく）
    let publisher_dir = tempfile::tempdir().unwrap();
    let mut config = ephemeral(publisher_dir.path(), seed);
    config.privacy = PrivacyOptions { delay_release: false, pad_file_size: false, ..Default::default() };
    let publisher = AetherClient::start(config, event_channel()).await.unwrap();
    wait_until("the publisher learns both lease sets", Duration::from_secs(120), || {
        let publisher = publisher.clone();
        let sids = sids.clone();
        async move {
            let dir = publisher.node().directory();
            let dir = dir.read().await;
            sids.iter().all(|sid| dir.lease_set(sid).is_some())
        }
    })
    .await;

    // 送るパケットの観測（試験専用の口）。全ノードの送信を集める
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    for relay in &relays {
        observe(&seen, relay.descriptor.addr, &relay.router);
    }
    for holder in &holders {
        observe(&seen, holder.node().descriptor.addr, &holder.node().router);
    }
    observe(&seen, publisher.node().descriptor.addr, &publisher.node().router);

    // --- 小さな投稿 ---
    let board = aether_client::BoardId::random();
    publisher
        .publish(PublicPost {
            board,
            content: b"hidden holders keep the shards".to_vec(),
            name: "small".into(),
            parents: Vec::new(),
        })
        .await
        .expect("publish small");

    // RS 3+2 の 5 枚が、保持者 2 人にそれぞれ全部入る（担当は SID ごとに 1 人。保持者は 2 人しかいない）
    wait_until("every holder stores the 5 shards", Duration::from_secs(60), || {
        let holders = holders.clone();
        async move { shard_entries(&holders).await.iter().all(|&n| n == 5) }
    })
    .await;
    for (i, relay) in relays.iter().enumerate() {
        assert_eq!(
            relay.mailbox.shard_entries_len(),
            0,
            "リレー {} がシャードを預かっている（索引だけのはず）",
            i
        );
    }

    // --- v2 の大きなファイル（2MiB） ---
    let big: Vec<u8> = (0..2 * 1024 * 1024u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let chunks = chunk::v2_layout_chunks("big".len(), big.len() as u64, false).unwrap();
    let v2_shards: usize = chunk::v2_stripe_shapes(chunks).unwrap().iter().map(|(k, m)| k + m).sum();
    publisher
        .publish(PublicPost { board, content: big, name: "big".into(), parents: Vec::new() })
        .await
        .expect("publish big");

    // 入る件数: 最初の投稿 5 枚 × 保持者 2 人 + Manifest 5 枚 × 2 人 + v2 のシャード（1 枚ずつ担当 1 人）
    let want_total = 10 + 10 + v2_shards;
    wait_until("the v2 shards reach the holders", Duration::from_secs(120), || {
        let holders = holders.clone();
        async move { shard_entries(&holders).await.iter().sum::<usize>() >= want_total }
    })
    .await;
    assert_eq!(shard_entries(&holders).await.iter().sum::<usize>(), want_total, "保持者に入った件数が合わない");
    for (i, relay) in relays.iter().enumerate() {
        assert_eq!(relay.mailbox.shard_entries_len(), 0, "リレー {} が v2 のシャードを預かっている", i);
    }

    // --- R5: 保持者の IP 宛ての、受け口のトンネルのパケットを送ったのは、その保持者のガードだけ ---
    let seen = seen.lock().unwrap().clone();
    for (i, holder) in holders.iter().enumerate() {
        let status = holder.holder_status();
        let addr = holder.node().descriptor.addr;
        let ids: HashSet<[u8; 32]> = status.receive_tunnel_ids.iter().copied().collect();
        let guard = status.guard_addr.expect("保持者のガードが分からない");

        let to_holder: Vec<_> = seen.iter().filter(|(_, dest, _, _)| *dest == addr).collect();
        let inlet_packets: Vec<_> = to_holder
            .iter()
            .filter(|(_, _, ty, head)| *ty == PacketType::TunnelData && ids.contains(head))
            .collect();
        assert!(!inlet_packets.is_empty(), "保持者 {} の受け口に何も届いていない（観測が壊れている）", i);
        let strangers: Vec<_> = inlet_packets.iter().filter(|(sender, ..)| *sender != guard).collect();
        assert!(
            strangers.is_empty(),
            "保持者 {} の受け口へ、ガード以外が {} 件送った",
            i,
            strangers.len()
        );
        // リレーの保存の旧い経路（出口 → 保持者の IP へ直接 MailboxPut / MailboxGet）が使われていない
        let direct: Vec<_> = to_holder
            .iter()
            .filter(|(_, _, ty, _)| matches!(ty, PacketType::MailboxPut | PacketType::MailboxGet))
            .collect();
        assert!(direct.is_empty(), "保持者 {} の IP へ MailboxPut/Get を直接送った者がいる", i);
        eprintln!(
            "holder {}: inlet packets {} (all from its guard), other packets to its address {}",
            i,
            inlet_packets.len(),
            to_holder.len() - inlet_packets.len()
        );
    }

    publisher.flush().await;
}
