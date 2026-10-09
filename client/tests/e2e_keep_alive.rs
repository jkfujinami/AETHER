//! 取り終えた人が、担当が入れ替わって見えなくなったシャードを置き直すこと（Part 25 の P11）
//!
//! 保持者 2 台に 2MiB の v2 ファイルを置いた後で、3 台目の保持者が網に加わる。3 台目は、置いた時点では
//! 居なかったので何も持たないが、取る人から見ると一部のシャードの担当は 3 台目に入れ替わる。
//! 取る人は 3 台目に要求しても返事が来ない（失われた）ので、パリティで補って取り切り、
//! 取り終えた後に、失われた位置のシャードを今の担当（3 台目）へ置き直す。

mod common;

use aether_client::{event_channel, AetherClient, ClientEvent, PrivacyOptions, PublicPost};
use common::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "ノードを 10 台立てる重い試験。`cargo test -p aether-client --test e2e_keep_alive -- --ignored --nocapture`"]
async fn a_reader_re_places_shards_whose_holder_changed() {
    let (relays, _dirs) = spawn_relays(6).await;
    let seed = relays[0].descriptor.addr;

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let mut holders = vec![
        hidden_holder(dir_a.path(), seed, event_channel()).await,
        hidden_holder(dir_b.path(), seed, event_channel()).await,
    ];
    for (i, holder) in holders.iter().enumerate() {
        wait_until(&format!("holder {} issues a lease set", i), Duration::from_secs(120), || {
            let holder = holder.clone();
            async move { holder.holder_status().lease_set.is_some() }
        })
        .await;
    }

    // 置く人（一回限り）。置く時点で知っている保持者は 2 台
    let publisher_dir = tempfile::tempdir().unwrap();
    let mut config = ephemeral(publisher_dir.path(), seed);
    config.privacy = PrivacyOptions { delay_release: false, pad_file_size: false, ..Default::default() };
    let publisher = AetherClient::start(config, event_channel()).await.unwrap();
    wait_for_leases(std::slice::from_ref(&publisher), &holders).await;

    let board = aether_client::BoardId::random();
    let big: Vec<u8> = (0..2 * 1024 * 1024u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let big_copy = big.clone();
    publisher
        .publish(PublicPost { board, content: big, name: "big".into(), parents: Vec::new() })
        .await
        .expect("publish big");
    publisher.flush().await;
    let before: usize = holders.iter().map(|h| h.node().mailbox().shard_entries_len()).sum();

    // 3 台目の保持者が加わる（置いた後なので、何も持たない）
    let dir_c = tempfile::tempdir().unwrap();
    let newcomer = hidden_holder(dir_c.path(), seed, event_channel()).await;
    wait_until("the newcomer issues a lease set", Duration::from_secs(120), || {
        let newcomer = newcomer.clone();
        async move { newcomer.holder_status().lease_set.is_some() }
    })
    .await;
    holders.push(newcomer.clone());
    assert_eq!(newcomer.node().mailbox().shard_entries_len(), 0, "新しい保持者は何も持っていない");

    // 取る人は 3 台とも知っている
    let reader_dir = tempfile::tempdir().unwrap();
    let events = event_channel();
    let mut rx = events.subscribe();
    let reader = AetherClient::start(ephemeral(reader_dir.path(), seed), events).await.unwrap();
    wait_for_leases(std::slice::from_ref(&reader), &holders).await;
    let found: Arc<Mutex<Option<String>>> = Default::default();
    wait_until("the index shows the file", Duration::from_secs(90), || {
        let reader = reader.clone();
        let found = found.clone();
        async move {
            let Ok(b) = reader.search(&board).await else { return false };
            let r = b.threads.iter().flat_map(|t| &t.posts).find(|p| p.name == "big").map(|p| p.content_ref.clone());
            *found.lock().unwrap() = r.clone();
            r.is_some()
        }
    })
    .await;
    let content_ref = aether_client::parse_hex32(&found.lock().unwrap().clone().unwrap(), "ref").unwrap();
    let started = std::time::Instant::now();
    let got = reader.get(&board, content_ref).await.expect("get").expect("パリティで補って取れるはず");
    assert!(got.bytes == big_copy, "バイト単位で一致しない");
    // 取ったファイルは、網に残す手伝い（延命・置き直し）を待たずに返る
    eprintln!("get returned after {:?}", started.elapsed());

    // 取り終えた後に、失われた位置のシャードが 3 台目へ置き直されている
    wait_until("the lost shards are re-placed to the new holder", Duration::from_secs(60), || {
        let newcomer = newcomer.clone();
        async move { newcomer.node().mailbox().shard_entries_len() > 0 }
    })
    .await;
    let after: usize = holders.iter().map(|h| h.node().mailbox().shard_entries_len()).sum();
    assert!(after > before, "置き直した分だけ保持者の持つ件数が増える");
    // 手伝いは裏で走る。送り終えて 1 行の知らせが出るまで待つ
    reader.flush().await;
    let mut lines = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let ClientEvent::Progress { message } = ev
            && message.starts_with("修復")
        {
            lines.push(message);
        }
    }
    eprintln!("re-placed to the newcomer: {}, progress: {:?}", newcomer.node().mailbox().shard_entries_len(), lines);
    assert_eq!(lines.len(), 1, "修復と延命を 1 行で知らせる");
}
