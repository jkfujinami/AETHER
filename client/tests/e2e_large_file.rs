//! 木の Manifest のファイルを、ディスクから上げ、ディスクへ順に書いて取ること
//!
//! 1 ページ 2 ストライプに絞った（試験の口 `NetworkParams::manifest_page_stripes`）置く人が、
//! 17MB（66 チャンク = 5 ストライプ。最後は 2 チャンク）のファイルを `publish_file_from_path` で上げると、
//! 根 + 3 ページの木になる。別の一回限りのクライアントが `get_to_path` で取り、元とバイト単位で
//! 一致すること、同じフォルダに一時ファイルが残らないことを確かめる。
//! ファイルは全体をメモリに持たない経路（ストライプ数本分）を通る。

mod common;

use aether_client::{event_channel, AetherClient, PrivacyOptions};
use aether_core::mailbox::chunk;
use common::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "ノードを 9 台立てる重い試験。`cargo test -p aether-client --test e2e_large_file -- --ignored --nocapture`"]
async fn a_paged_manifest_file_goes_up_from_disk_and_comes_down_to_disk() {
    let (relays, _dirs) = spawn_relays(6).await;
    let seed = relays[0].descriptor.addr;

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let holders = vec![
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

    // 置く人。1 ページ 2 ストライプ、遅延と切り上げは切る
    let publisher_dir = tempfile::tempdir().unwrap();
    let mut config = ephemeral(publisher_dir.path(), seed);
    config.network.manifest_page_stripes = Some(2);
    config.privacy = PrivacyOptions { delay_release: false, pad_file_size: false, ..Default::default() };
    let publisher = AetherClient::start(config, event_channel()).await.unwrap();
    wait_for_leases(std::slice::from_ref(&publisher), &holders).await;

    // 元のファイル（17MB 強。最後のストライプは 2 チャンク。1 チャンクだと冗長が同じ中身になって件数がずれる）
    let work = tempfile::tempdir().unwrap();
    let src = work.path().join("src.bin");
    let original: Vec<u8> = (0..17_100_003u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    std::fs::write(&src, &original).unwrap();

    let board = aether_client::BoardId::random();
    let report = publisher
        .publish_file_from_path(&board, "big.bin", &src, Vec::new(), None)
        .await
        .expect("publish from path");
    publisher.flush().await;
    assert_eq!(report.chunks, Some(66));

    // 保持者に入った件数: v2 のシャード + 5 枚 × 2 人 × (根 1 + ページ 3)
    let chunks = chunk::v2_layout_chunks(original.len() as u64, false).unwrap();
    let v2_shards: usize = chunk::v2_stripe_shapes(chunks).unwrap().iter().map(|(k, m)| k + m).sum();
    assert_eq!(chunk::page_ranges(5, 2).len(), 3);
    wait_until("the shards reach the holders", Duration::from_secs(180), || {
        let holders = holders.clone();
        async move { holders.iter().map(|h| h.node().mailbox().shard_entries_len()).sum::<usize>() >= v2_shards + 40 }
    })
    .await;
    let total: usize = holders.iter().map(|h| h.node().mailbox().shard_entries_len()).sum();
    assert_eq!(total, v2_shards + 40, "根 1 + ページ 3 が小さなものの経路で置かれる");

    // 別のクライアントが取る
    let reader_dir = tempfile::tempdir().unwrap();
    let reader = AetherClient::start(ephemeral(reader_dir.path(), seed), event_channel()).await.unwrap();
    wait_for_leases(std::slice::from_ref(&reader), &holders).await;
    let found: Arc<Mutex<Option<String>>> = Default::default();
    wait_until("the index shows the file", Duration::from_secs(90), || {
        let reader = reader.clone();
        let found = found.clone();
        async move {
            let Ok(b) = reader.search(&board).await else { return false };
            let r = b.threads.iter().flat_map(|t| &t.posts).find(|p| p.name == "big.bin").map(|p| p.content_ref.clone());
            *found.lock().unwrap() = r.clone();
            r.is_some()
        }
    })
    .await;
    let content_ref = aether_client::parse_hex32(&found.lock().unwrap().clone().unwrap(), "ref").unwrap();

    let out_dir = tempfile::tempdir().unwrap();
    let out = out_dir.path().join("got.bin");
    let info = reader
        .get_to_path(&board, content_ref, &out)
        .await
        .expect("get_to_path")
        .expect("取れるはず");
    assert_eq!(info.size, original.len() as u64);
    assert_eq!(info.name, "big.bin");
    assert!(std::fs::read(&out).unwrap() == original, "バイト単位で一致しない");
    let left: Vec<String> = std::fs::read_dir(out_dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, vec!["got.bin".to_string()], "一時ファイルが残っている: {:?}", left);

    // メモリに載せる get でも、木のファイルを同じように取れる（上限以下の大きさ）
    let got = reader.get(&board, content_ref).await.expect("get").expect("取れるはず");
    assert!(got.bytes == original, "get の結果がバイト単位で一致しない");
    reader.flush().await;
}
