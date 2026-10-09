//! 置いて取る時間と通信量を測る（段 A の物差し / Part 25 の 25.4.1）
//!
//! 測るだけで、置き方・取り方は変えない。結果は 1 行の `BENCH ...` として出す。
//! 小さな試験網では保持者が重なるので、倍率は実網と少し違う。比べるのは段の前後。

mod common;

use aether_client::{AetherClient, PublicPost, event_channel};
use common::*;
use rand::RngCore;
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "ノードを 8 台立てる重い測定。AETHER_BENCH_MB=8 cargo test -p aether-client --test bench_transfer -- --ignored --nocapture で走らせる"]
async fn bench_put_and_get() {
    let mib: usize = std::env::var("AETHER_BENCH_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let size = mib * 1024 * 1024;
    let mut content = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut content);

    let (relays, _dirs) = spawn_relays(6).await;
    let seed = relays[0].descriptor.addr;
    let board = aether_client::BoardId::random();

    // --- 置く ---
    let put_dir = tempfile::tempdir().unwrap();
    let putter = AetherClient::start(ephemeral(put_dir.path(), seed), event_channel())
        .await
        .unwrap();
    wait_until("putter knows relays", Duration::from_secs(30), || {
        let putter = putter.clone();
        async move { putter.status().await.known_relays >= 7 }
    })
    .await;
    let before = putter.traffic();
    let started = Instant::now();
    putter
        .publish(PublicPost {
            board,
            content: content.clone(),
            name: "bench.bin".into(),
            parents: Vec::new(),
        })
        .await
        .expect("publish");
    putter.flush().await;
    let put_secs = started.elapsed().as_secs_f64();
    let put_sent = putter.traffic().0 - before.0;

    // --- 取る ---
    let get_dir = tempfile::tempdir().unwrap();
    let getter = AetherClient::start(ephemeral(get_dir.path(), seed), event_channel())
        .await
        .unwrap();
    wait_until("getter knows relays", Duration::from_secs(30), || {
        let getter = getter.clone();
        async move { getter.status().await.known_relays >= 7 }
    })
    .await;
    let content_ref_hex: std::sync::Arc<std::sync::Mutex<Option<String>>> = Default::default();
    wait_until("index shows the post", Duration::from_secs(60), || {
        let getter = getter.clone();
        let found = content_ref_hex.clone();
        async move {
            let Ok(b) = getter.search(&board).await else { return false };
            let r = b
                .threads
                .iter()
                .flat_map(|t| &t.posts)
                .find(|p| p.name == "bench.bin")
                .map(|p| p.content_ref.clone());
            let hit = r.is_some();
            *found.lock().unwrap() = r;
            hit
        }
    })
    .await;
    let content_ref = aether_client::parse_hex32(&content_ref_hex.lock().unwrap().clone().unwrap(), "ref").unwrap();
    let before = getter.traffic();
    let started = Instant::now();
    let fetched = getter
        .get(&board, content_ref)
        .await
        .expect("get")
        .expect("取得できない");
    let get_secs = started.elapsed().as_secs_f64();
    let get_recv = getter.traffic().1 - before.1;
    assert!(fetched.bytes == content, "取れた中身が元と一致しない");

    println!(
        "BENCH size_mib={} put_secs={:.1} put_sent={} ({:.2}x) get_secs={:.1} get_recv={} ({:.2}x)",
        mib,
        put_secs,
        put_sent,
        put_sent as f64 / size as f64,
        get_secs,
        get_recv,
        get_recv as f64 / size as f64,
    );
}
