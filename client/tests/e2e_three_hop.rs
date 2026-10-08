//! 3 ホップ回路での往復を実ノードで確かめる
//!
//! localhost に到達可能なリレーを並べ、クライアント API だけを使って
//! 公開 → 検索 → 取得、私信（X3DH 初回接触）→ 受信 が通ることを見る。
//! 1 ホップ時代の試験は「入口 = 出口」でも通ってしまうので、ここでは
//! 3 ホップ（ガード → 中間 → 出口）と 3 ホップの返信トンネルを必須にしている。

mod common;

use aether_client::{
    AetherClient, ClientConfig, ClientEvent, Contact, NodeMode, PublicPost, RelayOptions,
    event_channel,
};
use common::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "ノードを 6 台立てる重い試験。`cargo test -p aether-client -- --ignored` で明示的に走らせる"]
async fn publish_search_and_get_over_three_hops() {
    let (relays, _dirs) = spawn_relays(6).await;
    let seed = relays[0].descriptor.addr;

    // --- 公開 ---
    let pub_dir = tempfile::tempdir().unwrap();
    let publisher = AetherClient::start(ephemeral(pub_dir.path(), seed), event_channel())
        .await
        .unwrap();
    let content = b"three hops or nothing".to_vec();
    let test_board = aether_client::BoardId::random();
    let report = publisher
        .publish(PublicPost {
            board: test_board,
            content: content.clone(),
            name: "hello".into(),
            parents: Vec::new(),
        })
        .await
        .expect("publish");

    // ガードを固定して保存していること（毎回ランダムな入口にしない）
    assert!(pub_dir.path().join("guards.bin").exists(), "ガードが永続化されていない");
    // 回路分離：本体と Hint は別の出口
    assert_ne!(Some(report.body_exit.clone()), report.hint_exit, "本体と Hint が同じ出口");

    // 一回限りのクライアントはリレーとして網に広まらない
    let publisher_id = publisher.node().descriptor.node_id;
    for relay in &relays {
        assert!(
            relay.directory().read().await.get(&publisher_id).is_none(),
            "一回限りのクライアントの記述子がリレーのディレクトリに載った"
        );
    }

    // --- 検索（別のクライアント）---
    let reader_dir = tempfile::tempdir().unwrap();
    let reader = AetherClient::start(ephemeral(reader_dir.path(), seed), event_channel())
        .await
        .unwrap();
    let board = reader.search(&test_board).await.expect("search");
    let post = board
        .threads
        .iter()
        .flat_map(|t| &t.posts)
        .find(|p| p.name == "hello")
        .expect("索引に投稿が見つからない");
    assert_eq!(Some(post.content_ref.clone()), report.content_ref);

    // --- 取得 ---
    let content_ref = aether_client::parse_hex32(&post.content_ref, "ref").unwrap();
    let fetched = reader
        .get(&test_board, content_ref)
        .await
        .expect("get")
        .expect("本体を取得できない");
    assert_eq!(fetched.bytes, content);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "ノードを 7 台立てる重い試験。`cargo test -p aether-client -- --ignored` で明示的に走らせる"]
async fn private_message_first_contact_over_three_hops() {
    let (relays, _dirs) = spawn_relays(6).await;
    let seed = relays[0].descriptor.addr;

    // --- 受信者：常駐リレー。私信の身元とリレーの鍵は別 ---
    let bob_dir = tempfile::tempdir().unwrap();
    let bob_port = free_port();
    let bob_keys = aether_client::KeyFiles::new(bob_dir.path(), None);
    let bob_id = bob_keys.create_identity(false).unwrap().public_id();

    let alice_dir = tempfile::tempdir().unwrap();
    let alice_keys = aether_client::KeyFiles::new(alice_dir.path(), None);
    let alice_id = alice_keys.create_identity(false).unwrap().public_id();

    let bob_events = event_channel();
    let mut bob_rx = bob_events.subscribe();
    let bob = AetherClient::start(
        ClientConfig {
            data_dir: bob_dir.path().to_path_buf(),
            passphrase: None,
            port: bob_port,
            seed: Some(seed),
            min_relays: 4,
            mode: NodeMode::Relay(RelayOptions {
                advertise: Some(format!("127.0.0.1:{}", bob_port).parse().unwrap()),
                allow_port_mapping: false,
                pow_difficulty: 0,
                epoch_beacon: false,
            }),
            network: test_network(),
            privacy: Default::default(),
        },
        bob_events,
    )
    .await
    .unwrap();
    // 受信者のリレー NodeId は私信の宛先ではない（宛先から IP を引かせない）
    assert_ne!(bob.node().descriptor.node_id, bob_id);

    bob.start_receiving(
        vec![Contact {
            node_id: alice_id,
            secret: None,
        }],
        Vec::new(),
    )
    .await
    .unwrap();

    // Bob のリレーが網に広まり、プレキー束が置かれるまで待つ
    wait_until("bob's relay spreads", Duration::from_secs(20), || {
        let relays = relays.clone();
        let bob_relay = bob.node().descriptor.node_id;
        async move {
            for r in &relays {
                if r.directory().read().await.get(&bob_relay).is_none() {
                    return false;
                }
            }
            true
        }
    })
    .await;
    // 保持者は各自のディレクトリから計算する。Bob の見え方が揃ってから置く
    // （揃う前に置くと、取りに来る側と保持者の集合が食い違う。実網では定期再公開で追いつく）
    wait_until("bob knows every relay", Duration::from_secs(20), || {
        let bob = bob.clone();
        async move { bob.status().await.known_relays >= 7 }
    })
    .await;
    // プレキー束を置く（定期の公開は在席を悟られないよう遅らせるので、ここでは即座に置く。
    // 置く前に取りに行くと初回接触が失敗する）
    bob.publish_prekeys_now().await.expect("Bob のプレキー束を置けない");

    // --- 送信者：一回限り ---
    let alice = AetherClient::start(ephemeral(alice_dir.path(), seed), event_channel())
        .await
        .unwrap();
    wait_until("alice knows every relay", Duration::from_secs(20), || {
        let alice = alice.clone();
        // 6 リレー + Bob + 自分
        async move { alice.status().await.known_relays >= 8 }
    })
    .await;
    alice
        .send_private(bob_id, None, b"hi bob, over three hops")
        .await
        .expect("send_private");

    let text = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            if let Ok(ClientEvent::Received { text, .. }) = bob_rx.recv().await {
                return text;
            }
        }
    })
    .await
    .expect("Bob が私信を受信しない");
    assert_eq!(text, "hi bob, over three hops");
}

/// 往復の会話：初回接触 → 返事（Hint 鍵チェーン・双方向ラチェット）→ 継続
///
/// 返事からは Hint を X3DH 由来の日ごとの鍵で作り、ラチェットは往復で DH が回る。
/// 片道 1 通の試験ではこの経路を通らない。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "ノードを 8 台立てる重い試験。`cargo test -p aether-client -- --ignored` で明示的に走らせる"]
async fn private_conversation_round_trip_over_three_hops() {
    let (relays, _dirs) = spawn_relays(6).await;
    let seed = relays[0].descriptor.addr;

    let alice_dir = tempfile::tempdir().unwrap();
    let alice_id = aether_client::KeyFiles::new(alice_dir.path(), None)
        .create_identity(false)
        .unwrap()
        .public_id();
    let bob_dir = tempfile::tempdir().unwrap();
    let bob_id = aether_client::KeyFiles::new(bob_dir.path(), None)
        .create_identity(false)
        .unwrap()
        .public_id();

    let alice_events = event_channel();
    let mut alice_rx = alice_events.subscribe();
    let alice = resident(alice_dir.path(), seed, alice_events).await;
    let bob_events = event_channel();
    let mut bob_rx = bob_events.subscribe();
    let bob = resident(bob_dir.path(), seed, bob_events).await;

    // 6 リレー + Alice + Bob が互いに見えるまで待つ
    for c in [&alice, &bob] {
        wait_until("everyone knows everyone", Duration::from_secs(30), || {
            let c = c.clone();
            async move { c.status().await.known_relays >= 8 }
        })
        .await;
    }

    alice
        .start_receiving(vec![Contact { node_id: bob_id, secret: None }], Vec::new())
        .await
        .unwrap();
    bob.start_receiving(vec![Contact { node_id: alice_id, secret: None }], Vec::new())
        .await
        .unwrap();
    alice.publish_prekeys_now().await.expect("Alice のプレキー束");
    bob.publish_prekeys_now().await.expect("Bob のプレキー束");

    // 1. 初回接触（静的な DH の Hint ＋ X3DH の初回メッセージ）
    alice.send_private(bob_id, None, b"hello bob").await.expect("send 1");
    assert_eq!(next_received(&mut bob_rx, "bob").await, "hello bob");

    // 2. 返事（Hint は日ごとの鍵チェーン。受け取った Alice は初回メッセージを添えなくなる）
    bob.send_private(alice_id, None, b"hi alice").await.expect("send 2");
    assert_eq!(next_received(&mut alice_rx, "alice").await, "hi alice");

    // 3. 継続（Alice もチェーンの Hint で送る）
    alice.send_private(bob_id, None, b"how are you").await.expect("send 3");
    assert_eq!(next_received(&mut bob_rx, "bob").await, "how are you");
}
