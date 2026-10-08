//! 落ちたノードの記述子がリレー一覧に残った網での私信
//!
//! 片方がオフラインの間に送った私信が届かない不具合の再現。オフラインになった
//! ノードの記述子は、期限（3 時間）が切れるまで全員の一覧に「到達可能」のまま残り、
//! 回路の中間・出口、返信トンネルの中間・gateway、保持者に選ばれ続ける。
//!
//! - 送信側：本体の回路にそのノードが入ると、全シャードが黙って消える
//!   （入口へ書けた時点で送信は成功扱い）。
//! - 受信側：返信トンネルにそのノードが入ると疎通確認に失敗し、組み直しても
//!   同じ候補から引き直すので、また失敗する。
//!
//! ここでは「動いていないノードの記述子」を全員の一覧に差し込んで、この状態を作る。
//! 落ちたノードが網からどう見えるかはそれと同じ（止めた実ノードとの違いは無い）。

mod common;

use aether_client::{AetherClient, ClientEvent, Contact, PrivacyOptions, event_channel};
use aether_core::crypto::identity::Identity;
use aether_core::net::reachability::Tier;
use aether_core::net::relay_list::RelayDescriptor;
use aether_core::node::server::NodeServer;
use common::*;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 送る私信の数（回路の選び方は無作為なので、1 通では当たり外れが出る）
const MESSAGES: usize = 4;
/// 最後の送信から、全部届くまで待つ上限（受信側の取り寄せ直し 30 秒 × 3 回を含める）
const DELIVERY_WAIT: Duration = Duration::from_secs(120);

/// 遅延なし（再現を速くする。遅延は不具合と関係しない）
fn no_delays() -> PrivacyOptions {
    PrivacyOptions {
        delay_fetch: false,
        delay_release: false,
        save_talk_history: false,
    }
}

/// 誰も待ち受けていないアドレスを持つ、到達可能と称する記述子（＝落ちたノード）
fn dead_relay() -> RelayDescriptor {
    let addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    RelayDescriptor::new_signed(&Identity::generate(), addr, 0, Tier::Open)
}

async fn insert_everywhere(dead: &RelayDescriptor, nodes: &[&Arc<NodeServer>]) {
    for node in nodes {
        node.directory().write().await.insert_unchecked(dead.clone());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "ノードを 7 台立てる重い試験。`cargo test -p aether-client --test e2e_dead_relay -- --ignored --nocapture`"]
async fn private_messages_arrive_despite_a_dead_relay_in_the_directory() {
    let (relays, _dirs) = spawn_relays(5).await;
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
    let alice = resident_with(alice_dir.path(), seed, alice_events, no_delays()).await;
    let bob_events = event_channel();
    let mut bob_rx = bob_events.subscribe();
    let bob = resident_with(bob_dir.path(), seed, bob_events, no_delays()).await;

    // 5 リレー + Alice + Bob が互いに見えるまで待つ
    for c in [&alice, &bob] {
        wait_until("everyone knows everyone", Duration::from_secs(30), || {
            let c = c.clone();
            async move { c.status().await.known_relays >= 7 }
        })
        .await;
    }

    // GUI と同じく、友だちコードを交換し、受信を始めておく。
    // これで Bob のガードは、落ちたノードが現れる前に決まる（実際の状況と揃える）
    alice
        .accept_friend_code(&bob.create_friend_code().unwrap())
        .expect("Bob のコードを受け取る");
    bob.accept_friend_code(&alice.create_friend_code().unwrap())
        .expect("Alice のコードを受け取る");
    bob.start_receiving(vec![Contact { node_id: alice_id, secret: None }], Vec::new())
        .await
        .unwrap();

    // --- ここでノードが 1 台落ちる（記述子だけが全員の一覧に残る）---
    let dead = dead_relay();
    let mut everyone: Vec<&Arc<NodeServer>> = relays.iter().collect();
    everyone.push(alice.node());
    everyone.push(bob.node());
    insert_everywhere(&dead, &everyone).await;
    let dead_hex = hex::encode(dead.node_id.as_bytes());

    // Bob 側で届いたもの・警告を集める
    let received = Arc::new(Mutex::new(HashSet::new()));
    {
        let received = received.clone();
        tokio::spawn(async move {
            loop {
                match bob_rx.recv().await {
                    Ok(ClientEvent::Received { text, .. }) => {
                        eprintln!("bob: 受信 {:?}", text);
                        received.lock().unwrap().insert(text);
                    }
                    Ok(ClientEvent::Warning { message }) => eprintln!("bob: 警告 {}", message),
                    Ok(ClientEvent::Progress { message }) => eprintln!("bob: {}", message),
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                }
            }
        });
    }

    // Alice 側の組み直し・警告を見る（落ちたノードを踏んで避けたかが分かる）
    tokio::spawn(async move {
        loop {
            match alice_rx.recv().await {
                Ok(ClientEvent::Warning { message }) => eprintln!("alice: 警告 {}", message),
                Ok(ClientEvent::Progress { message }) if message.contains("組み直し") => {
                    eprintln!("alice: {}", message)
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return,
            }
        }
    });

    let mut sent = Vec::new();
    for i in 0..MESSAGES {
        let text = format!("message {}", i);
        match send(&alice, bob_id, &text).await {
            Ok(report) => {
                eprintln!(
                    "alice: {:?} 送信成功（本体の出口 = {}{}）",
                    text,
                    &report.body_exit[..8],
                    if report.body_exit == dead_hex { "、落ちたノード" } else { "" }
                );
                sent.push(text);
            }
            Err(e) => eprintln!("alice: {:?} 送信失敗: {}", text, e),
        }
    }
    alice.flush().await;

    let deadline = tokio::time::Instant::now() + DELIVERY_WAIT;
    while tokio::time::Instant::now() < deadline {
        if sent.iter().all(|t| received.lock().unwrap().contains(t)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let received = received.lock().unwrap().clone();
    let missing: Vec<_> = sent.iter().filter(|t| !received.contains(*t)).collect();
    eprintln!(
        "結果: 送信 {} 通中 成功扱い {} 通 / 受信 {} 通 / 未着 {:?}",
        MESSAGES,
        sent.len(),
        received.len(),
        missing
    );
    assert_eq!(sent.len(), MESSAGES, "送信自体が失敗した私信がある");
    assert!(missing.is_empty(), "送信は成功扱いなのに届かない私信がある: {:?}", missing);

    // 落ちたノードは、リレーの生死の確認で全員の一覧から外れる。
    // 外したあと、まだ持っている他のノードから PEX で同じ記述子が戻ってきても入れない
    wait_until("dead relay is evicted everywhere", Duration::from_secs(120), || {
        let everyone: Vec<Arc<NodeServer>> = everyone.iter().map(|n| (*n).clone()).collect();
        let dead_id = dead.node_id;
        async move {
            for node in &everyone {
                if node.directory().read().await.get(&dead_id).is_some() {
                    return false;
                }
            }
            true
        }
    })
    .await;
}

async fn send(
    alice: &Arc<AetherClient>,
    to: aether_core::crypto::identity::NodeId,
    text: &str,
) -> aether_client::Result<aether_client::SendReport> {
    alice.send_private(to, None, text.as_bytes()).await
}
