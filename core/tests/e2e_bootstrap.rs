//! MVP: 種ノード1台からの自己組織化 (設計書 18.5.2 / PEX)
//!
//! Kademlia を廃止したため、各ノードはリレーリスト全体をローカルに持つ。
//! その入手経路が PEX であり、**これが無いと1台も繋がらない**。
//!
//! 検証内容:
//! 1. 種ノード1台のアドレスだけを知っている状態から、網全体を発見できる
//! 2. 相互に知り合える（要求した側もされた側も相手を覚える）
//! 3. 発見したリストからガードを選び、実際に接続できる
//! 4. 全ノードが同じ担当リレー集合に到達する（配置と取得が食い違わない）

use aether_core::crypto::identity::Identity;
use aether_core::net::guard::GuardSet;
use aether_core::net::relay::RelayClient;
use aether_core::node::server::NodeServer;
use std::net::SocketAddr;
use std::sync::Arc;

mod common;

async fn spawn(port: u16) -> (Arc<NodeServer>, tempfile::TempDir, SocketAddr) {
    let dir = tempfile::tempdir().unwrap();
    let mut node =
        NodeServer::with_config(port, Identity::generate(), dir.path(), &common::test_config())
            .unwrap();

    // ローカルホストなので到達性は既知。
    // 宣言しないと Tier::Reversed のままで、ガードにも Mailbox にも選ばれない
    node.declare_reachable(format!("127.0.0.1:{}", port).parse().unwrap())
        .await;

    let server = Arc::new(node);

    let running = server.clone();
    tokio::spawn(async move {
        if let Err(e) = running.run().await {
            eprintln!("node stopped: {}", e);
        }
    });

    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    common::wait_for_listener(addr).await;

    (server, dir, addr)
}

#[tokio::test]
async fn network_self_organises_from_a_single_seed() {
    const NODE_COUNT: usize = 6;

    // 種ノード
    let (seed, _seed_dir, seed_addr) = spawn(19501).await;

    // 参加ノード。種のアドレス「だけ」を知っている
    let mut nodes = Vec::new();
    let mut dirs = Vec::new();
    for i in 0..NODE_COUNT {
        let (node, dir, _addr) = spawn(19502 + i as u16).await;
        node.bootstrap(seed_addr).await.expect("bootstrap failed");
        nodes.push(node);
        dirs.push(dir);
    }

    // --- 1. 種ノードが全員を認識する ---
    // PexRequest には要求者の記述子が同梱されているので、
    // 一方向の要求だけで相手にも自分が伝わる
    // 自分自身も含むので NODE_COUNT + 1
    common::wait_until("seed to learn every joiner", common::DEFAULT_TIMEOUT, || async {
        seed.directory_size().await > NODE_COUNT
    })
    .await;

    // --- 2. 参加ノードが互いを発見する ---
    // 種からの応答には種が知っている他の参加者が含まれるので、
    // 種としか話していなくても網全体へ収束していく
    // 全員が「種 + 全参加者 + 自分」= NODE_COUNT + 1 台を知る状態へ収束すること。
    // 自分を含めないと K最近接が他ノードとずれる
    let expected = NODE_COUNT + 1;
    common::wait_until("joiners to discover each other", common::DEFAULT_TIMEOUT, || async {
        for node in &nodes {
            if node.directory_size().await < expected {
                return false;
            }
        }
        true
    })
    .await;

    for (i, node) in nodes.iter().enumerate() {
        let size = node.directory_size().await;
        assert_eq!(
            size, expected,
            "ノード {} が {} 台しか知らない（期待 {} 台）",
            i, size, expected
        );
    }

    // --- 3. 発見したリストからガードを選んで実際に繋がる ---
    // GuardSet 側は完成していたが、候補リストの供給元が無く使えなかった。
    // PEX が入って初めて機能する。
    let self_id = nodes[0].descriptor.node_id;
    let candidates: Vec<_> = nodes[0]
        .directory()
        .read()
        .await
        .guard_candidates()
        .into_iter()
        .filter(|c| c.node_id != self_id) // 自分をガードにはできない
        .collect();
    assert!(!candidates.is_empty(), "ガード候補が空");

    let guard_dir = tempfile::tempdir().unwrap();
    let guard_path = guard_dir.path().join("guards.bin");
    let mut guards = GuardSet::load(&guard_path).unwrap();

    let mut client = RelayClient::new().unwrap();
    let chosen = client
        .connect_guard(&mut guards, &candidates, &guard_path)
        .await
        .expect("発見したリレーにガードとして接続できない");

    assert!(
        candidates.iter().any(|c| c.addr == chosen),
        "候補に無いアドレスへ繋いでいる"
    );

    // 再起動しても同じガードを使うこと（永続化されていなければ実質ランダム選択に退化）
    let reloaded = GuardSet::load(&guard_path).unwrap();
    let now = aether_core::protocol::hint::current_timestamp();
    assert_eq!(
        reloaded.current(now).map(|g| g.addr),
        Some(chosen),
        "ガードが永続化されていない"
    );

    // --- 4. 全ノードが同じ担当リレー集合に到達する ---
    // ここが崩れると、置いた場所と取りに行く場所が食い違って配送されない
    let mailbox_key = [0x77u8; 32];
    let key = [0x88u8; 32];

    let reference = nodes[0]
        .directory()
        .read()
        .await
        .mailbox_targets(&mailbox_key, &key, 3);

    for (i, node) in nodes.iter().enumerate().skip(1) {
        let targets = node
            .directory()
            .read()
            .await
            .mailbox_targets(&mailbox_key, &key, 3);

        assert_eq!(
            targets.iter().map(|r| r.node_id).collect::<Vec<_>>(),
            reference.iter().map(|r| r.node_id).collect::<Vec<_>>(),
            "ノード 0 と {} で担当リレーがずれている",
            i
        );
    }
}

#[tokio::test]
async fn pex_rejects_descriptors_with_bad_pow() {
    // PoW を要求する設定では、偽の記述子を取り込まないこと。
    // ここが素通しだと Sybil で座標を狙い撃ちできる (18.5.3)。
    use aether_core::crypto::identity::NodeId;
    use aether_core::net::pex::{absorb_response, PexResponse};
    use aether_core::net::relay_list::{RelayDescriptor, RelayDirectory};
    use aether_core::net::ring;

    let mut dir = RelayDirectory::new(ring::EPOCH_SEED_PLACEHOLDER, 8);

    let forged = RelayDescriptor {
        node_id: NodeId([0xEEu8; 32]),
        addr: "127.0.0.1:19999".parse().unwrap(),
        x25519_pub: [0xEEu8; 32],
        pow_nonce: 0,
        uptime_secs: 999_999,
        tier: aether_core::net::reachability::Tier::Open,
    };

    assert_eq!(absorb_response(&mut dir, PexResponse { relays: vec![forged] }), 0);
    assert!(dir.is_empty());
}
