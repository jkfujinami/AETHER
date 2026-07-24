//! 分散 Hint backlog のオフライン追いつき (19.1.3)
//!
//! Hint は gossip の窓（数秒）を逃すと二度と来ない。担当ノードが 24h 保持し、
//! 復帰したノードが差分同期で取りこぼしを埋められることを確認する。

mod common;

use aether_core::crypto::identity::Identity;
use aether_core::net::relay::RelayClient;
use aether_core::node::server::NodeServer;
use aether_core::protocol::hint::HintPacket;
use aether_core::protocol::wire::PacketType;
use std::sync::Arc;

#[tokio::test]
async fn offline_node_catches_up_via_backlog_reconciliation() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

    // ポートは OS 任せ（固定すると並列実行で衝突する）
    let a = Arc::new(
        NodeServer::with_config(0, Identity::generate(), dir_a.path(), &common::test_config())
            .unwrap(),
    );
    let b = Arc::new(
        NodeServer::with_config(0, Identity::generate(), dir_b.path(), &common::test_config())
            .unwrap(),
    );
    let a_addr = a.descriptor.addr;
    let b_addr = b.descriptor.addr;

    {
        let a = a.clone();
        tokio::spawn(async move {
            let _ = a.run().await;
        });
    }
    {
        let b = b.clone();
        tokio::spawn(async move {
            let _ = b.run().await;
        });
    }
    common::wait_for_listener(a_addr).await;
    common::wait_for_listener(b_addr).await;

    // B は A を知る（応答が返せる & 現実的なトポロジ）
    b.bootstrap(a_addr).await.unwrap();

    // --- A だけが Hint を受け取る（B はこの間オフラインだった想定）---
    let mut hint = HintPacket::new([0xAB; 4], [0xCD; 12], vec![0x11; 48], 5);
    hint.seal_pow(0).unwrap(); // テストは難易度 0

    let sender = RelayClient::new().unwrap();
    sender
        .send_direct_packet(a_addr, PacketType::GossipHint, &hint.encode().unwrap())
        .await
        .unwrap();

    // A は担当なので backlog に保存する（ノードが K 未満なので必ず担当）
    common::wait_until("A persists the hint in its backlog", common::DEFAULT_TIMEOUT, || async {
        a.backlog_len() >= 1
    })
    .await;

    assert_eq!(b.backlog_len(), 0, "B はまだ取りこぼしている");

    // --- B が差分同期で追いつく ---
    b.reconcile_backlog_with(a_addr).await.unwrap();

    common::wait_until("B catches up via reconciliation", common::DEFAULT_TIMEOUT, || async {
        b.backlog_len() >= 1
    })
    .await;
}
