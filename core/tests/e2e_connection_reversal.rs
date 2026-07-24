//! Connection Reversal — NAT 内ノードが保持者になれること
//!
//! # なぜこれが要るか
//!
//! NAT の内側にいるノードには、こちらからダイヤルしても届かない。
//! 届かないと Mailbox（保持者）になれず、キャッシュが
//! **「自分が取りに行ったものだけ」**になる。
//!
//! ```text
//! 保持者になれる : {取得したもの} ∪ {割り当てられたもの}  ← カバーがある
//! なれない       : {取得したもの}                         ← 全部が意図的な取得
//! ```
//!
//! 設計書 18.3-C の否認可能性は後者では成立しない。
//! **投稿は outbound だけなので NAT 内でもできるが、保持ができないと
//! 「触れたもの全部を自分で選んだ」ノードになり、かえって危険になる。**
//!
//! # 仕組み
//!
//! QUIC は双方向なので、**相手が張った接続の上でこちらからストリームを開ける**。
//! accept した接続をプールへ登録しておけば、ダイヤルせずに送り返せる。
//!
//! Winny の Port0 救済、BitTorrent BEP 55、libp2p Circuit Relay、
//! Tailscale DERP が全部この形。

use aether_core::crypto::identity::Identity;
use aether_core::net::quic::QuicClient;
use aether_core::protocol::wire::{self, PacketType};
use std::net::SocketAddr;

mod common;

/// ダイヤルできない相手（NAT 内ノード）を模したクライアント
///
/// サーバを持たないので、外から接続することは原理的にできない。
/// 唯一の経路は、こちらから張った接続の折り返しだけ。
struct UnreachableNode {
    client: QuicClient,
}

impl UnreachableNode {
    fn new() -> Self {
        Self {
            client: QuicClient::new().unwrap(),
        }
    }
}

#[tokio::test]
async fn unreachable_node_can_be_reached_over_its_own_connection() {
    // ポートは OS に任せる。固定すると並列実行や別のテストランと衝突して
    // bind に失敗し、退行と見分けがつかない偽の失敗になる
    let dir = tempfile::tempdir().unwrap();
    let relay = std::sync::Arc::new(
        aether_core::node::server::NodeServer::with_config(
            0,
            Identity::generate(),
            dir.path(),
            &common::test_config(),
        )
        .unwrap(),
    );
    let addr: SocketAddr = relay.descriptor.addr;

    let running = relay.clone();
    tokio::spawn(async move {
        let _ = running.run().await;
    });
    // --- NAT 内ノードがリレーへ接続する（outbound のみ） ---
    //
    // 別途プローブ接続を張ると、それもピアとして記録されて紛らわしいので、
    // この接続自体を待ち合わせに使う。
    let nat_node = UnreachableNode::new();
    let mut conn = None;
    for _ in 0..200 {
        if let Ok(c) = nat_node.client.connect(addr, "aether-node").await {
            conn = Some(c);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let conn = conn.expect("outbound は NAT 内からでも通るはず");

    // リレー側がこの接続を登録するまで待つ
    let relay_probe = relay.clone();
    common::wait_until("relay to register the inbound connection", common::DEFAULT_TIMEOUT, || {
        let relay = relay_probe.clone();
        async move {
            for peer in relay.peers().get_random_peers(8).await {
                if relay.router.has_live_connection(peer).await {
                    return true;
                }
            }
            false
        }
    })
    .await;

    // --- リレーが「ダイヤルせずに」NAT 内ノードへ送れること ---
    //
    // send_packet_existing はダイヤルへフォールバックしない。
    // これが通るということは、相手が張った接続を再利用できている。
    let mut payload = vec![0x5Au8; 32]; // mailbox key
    payload.extend_from_slice(b"pushed down the reversed connection");

    let mut delivered = false;
    for peer in relay.peers().get_random_peers(8).await {
        if relay
            .router
            .send_packet_existing(peer, PacketType::MailboxPut, &payload)
            .await
            .is_ok()
        {
            delivered = true;
        }
    }
    assert!(
        delivered,
        "既存接続を再利用できていない。NAT 内ノードへ送り返せない"
    );

    // --- NAT 内ノードが実際に受け取れること ---
    let mut recv = conn
        .accept_uni()
        .await
        .expect("相手が張った接続の上でストリームが開かれるはず");

    let (packet_type, body) = wire::read_packet(&mut recv).await.unwrap();

    assert_eq!(packet_type, PacketType::MailboxPut);
    assert_eq!(
        &body[32..],
        b"pushed down the reversed connection",
        "押し込まれた内容が一致しない"
    );
}

#[tokio::test]
async fn inbound_connections_survive_the_outbound_ttl() {
    // outbound の TTL/アイドル規則で inbound を切ると、
    // NAT 内ノードへの唯一の経路を自分から捨てることになる。
    // ポートは OS に任せる。固定すると並列実行や別のテストランと衝突して
    // bind に失敗し、退行と見分けがつかない偽の失敗になる
    let dir = tempfile::tempdir().unwrap();
    let relay = std::sync::Arc::new(
        aether_core::node::server::NodeServer::with_config(
            0,
            Identity::generate(),
            dir.path(),
            &common::test_config(),
        )
        .unwrap(),
    );
    let addr: SocketAddr = relay.descriptor.addr;

    let running = relay.clone();
    tokio::spawn(async move {
        let _ = running.run().await;
    });
    common::wait_for_listener(addr).await;

    let nat_node = UnreachableNode::new();
    let _conn = nat_node.client.connect(addr, "aether-node").await.unwrap();

    let router = relay.router.clone();
    common::wait_until("inbound registered", common::DEFAULT_TIMEOUT, || {
        let router = router.clone();
        async move { router.inbound_count().await > 0 }
    })
    .await;

    // outbound のアイドル上限 (10秒) を超えて待つ。
    // inbound が同じ規則で落とされないことを確認する
    tokio::time::sleep(std::time::Duration::from_secs(11)).await;

    relay.router.maintain_connections().await;

    assert!(
        relay.router.inbound_count().await > 0,
        "掃除で inbound 接続が落とされている。NAT 内ノードへ届かなくなる"
    );
}
