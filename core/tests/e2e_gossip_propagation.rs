//! Gossip 伝播 ── Broadcast Veil が「出口 ≠ 購読者」でも成立すること (2-1 の回帰)
//!
//! # 何を守るか
//!
//! Broadcast Veil の前提は「**全ノードが全 Hint を受け取り、自分宛てかは手元で判定する**」。
//! これが崩れると、購読者は Hint の onion 出口リレーになった時しか受信できず、
//! 実網（購読者 ≠ 出口が普通）では push 購読がほぼ機能しない。
//!
//! # 過去のバグ
//!
//! 拡散先を `PeerManager`（自分が accept した inbound 接続のみ）から選んでいた。
//! 種は Connection Reversal で「相手の接続に返信するだけ」なので leaf ノードの
//! PeerManager に載らず、出口が leaf のとき Hint が種（＝購読者）へ届かなかった。
//! 修正: 拡散先をディレクトリ（既知リレー全体）から無作為抽選する。
//!
//! このテストは **C に Hint を注入し、出口でない A・B の gossip 購読へ届く**ことを確認する。

mod common;

use aether_core::crypto::identity::{Identity, NodeId};
use aether_core::net::reachability::Tier;
use aether_core::net::relay::RelayClient;
use aether_core::net::relay_list::RelayDescriptor;
use aether_core::node::server::NodeServer;
use aether_core::protocol::hint::HintPacket;
use aether_core::protocol::wire::PacketType;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn hint_reaches_subscribers_that_are_not_the_exit_relay() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let dir_c = tempfile::tempdir().unwrap();

    // ポートは OS 任せ（固定すると並列実行で衝突する）
    let a = Arc::new(
        NodeServer::with_config(0, Identity::generate(), dir_a.path(), &common::test_config())
            .unwrap(),
    );
    let b = Arc::new(
        NodeServer::with_config(0, Identity::generate(), dir_b.path(), &common::test_config())
            .unwrap(),
    );
    let c = Arc::new(
        NodeServer::with_config(0, Identity::generate(), dir_c.path(), &common::test_config())
            .unwrap(),
    );
    let a_addr = a.descriptor.addr;
    let b_addr = b.descriptor.addr;
    let c_addr = c.descriptor.addr;

    for node in [&a, &b, &c] {
        let node = node.clone();
        tokio::spawn(async move {
            let _ = node.run().await;
        });
    }
    common::wait_for_listener(a_addr).await;
    common::wait_for_listener(b_addr).await;
    common::wait_for_listener(c_addr).await;

    // B, C は A を種にして参加する。
    // ここが要点: C は A へ**ダイヤルする**（outbound）が、A は Connection Reversal で
    // C の接続に返信するだけなので、**C の PeerManager には A が載らない**。
    // それでも C はディレクトリで A を知るので、拡散はディレクトリ経由なら届く。
    b.bootstrap(a_addr).await.unwrap();
    c.bootstrap(a_addr).await.unwrap();

    // C が 3 リレー（A・B・自分）を知るまで待つ。拡散先はここから選ばれる。
    common::wait_until(
        "C's directory converges to all 3 relays",
        common::DEFAULT_TIMEOUT,
        || async { c.directory_size().await >= 3 },
    )
    .await;

    // A・B の gossip を購読する（**Hint 注入より前に**。broadcast は既存の受信者にだけ配る）
    let mut rx_a = a.gossip().subscribe();
    let mut rx_b = b.gossip().subscribe();

    // C に Hint を注入する ── C が onion 出口 / 中継ノードになった状況。
    // A も B も出口ではない。
    let mut hint = HintPacket::new([0x7E; 4], [0x11; 12], vec![0x22; 48], 5);
    hint.seal_pow(0).unwrap(); // テストは難易度 0
    let expected_id = hint.id();

    let sender = RelayClient::new().unwrap();
    sender
        .send_direct_packet(c_addr, PacketType::GossipHint, &hint.encode().unwrap())
        .await
        .unwrap();

    // A（出口でない購読者）が受け取る
    let got_a = tokio::time::timeout(common::DEFAULT_TIMEOUT, rx_a.recv())
        .await
        .expect("A が Hint を受信しなかった（gossip 拡散が購読者へ届いていない）")
        .expect("A の gossip チャネルが閉じている");
    assert_eq!(got_a.id(), expected_id, "A に届いた Hint が注入したものと一致しない");

    // B（出口でない購読者）も受け取る＝全ノードに広がる Broadcast Veil
    let got_b = tokio::time::timeout(common::DEFAULT_TIMEOUT, rx_b.recv())
        .await
        .expect("B が Hint を受信しなかった（拡散が全ノードに広がっていない）")
        .expect("B の gossip チャネルが閉じている");
    assert_eq!(got_b.id(), expected_id, "B に届いた Hint が注入したものと一致しない");
}

/// Dandelion++ stem に**黒穴の後継が混じっても配送は保証される** (3-2 echo 再送の回帰)
///
/// # 何を守るか
///
/// stem 相で選ばれた後継が死んでいる（ACK を返さない）と、そこで Hint が消えれば
/// 放流が黙って落ちる。修正: ACK が返らない後継は黒穴とみなし別の後継へ echo 再送し、
/// 生きた後継が尽きれば自分で fluff する。**どの分岐でも購読者へ必ず届く**こと。
///
/// A の**ディレクトリに死んだリレー D を注入**して stem 後継の候補に混ぜ、A へ
/// `StemHint` を撃つ（＝ A の `inject_hint` / 再送ループを起動する）。出口でない
/// 購読者 B が、黒穴 D が候補に居ても Hint を受け取ることを確認する。
#[tokio::test]
async fn stem_delivery_survives_a_black_hole_successor() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

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

    for node in [&a, &b] {
        let node = node.clone();
        tokio::spawn(async move {
            let _ = node.run().await;
        });
    }
    common::wait_for_listener(a_addr).await;
    common::wait_for_listener(b_addr).await;

    // B が A を種に参加。PexRequest の吸収で A も B を学ぶ（相互に知り合う）
    b.bootstrap(a_addr).await.unwrap();
    common::wait_until("A and B know each other", common::DEFAULT_TIMEOUT, || async {
        a.directory_size().await >= 2 && b.directory_size().await >= 2
    })
    .await;

    // **死んだリレー D を A のディレクトリへ注入する。** 何も listen していない
    // アドレスなので stem を撃っても ACK は返らない（黒穴）。stem 後継の候補に混ざる。
    {
        let dead = RelayDescriptor {
            node_id: NodeId([0xDD; 32]),
            addr: "127.0.0.1:9".parse().unwrap(), // discard port: 誰も受けない
            x25519_pub: [0u8; 32],
            pow_nonce: 0,
            uptime_secs: 0,
            tier: Tier::Open,
            issued_at: 0,
            signature: Vec::new(),
        };
        a.directory().write().await.insert_unchecked(dead);
    }

    // 注入より前に購読する（broadcast は既存の受信者にだけ配る）
    let mut rx_b = b.gossip().subscribe();

    // A へ StemHint を撃つ ── A が stem 相の中継ノードになった状況。
    // A は後継（B か 死んだ D）へ forward し、D なら ACK が来ず B へ再送 / fluff する。
    let mut hint = HintPacket::new([0x3B; 4], [0x55; 12], vec![0x66; 48], 5);
    hint.seal_pow(0).unwrap();
    let expected_id = hint.id();

    let sender = RelayClient::new().unwrap();
    sender
        .send_direct_packet(a_addr, PacketType::StemHint, &hint.encode().unwrap())
        .await
        .unwrap();

    // 黒穴 D が候補に居ても B は Hint を受け取る（再送 or fail-safe fluff で配送保証）。
    // 最悪ケース（stem→D で ACK 待ち + 再送、または fail-safe 3s）を吸収する余裕を持たせる。
    let got_b = tokio::time::timeout(Duration::from_secs(8), rx_b.recv())
        .await
        .expect("B が Hint を受信しなかった（黒穴後継で放流が落ちた）")
        .expect("B の gossip チャネルが閉じている");
    assert_eq!(got_b.id(), expected_id, "B に届いた Hint が注入したものと一致しない");
}

/// 拡散は **id で重複排除** され、同じ Hint が何周しても購読者へは 1 回だけ届く
///
/// 拡散先をディレクトリ全体にした後も、フラッドが購読者に多重配送されないことを守る。
#[tokio::test]
async fn duplicate_flood_is_delivered_to_a_subscriber_only_once() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

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

    for node in [&a, &b] {
        let node = node.clone();
        tokio::spawn(async move {
            let _ = node.run().await;
        });
    }
    common::wait_for_listener(a_addr).await;
    common::wait_for_listener(b_addr).await;

    b.bootstrap(a_addr).await.unwrap();
    common::wait_until("B knows A", common::DEFAULT_TIMEOUT, || async {
        b.directory_size().await >= 2
    })
    .await;

    let mut rx_a = a.gossip().subscribe();

    let mut hint = HintPacket::new([0x5A; 4], [0x33; 12], vec![0x44; 48], 5);
    hint.seal_pow(0).unwrap();
    let expected_id = hint.id();

    // 同じ Hint を B へ 3 回注入する（フラッドで戻ってくる状況の模擬）
    let sender = RelayClient::new().unwrap();
    for _ in 0..3 {
        sender
            .send_direct_packet(b_addr, PacketType::GossipHint, &hint.encode().unwrap())
            .await
            .unwrap();
    }

    // A は 1 回だけ受け取る
    let first = tokio::time::timeout(common::DEFAULT_TIMEOUT, rx_a.recv())
        .await
        .expect("A が Hint を受信しなかった")
        .expect("channel closed");
    assert_eq!(first.id(), expected_id);

    // 2 回目以降は来ない（重複排除）
    let second = tokio::time::timeout(Duration::from_millis(500), rx_a.recv()).await;
    assert!(
        second.is_err(),
        "同一 Hint が購読者へ複数回配送されている（dedup が効いていない）"
    );
}
