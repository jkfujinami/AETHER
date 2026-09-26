//! 出口リレーと Mailbox が別ノードになることの検証 (設計書 18.8.2 / 穴2)
//!
//! Mailbox の位置は `H(mailbox_key ‖ K)` で決定論的に決まる。
//! 出口リレー = Mailbox だと、攻撃者は Sybil で座標を合わせるだけで
//! 狙ったコンテンツの出口リレーになれてしまう（確率 f ではなく確定）。
//! 入口さえ引けばタイミング相関が成立する。
//!
//! 分離すると、Mailbox から見える送信元は「出口リレーの IP」になり、
//! Sybil で Mailbox の座を取っても発信者には近づけない。

use aether_core::crypto::identity::Identity;
use aether_core::net::onion::OnionCircuit;
use aether_core::net::relay::RelayClient;
use std::net::SocketAddr;

mod common;

#[tokio::test]
async fn exit_relay_forwards_to_a_different_mailbox() {
    let exit_port = 19301;
    let mailbox_port = 19302;

    let exit_addr: SocketAddr = format!("127.0.0.1:{}", exit_port).parse().unwrap();
    let mailbox_addr: SocketAddr = format!("127.0.0.1:{}", mailbox_port).parse().unwrap();

    let exit_id = Identity::generate();
    let mailbox_id = Identity::generate();

    // 出口リレーの X25519 公開鍵（Onion の最終層はこの鍵で暗号化される）
    let exit_x25519 = x25519_dalek::PublicKey::from(&exit_id.x25519_secret()).to_bytes();

    let exit_dir = tempfile::tempdir().unwrap();
    let mailbox_dir = tempfile::tempdir().unwrap();

    let exit_node = common::spawn_ready_node(exit_port, exit_id, exit_dir.path()).await;
    let mailbox_node = common::spawn_ready_node(mailbox_port, mailbox_id, mailbox_dir.path()).await;

    // クライアントは出口リレーへの1ホップ回路を張る
    let mut client = RelayClient::new().unwrap();
    client
        .connect_entry(exit_addr)
        .await
        .expect("failed to connect to exit relay");

    let mut circuit = OnionCircuit::new();
    circuit.add_hop(exit_addr, exit_x25519).unwrap();
    client.set_circuit(circuit);

    // Mailbox ペイロード: [Key(32)][Value]
    let mailbox_key = [0x7Au8; 32];
    let body = b"payload the exit relay must not keep";

    let mut payload = Vec::new();
    payload.extend_from_slice(&mailbox_key);
    payload.extend_from_slice(body);

    // 出口リレー(exit_addr)を通して、別ノード(mailbox_addr)の Mailbox へ送る
    client
        .send_onion_message(&payload, mailbox_addr)
        .await
        .expect("failed to send onion message");

    // 転送が完了するまで待つ
    common::wait_for_mailbox_entries(&mailbox_node, 1).await;

    // 本体は Mailbox ノードにだけ存在すること
    let stored = mailbox_node
        .mailbox()
        .handle_get(&mailbox_key)
        .await
        .unwrap();
    assert_eq!(
        stored.as_deref(),
        Some(&body[..]),
        "指定した Mailbox ノードに本体が届いていない"
    );

    // 出口リレーは中身を保持していないこと
    let leaked = exit_node.mailbox().handle_get(&mailbox_key).await.unwrap();
    assert_eq!(
        leaked, None,
        "出口リレーが本体を保持している。これでは出口 = Mailbox となり、\
         Sybil で狙ったコンテンツの出口を確定で取られてしまう"
    );
}
