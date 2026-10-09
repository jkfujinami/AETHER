//! リレーは MailboxForward・MailboxPut を受け付けない（段 B・設計書 18.8.2 の置き換え）
//!
//! 以前は、出口リレーが別ノードの Mailbox へ中身を転送した（出口 = Mailbox を避けるため）。
//! 段 B で中身は保持者の受け口（TunnelData）経由でしか届かなくなり、リレーは中身を
//! 預からない。出口を通した MailboxForward も、出口にも転送先にも保存されない
//! （残すと、リレーにゴミを置かれる攻撃面になる）。

use aether_core::crypto::identity::Identity;
use aether_core::net::onion::OnionCircuit;
use aether_core::net::relay::RelayClient;
use aether_core::protocol::wire::{self, InnerPacketType};
use std::net::SocketAddr;

mod common;

#[tokio::test]
async fn exit_relay_neither_keeps_nor_forwards_mailbox_payloads() {
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
    common::introduce(&[&exit_node, &mailbox_node]).await;

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
    let mut payload = Vec::new();
    payload.extend_from_slice(&mailbox_key);
    payload.extend_from_slice(b"payload no relay may keep");

    // 出口リレー(exit_addr)を通して、別ノード(mailbox_addr)へ MailboxForward を送る
    let forward = wire::build_mailbox_forward(mailbox_addr, &payload).unwrap();
    client
        .send_onion_inner(InnerPacketType::MailboxForward, &forward[1..])
        .await
        .expect("failed to send onion message");

    // 転送されていれば届くはずの猶予を置く
    common::settle().await;

    assert_eq!(
        mailbox_node.mailbox().handle_get(&mailbox_key).await.unwrap(),
        None,
        "転送先のリレーが MailboxForward 経由の中身を保存している"
    );
    assert_eq!(
        exit_node.mailbox().handle_get(&mailbox_key).await.unwrap(),
        None,
        "出口リレーが中身を保存している"
    );
    assert_eq!(exit_node.mailbox().len() + mailbox_node.mailbox().len(), 0);
}
