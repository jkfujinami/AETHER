//! 保持者の受け口まわりの、ノード側の受け口
//!
//! - `LeaseSetPublish` を受けたノードは、検証してディレクトリに入れる（偽の署名は入れない）
//! - 自分が終端のトンネルに届いた中身は、口を登録していれば受け箱を通さず直接渡る

use aether_core::crypto::identity::Identity;
use aether_core::net::lease_set::{solve_slots, LeaseGateway, LeaseSet};
use aether_core::net::relay::RelayClient;
use aether_core::net::tunnel::InboundTunnel;
use aether_core::protocol::hint::current_timestamp;
use aether_core::protocol::wire::PacketType;
use std::net::SocketAddr;

mod common;

fn lease(id: &Identity) -> LeaseSet {
    let gateways = vec![LeaseGateway {
        gateway: Identity::generate().public_id(),
        tunnel_id: [7; 32],
    }];
    LeaseSet::new_signed(
        id,
        solve_slots(&id.public_id().0, 1, 0, 1).unwrap(),
        gateways,
        current_timestamp(),
    )
    .unwrap()
}

#[tokio::test]
async fn lease_set_publish_is_verified_before_it_enters_the_directory() {
    let (recv_port, send_port) = (19610, 19611);
    let recv_dir = tempfile::tempdir().unwrap();
    let send_dir = tempfile::tempdir().unwrap();
    let receiver = common::spawn_ready_node(recv_port, Identity::generate(), recv_dir.path()).await;
    let _sender = common::spawn_ready_node(send_port, Identity::generate(), send_dir.path()).await;
    let recv_addr: SocketAddr = format!("127.0.0.1:{}", recv_port).parse().unwrap();
    let client = RelayClient::new().unwrap();

    // 署名を壊した偽物
    let forged_id = Identity::generate();
    let mut forged = lease(&forged_id);
    forged.signature[0] ^= 0xff;
    client
        .send_direct_packet(recv_addr, PacketType::LeaseSetPublish, &bincode::serialize(&forged).unwrap())
        .await
        .unwrap();
    // 読めない中身
    client
        .send_direct_packet(recv_addr, PacketType::LeaseSetPublish, b"not a lease set")
        .await
        .unwrap();

    // 本物
    let good_id = Identity::generate();
    let good = lease(&good_id);
    client
        .send_direct_packet(recv_addr, PacketType::LeaseSetPublish, &bincode::serialize(&good).unwrap())
        .await
        .unwrap();

    common::wait_until("valid lease set to enter the directory", common::DEFAULT_TIMEOUT, || async {
        receiver.directory().read().await.lease_set(&good.sid).is_some()
    })
    .await;
    // 偽物は本物より先に送ってある。本物が入った時点で、偽物の判定も済んでいる
    let dir = receiver.directory();
    let dir = dir.read().await;
    assert!(dir.lease_set(&forged.sid).is_none(), "署名の偽物が入った");
    assert_eq!(dir.lease_set_count(), 1, "入ったのは本物の 1 件だけのはず");
}

#[tokio::test]
async fn tunnel_end_message_goes_to_the_registered_sink_not_the_inbox() {
    let (gw_port, relay_port, alice_port) = (19612, 19613, 19614);
    let gw_addr: SocketAddr = format!("127.0.0.1:{}", gw_port).parse().unwrap();
    let relay_addr: SocketAddr = format!("127.0.0.1:{}", relay_port).parse().unwrap();
    let alice_addr: SocketAddr = format!("127.0.0.1:{}", alice_port).parse().unwrap();
    let (gw_id, relay_id, alice_id) = (Identity::generate(), Identity::generate(), Identity::generate());
    let x = |id: &Identity| x25519_dalek::PublicKey::from(&id.x25519_secret()).to_bytes();
    let pubkeys = vec![x(&gw_id), x(&relay_id), x(&alice_id)];

    let (gw_dir, relay_dir, alice_dir) =
        (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let gw = common::spawn_ready_node(gw_port, gw_id, gw_dir.path()).await;
    let relay = common::spawn_ready_node(relay_port, relay_id, relay_dir.path()).await;
    let alice = common::spawn_ready_node(alice_port, alice_id, alice_dir.path()).await;
    common::introduce(&[&gw, &relay, &alice]).await;

    let (tunnel, instructions) =
        InboundTunnel::build(vec![gw_addr, relay_addr, alice_addr], pubkeys).unwrap();
    // 口は届く前に登録する
    let mut sink = alice.register_tunnel_sink(tunnel.receive_tunnel_id);

    let builder = RelayClient::new().unwrap();
    for (addr, payload) in instructions {
        builder.send_direct_packet(addr, PacketType::TunnelBuild, &payload).await.unwrap();
    }
    common::wait_until("all hops to register the tunnel", common::DEFAULT_TIMEOUT, || async {
        gw.tunnel_count().await >= 1 && relay.tunnel_count().await >= 1 && alice.tunnel_count().await >= 1
    })
    .await;

    let send = |msg: &'static [u8]| {
        let mut payload = tunnel.endpoint.tunnel_id.to_vec();
        payload.extend_from_slice(msg);
        let builder = &builder;
        async move { builder.send_direct_packet(gw_addr, PacketType::TunnelData, &payload).await.unwrap() }
    };

    send(b"hello, to the sink").await;
    let raw = tokio::time::timeout(common::DEFAULT_TIMEOUT, sink.recv())
        .await
        .expect("口に届かない")
        .expect("口が閉じた");
    assert_eq!(tunnel.decrypt(&raw).unwrap(), b"hello, to the sink");
    assert_eq!(alice.mailbox().tunnel_inbox_len(), 0, "口に渡した中身が受け箱にも入った");

    // 口を外したら、今までどおり受け箱に入る
    alice.unregister_tunnel_sink(&tunnel.receive_tunnel_id);
    send(b"hello, to the inbox").await;
    common::wait_for_tunnel_messages(&alice, 1).await;
    let stored = alice.mailbox().fetch_tunnel_messages(&tunnel.receive_tunnel_id).await.unwrap();
    assert_eq!(tunnel.decrypt(&stored[0]).unwrap(), b"hello, to the inbox");
}

/// 同じノードが 1 本のトンネルの隣り合う 2 役（gateway と中間）を担っても、終端と取り違えず先へ流す
#[tokio::test]
async fn one_node_can_play_two_adjacent_roles_in_a_tunnel() {
    let (gw_port, relay_port, alice_port) = (19615, 19616, 19617);
    let gw_addr: SocketAddr = format!("127.0.0.1:{}", gw_port).parse().unwrap();
    let relay_addr: SocketAddr = format!("127.0.0.1:{}", relay_port).parse().unwrap();
    let alice_addr: SocketAddr = format!("127.0.0.1:{}", alice_port).parse().unwrap();
    let (gw_id, relay_id, alice_id) = (Identity::generate(), Identity::generate(), Identity::generate());
    let x = |id: &Identity| x25519_dalek::PublicKey::from(&id.x25519_secret()).to_bytes();
    // gateway と 2 番目の中間は同じノード
    let pubkeys = vec![x(&gw_id), x(&gw_id), x(&relay_id), x(&alice_id)];

    let (gw_dir, relay_dir, alice_dir) =
        (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let gw = common::spawn_ready_node(gw_port, gw_id, gw_dir.path()).await;
    let relay = common::spawn_ready_node(relay_port, relay_id, relay_dir.path()).await;
    let alice = common::spawn_ready_node(alice_port, alice_id, alice_dir.path()).await;
    common::introduce(&[&gw, &relay, &alice]).await;

    let (tunnel, instructions) =
        InboundTunnel::build(vec![gw_addr, gw_addr, relay_addr, alice_addr], pubkeys).unwrap();
    let mut sink = alice.register_tunnel_sink(tunnel.receive_tunnel_id);

    let builder = RelayClient::new().unwrap();
    for (addr, payload) in instructions {
        builder.send_direct_packet(addr, PacketType::TunnelBuild, &payload).await.unwrap();
    }
    common::wait_until("all roles to register", common::DEFAULT_TIMEOUT, || async {
        gw.tunnel_count().await >= 2 && relay.tunnel_count().await >= 1 && alice.tunnel_count().await >= 1
    })
    .await;

    let mut payload = tunnel.endpoint.tunnel_id.to_vec();
    payload.extend_from_slice(b"through two roles of one node");
    builder.send_direct_packet(gw_addr, PacketType::TunnelData, &payload).await.unwrap();

    let raw = tokio::time::timeout(common::DEFAULT_TIMEOUT, sink.recv())
        .await
        .expect("2 役を担うノードで止まった")
        .expect("口が閉じた");
    assert_eq!(tunnel.decrypt(&raw).unwrap(), b"through two roles of one node");
    assert_eq!(gw.mailbox().tunnel_inbox_len(), 0, "自分の次の役を終端と取り違えて受け箱に入れた");
}
