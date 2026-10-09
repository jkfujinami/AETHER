use aether_core::net::relay::RelayClient;
use aether_core::crypto::identity::Identity;
use aether_core::net::onion::OnionCircuit;
use aether_core::mailbox::schrodinger::SchrodingerMailbox;
use aether_core::protocol::wire::{self, InnerPacketType};
use aether_core::net::gossip::GossipClient;
use aether_core::net::gossip_server::HintAction;

mod common;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

#[tokio::test]
async fn test_local_e2e_relay_rejects_mailbox_put_but_takes_hints() {
    // 1. Setup Bob (Server)
    let bob_id = Identity::generate();

    // Pre-calculate keys before moving bob_id
    let bob_x25519_secret = bob_id.x25519_secret();
    let bob_x25519_pub = x25519_dalek::PublicKey::from(&bob_x25519_secret);
    let bob_x25519_pub_bytes = bob_x25519_pub.to_bytes();
    let bob_public_id = bob_id.public_id();

    let port = 19001;
    let bob_addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let server_db = tempfile::tempdir().unwrap();

    let bob_server = common::spawn_ready_node(port, bob_id, server_db.path()).await;

    // 2. Setup Alice's network client (RelayClient)
    let mut relay_client = RelayClient::new().unwrap();
    // Connect to Bob as Entry Node
    relay_client.connect_entry(bob_addr).await.expect("Failed to connect to Bob");

    // 3. Setup Circuit (Alice -> Bob)
    // Assume handshake done.
    let mut circuit = OnionCircuit::new();
    circuit.add_hop(bob_addr, bob_x25519_pub_bytes).unwrap();
    relay_client.set_circuit(circuit);

    // 4. Create Packet using SchrodingerMailbox logic
    let _alice_id = Identity::generate();

    // Prepare dependencies for SchrodingerMailbox (Mock/Dummy)
    // We only use `prepare_packet` which is pure logic, so these can be dummy.
    let dummy_relay = Arc::new(RelayClient::new().unwrap());
    let dummy_gossip = Arc::new(GossipClient::new(RelayClient::new().unwrap()));
    let contacts = Arc::new(Mutex::new(HashMap::new()));

    // Register shared secret for Message Encryption (X3DH result simulation)
    let shared_secret = [0x55u8; 32];
    contacts.lock().unwrap().insert(bob_public_id, shared_secret);

    let mailbox = SchrodingerMailbox::new(dummy_relay, dummy_gossip, contacts);

    let message = b"Hello from Alice via Onion!";
    // Prepare Mailbox Payload and Hint
    let (mut payload, hint) = mailbox.prepare_packet(&bob_public_id, message).unwrap();
    // 生のキーで直接置く低い層の試験。キーの最上位ビットが 1 だと保持者は v2 のシャードとして
    // 中身のハッシュと照合する（置き場所の先書き対策）ので、v1 のキーの決まりどおり 0 にする
    payload[0] &= 0x7F;

    // 5. リレーは中身を預からない（段 B）。出口の MailboxPut・MailboxForward（自分宛て）は捨てられる
    println!("Sending Onion MailboxPut / MailboxForward ({} bytes)...", payload.len());
    relay_client
        .send_onion_inner(InnerPacketType::MailboxPut, &payload)
        .await
        .expect("Failed to send onion");
    let forward = wire::build_mailbox_forward(bob_addr, &payload).unwrap();
    relay_client
        .send_onion_inner(InnerPacketType::MailboxForward, &forward[1..])
        .await
        .expect("Failed to send onion");
    // 直接の MailboxPut・MailboxGet も同じ
    let get_body = wire::build_mailbox_get(&[0x11u8; 32], &aether_core::net::tunnel::TunnelEndpoint {
        gateway: bob_addr,
        tunnel_id: [0u8; 32],
    })
    .unwrap();
    relay_client.send_raw_packet(wire::PacketType::MailboxPut, &payload).await.expect("direct put");
    relay_client.send_raw_packet(wire::PacketType::MailboxGet, &get_body).await.expect("direct get");

    // 7. Send Gossip Hint (Onion 経由)
    // Hint を素で Entry Relay に投げると発信源 IP が割れるため、
    // 必ず Onion で包んで送る。出口リレーが Gossip への投入点になる。
    let hint_bytes = bincode::serialize(&hint).unwrap();
    println!("Sending Gossip Hint via Onion...");
    relay_client
        .send_onion_inner(InnerPacketType::GossipHint, &hint_bytes)
        .await
        .expect("Failed send hint");

    // Hint が GossipServer に登録されるまで待つ
    let seen = bob_server.gossip();
    common::wait_until("Bob to register the Hint", common::DEFAULT_TIMEOUT, || {
        let seen = seen.clone();
        async move { seen.seen_count().await > 0 }
    })
    .await;

    // 8. Verify Bob received Gossip Hint
    // 受信済みなら同じ Hint は重複として Drop されるはず。
    // 一度も届いていなければ Relay が返る。
    let action = bob_server.gossip().handle_hint(&hint_bytes).await.unwrap();
    assert_eq!(
        action,
        HintAction::Drop,
        "Onion 経由で届いた Hint が GossipServer に登録されていない"
    );

    // Hint は同じ回路で後に送ったので、先の MailboxPut・MailboxForward は処理され終わっている。
    // どれも保存されていない
    common::settle().await;
    assert_eq!(bob_server.mailbox().len(), 0, "リレーが MailboxPut・MailboxForward を受け付けている");
    let mailbox_key: [u8; 32] = payload[0..32].try_into().unwrap();
    assert!(bob_server.mailbox().handle_get(&mailbox_key).await.unwrap().is_none());

    println!("E2E Gossip Hint Test Passed!");
}
