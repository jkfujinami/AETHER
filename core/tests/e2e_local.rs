use aether_core::net::relay::RelayClient;
use aether_core::crypto::identity::Identity;
use aether_core::net::onion::OnionCircuit;
use aether_core::crypto::key_exchange;
use aether_core::mailbox::schrodinger::SchrodingerMailbox;
use aether_core::protocol::wire::InnerPacketType;
use aether_core::net::gossip::GossipClient;
use aether_core::net::gossip_server::HintAction;

mod common;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

#[tokio::test]
async fn test_local_e2e_mailbox_put() {
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
    let mut circuit = OnionCircuit::new(1);

    let client_ephemeral = key_exchange::EphemeralKey::generate();

    circuit.add_hop(bob_addr, bob_x25519_pub_bytes, client_ephemeral).unwrap();
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
    let (payload, hint) = mailbox.prepare_packet(&bob_public_id, message).unwrap();

    // 5. Send Onion Packet (Mailbox Put)
    // payload = [Key][Nonce][EncMsg]
    println!("Sending Onion Packet ({} bytes)...", payload.len());
    relay_client.send_onion_message(&payload, bob_addr).await.expect("Failed to send onion");

    common::wait_for_mailbox_entries(&bob_server, 1).await;

    // 6. Verify Bob received Mailbox Put
    // Key is first 32 bytes
    let mailbox_key: [u8; 32] = payload[0..32].try_into().unwrap();

    // Check Bob's Mailbox Server directly
    let stored = bob_server.mailbox().handle_get(&mailbox_key).await.unwrap();
    assert!(stored.is_some(), "Message should be saved in Bob's mailbox");

    let stored_bytes = stored.unwrap();
    // stored content: [MsgNonce(12)] + [EncMsg(msg+tag)]
    assert_eq!(stored_bytes.len(), 12 + message.len() + 16);

    println!("E2E Mailbox PUT Test Passed!");

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

    println!("E2E Gossip Hint Test Passed!");
}
