use aether_core::node::server::NodeServer;
use aether_core::net::relay::RelayClient;
use aether_core::crypto::identity::Identity;
use aether_core::net::onion::OnionCircuit;
use aether_core::crypto::key_exchange;
use aether_core::mailbox::schrodinger::SchrodingerMailbox;
use aether_core::protocol::wire::PacketType;
use aether_core::net::gossip::GossipClient;
use std::time::Duration;
use tokio::time::sleep;
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

    let bob_server = Arc::new(NodeServer::new(port, bob_id, server_db.path()).unwrap());
    let bob_server_clone = bob_server.clone();

    // Run server in background
    tokio::spawn(async move {
        if let Err(e) = bob_server_clone.run().await {
            eprintln!("Server Error: {}", e);
        }
    });

    // Wait for server startup
    sleep(Duration::from_millis(500)).await;

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

    // Wait for processing
    sleep(Duration::from_millis(500)).await;

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

    // 7. Send Gossip Hint
    // broadcast uses send_raw_packet
    let hint_bytes = bincode::serialize(&hint).unwrap();
    println!("Sending Gossip Hint...");
    relay_client.send_raw_packet(PacketType::GossipHint, &hint_bytes).await.expect("Failed send hint");

    sleep(Duration::from_millis(500)).await;

    // 8. Verify Bob received Gossip Hint
    // Since handle_hint returns false if duplicate, we check if it returns false for the same hint.
    // (If it was never received, it would return true)
    let is_new = bob_server.gossip().handle_hint(&hint_bytes).await.unwrap();
    assert!(!is_new, "Hint should be already seen by Bob (so now it's not new)");

    println!("E2E Gossip Hint Test Passed!");
}
