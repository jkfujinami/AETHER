use aether_core::net::relay::RelayClient;
use aether_core::crypto::identity::Identity;
use aether_core::net::tunnel::InboundTunnel;
use aether_core::protocol::wire::PacketType;

mod common;
use std::net::SocketAddr;

#[tokio::test]
async fn test_inbound_tunnel_e2e() {
    // 1. Setup Nodes
    let gw_port = 19110;
    let relay_port = 19111;
    let alice_port = 19112;

    let gw_addr: SocketAddr = format!("127.0.0.1:{}", gw_port).parse().unwrap();
    let relay_addr: SocketAddr = format!("127.0.0.1:{}", relay_port).parse().unwrap();
    let alice_addr: SocketAddr = format!("127.0.0.1:{}", alice_port).parse().unwrap();

    let gw_id = Identity::generate();
    let relay_id = Identity::generate();
    let alice_id = Identity::generate();

    let gw_x25519 = x25519_dalek::PublicKey::from(&gw_id.x25519_secret()).to_bytes();
    let relay_x25519 = x25519_dalek::PublicKey::from(&relay_id.x25519_secret()).to_bytes();
    let alice_x25519 = x25519_dalek::PublicKey::from(&alice_id.x25519_secret()).to_bytes();

    let gw_dir = tempfile::tempdir().unwrap();
    let relay_dir = tempfile::tempdir().unwrap();
    let alice_dir = tempfile::tempdir().unwrap();

    let _gw_server = common::spawn_ready_node(gw_port, gw_id, gw_dir.path()).await;
    let _relay_server = common::spawn_ready_node(relay_port, relay_id, relay_dir.path()).await;
    let alice_server = common::spawn_ready_node(alice_port, alice_id, alice_dir.path()).await;
    common::introduce(&[&_gw_server, &_relay_server, &alice_server]).await;

    // 2. Alice builds tunnel: Gateway -> Relay -> Alice
    // Alice acts as a client to set this up.
    let alice_client = RelayClient::new().unwrap();
    // InboundTunnel build logic
    let path = vec![gw_addr, relay_addr, alice_addr];
    let pubkeys = vec![gw_x25519, relay_x25519, alice_x25519];  // Include all hops including Alice

    let (tunnel, instructions) = InboundTunnel::build(path, pubkeys).unwrap();
    let endpoint = tunnel.endpoint.clone();

    println!("Alice: Building tunnel with ID {:?}", endpoint.tunnel_id);

    // Alice sends Build Instructions
    for (addr, payload) in instructions {
        println!("Alice: sending Build to {} (payload size: {})", addr, payload.len());
        alice_client.send_direct_packet(addr, PacketType::TunnelBuild, &payload).await.expect("Failed to send build packet");
        println!("Alice: Build packet sent successfully to {}", addr);
    }

    // 3本のトンネルが登録されるまで待つ
    common::wait_until("all 3 hops to register the tunnel", common::DEFAULT_TIMEOUT, || async {
        _gw_server.tunnel_count().await >= 1
            && _relay_server.tunnel_count().await >= 1
            && alice_server.tunnel_count().await >= 1
    })
    .await;

    // 3. Bob sends message to Alice via Inbound Tunnel (Gateway)
    let message = b"Hello Tunnel World!";
    println!("Bob: Sending message via Gateway {}", gw_addr);

    let bob_client = RelayClient::new().unwrap();

    let mut packet_payload = Vec::new();
    packet_payload.extend_from_slice(&endpoint.tunnel_id);
    packet_payload.extend_from_slice(message);

    bob_client.send_direct_packet(gw_addr, PacketType::TunnelData, &packet_payload).await.expect("Failed to send data to GW");

    common::wait_for_mailbox_entries(&alice_server, 1).await;

    // 4. Alice checks mailbox
    println!("Alice: Checking Mailbox for Tunnel Message");
    // Use alice_server instance to access mailbox locally
    let received_msgs = alice_server.mailbox.fetch_tunnel_messages(&tunnel.receive_tunnel_id).await.unwrap();

    if received_msgs.is_empty() {
        // Debugging info
        println!("Alice: No messages found!");
    } else {
        println!("Alice: Received {} messages", received_msgs.len());
    }

    assert_eq!(received_msgs.len(), 1, "Should have received 1 tunnel message");

    let encrypted_stored_msg = &received_msgs[0];

    // 5. Decrypt
    let decrypted_msg = tunnel.decrypt(encrypted_stored_msg).unwrap();
    assert_eq!(decrypted_msg, message, "Message should match after decryption");

    println!("Test Passed: Message decrypted successfully: {:?}", String::from_utf8_lossy(&decrypted_msg));
}
