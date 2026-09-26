//! シュレーディンガーMailbox の往復 E2E (設計書 Phase 1)
//!
//! これまで `process_hint()` はモックを返すだけで、
//! 「Hint を復号して mailbox_key は得られるが、どこへ問い合わせればよいか誰も知らない」
//! 状態だった (18.5.1)。本テストは以下を通しで検証する。
//!
//! ```text
//! Alice: 本体を K最近接の Mailbox へ PUT (Onion, 出口 != Mailbox)
//!        Hint を Gossip へ放流 (Onion)
//! Bob:   Hint を試行復号 → mailbox_key
//!        同じ K最近接をローカル計算 → MailboxGet (Onion, 送信元秘匿)
//!        Mailbox は Inbound Tunnel へ投げ返す (要求者の IP を知らないまま)
//!        Bob がトンネルから回収して復号
//! ```

use aether_core::crypto::identity::{Identity, NodeId};
use aether_core::mailbox::schrodinger::SchrodingerMailbox;
use aether_core::net::gossip::GossipClient;
use aether_core::net::onion::OnionCircuit;
use aether_core::net::relay::RelayClient;
use aether_core::net::relay_list::{RelayDescriptor, RelayDirectory};
use aether_core::net::tunnel::InboundTunnel;
use aether_core::protocol::wire::PacketType;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

mod common;

struct Node {
    identity_x25519: [u8; 32],
    node_id: NodeId,
    addr: SocketAddr,
    server: Arc<aether_core::node::server::NodeServer>,
    _dir: tempfile::TempDir,
}

async fn node(port: u16) -> Node {
    let identity = Identity::generate();
    let node_id = identity.public_id();
    let identity_x25519 = x25519_dalek::PublicKey::from(&identity.x25519_secret()).to_bytes();
    let dir = tempfile::tempdir().unwrap();
    let server = common::spawn_ready_node(port, identity, dir.path()).await;

    Node {
        identity_x25519,
        node_id,
        addr: format!("127.0.0.1:{}", port).parse().unwrap(),
        server,
        _dir: dir,
    }
}

fn descriptor(n: &Node) -> RelayDescriptor {
    RelayDescriptor {
        node_id: n.node_id,
        addr: n.addr,
        x25519_pub: n.identity_x25519,
        pow_nonce: 0,
        uptime_secs: 3600,
        tier: aether_core::net::reachability::Tier::Open,
        issued_at: 0,
        signature: Vec::new(),
    }
}

/// 1ホップ回路（出口リレー = `exit`）を張った RelayClient を作る
async fn client_via(exit: &Node) -> RelayClient {
    let mut client = RelayClient::new().unwrap();
    client.connect_entry(exit.addr).await.expect("connect to exit");

    let mut circuit = OnionCircuit::new();
    circuit.add_hop(exit.addr, exit.identity_x25519).unwrap();
    client.set_circuit(circuit);
    client
}

#[tokio::test]
async fn message_travels_from_alice_to_bob_through_the_mailbox() {
    // --- ネットワーク構成 ---
    // exit      : Alice / Bob の出口リレー
    // storage   : Mailbox 候補（K最近接で選ばれる）
    // gateway   : Bob の Inbound Tunnel の入口
    let exit = node(19401).await;
    let gateway = node(19404).await;
    let bob_node = node(19405).await;

    // シャードが散る先。RS 3+2 なので最低5台
    let mut storage = Vec::new();
    for port in 19410..19430 {
        storage.push(node(port).await);
    }

    // 全員が同じリレーリストを持つ（記述子の検証は relay_list の単体テストで見る）
    let mut dir = RelayDirectory::new(aether_core::net::ring::EPOCH_SEED_PLACEHOLDER, 0);
    for n in &storage {
        dir.insert_unchecked(descriptor(n));
    }
    let directory = Arc::new(RwLock::new(dir));

    // --- Alice / Bob の識別子と共有秘密 (X3DH の結果を模す) ---
    let bob_id = NodeId([0xB0u8; 32]);
    let shared_secret = [0x5Au8; 32];

    let alice_contacts = Arc::new(Mutex::new(HashMap::new()));
    alice_contacts.lock().unwrap().insert(bob_id, shared_secret);

    let bob_contacts = Arc::new(Mutex::new(HashMap::new()));
    bob_contacts
        .lock()
        .unwrap()
        .insert(NodeId([0xA1u8; 32]), shared_secret);

    // --- Bob: 返信用の Inbound Tunnel を張る ---
    // gateway -> bob_node の2ホップ。Mailbox は gateway しか知らない。
    let tunnel_path = vec![gateway.addr, bob_node.addr];
    let tunnel_keys = vec![gateway.identity_x25519, bob_node.identity_x25519];
    let (bob_tunnel, instructions) = InboundTunnel::build(tunnel_path, tunnel_keys).unwrap();
    let receive_tunnel_id = bob_tunnel.receive_tunnel_id;

    let builder = RelayClient::new().unwrap();
    for (addr, payload) in instructions {
        builder
            .send_direct_packet(addr, PacketType::TunnelBuild, &payload)
            .await
            .expect("tunnel build");
    }
    common::wait_until("tunnel hops to register", common::DEFAULT_TIMEOUT, || async {
        gateway.server.tunnel_count().await >= 1 && bob_node.server.tunnel_count().await >= 1
    })
    .await;

    let bob_mailbox = SchrodingerMailbox::with_directory(
        Arc::new(client_via(&exit).await),
        Arc::new(GossipClient::new(RelayClient::new().unwrap())),
        bob_contacts,
        directory.clone(),
    );
    bob_mailbox.register_inbound_tunnel(bob_tunnel);

    // --- Alice: 送信 ---
    let alice_mailbox = SchrodingerMailbox::with_directory(
        Arc::new(client_via(&exit).await),
        Arc::new(GossipClient::new(RelayClient::new().unwrap())),
        alice_contacts,
        directory.clone(),
    );

    let message = b"schrodinger round trip through reed-solomon shards";

    // 送信（分割して各シャードを別座標へ配置）。
    // Hint と実際に使われた mailbox_key を受け取る
    let (hint, mailbox_key) = alice_mailbox
        .place_body(&bob_id, message)
        .await
        .expect("send");

    // 送信側と受信側が独立に同じ担当集合へ到達すること（全シャードで）
    for i in 0..5u8 {
        let a = alice_mailbox.shard_targets(&mailbox_key, &shared_secret, i).await;
        let b = bob_mailbox.shard_targets(&mailbox_key, &shared_secret, i).await;
        assert_eq!(a, b, "シャード {} の担当がずれている", i);
        assert!(!a.is_empty());
    }

    // シャードがリング上に散っていること (18.5.4)
    let mut first_holders = Vec::new();
    for i in 0..5u8 {
        first_holders.push(alice_mailbox.shard_targets(&mailbox_key, &shared_secret, i).await[0]);
    }
    let unique: std::collections::HashSet<_> = first_holders.iter().collect();
    assert!(
        unique.len() >= 3,
        "5シャードが同じノードに集中している: {:?}",
        first_holders
    );

    // 全体でシャード数ぶんの格納が起きるまで待つ
    common::wait_until("shards to land", common::DEFAULT_TIMEOUT, || async {
        let mut total = 0;
        for n in &storage {
            total += n.server.mailbox().len();
        }
        total >= 5
    })
    .await;

    // 出口リレーは本体を保持していないこと
    assert_eq!(
        exit.server.mailbox().len(),
        0,
        "出口リレーが本体を抱えている（出口 = Mailbox に退行している）"
    );

    // 配置が広く散っていること（否認可能性の前提）
    //
    // 「どの1台も全シャードを持たない」は網の規模に依存する確率的性質で、
    // 候補が K_REPLICAS 程度しかいない小さな網では保証できない。
    // ここでは保持者の総数が K を明確に超えることを確認する。
    let mut holders = std::collections::HashSet::new();
    for i in 0..5u8 {
        for addr in alice_mailbox.shard_targets(&mailbox_key, &shared_secret, i).await {
            holders.insert(addr);
        }
    }
    assert!(
        holders.len() > 5,
        "全シャードが同じ K 台に集中している: {} 台",
        holders.len()
    );

    // --- Bob: Hint を受けて取得要求を出す ---
    let requested = bob_mailbox
        .process_hint(&hint)
        .await
        .expect("process_hint failed")
        .expect("Bob should recognise the hint as his own");

    assert_eq!(requested, mailbox_key, "復号した mailbox_key が一致しない");

    // --- Mailbox が Inbound Tunnel 経由で投げ返す ---
    //
    // K レプリカ × 5シャードぶんの応答が来るが、**同じシャードの複製が
    // 先に3件届いても復元できない**。異なるインデックスが3つ要る。
    // 実運用でも同じなので、揃うまで集め続ける。
    let mut collected: Vec<Vec<u8>> = Vec::new();
    let mut plaintext = None;

    for _ in 0..200 {
        let raw = bob_node
            .server
            .mailbox()
            .fetch_tunnel_messages(&receive_tunnel_id)
            .await
            .unwrap();

        collected.extend(bob_mailbox.decrypt_replies(&raw));

        if let Ok(Some(msg)) = bob_mailbox.reassemble(&collected, &mailbox_key, &shared_secret) {
            plaintext = Some(msg);
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(!collected.is_empty(), "トンネルに応答が届いていない");
    let plaintext = plaintext.expect("3つの異なるシャードが揃わなかった");

    assert_eq!(plaintext, message, "Alice の平文に戻らない");
}
