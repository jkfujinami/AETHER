//! ワイヤ効率の実測と回帰防止
//!
//! Hint は全ノードにブロードキャストされるため、1バイトの増加が
//! ネットワーク全体でノード数倍のコストになる (設計書 18.3-E)。
//! ここでサイズ上限を固定し、うっかりフィールドが増えるのを防ぐ。

use aether_core::net::onion::OnionCircuit;
use aether_core::protocol::hint::{HintPacket, HintPayload};
use std::net::SocketAddr;
use std::time::Instant;

/// Hint パケットの許容サイズ上限（バイト）
///
/// 90 バイト + PoW nonce 8 バイト（19.2.1）= 約 98 バイト。
/// ここを超える変更は、全ノードの常時帯域に直接効く。
const HINT_SIZE_BUDGET: usize = 104;

#[test]
fn hint_packet_stays_within_budget() {
    // 実際に送出される形の Hint を組み立てる
    let payload = HintPayload {
        nonce: [0xAB; 32],
        message_id: u64::MAX,
        timestamp: u64::MAX,
    };
    let payload_bytes = bincode::serialize(&payload).unwrap();

    // ChaCha20-Poly1305 は 16 バイトのタグを付ける
    let ciphertext = vec![0u8; payload_bytes.len() + 16];

    let hint = HintPacket::new([0xFF; 4], [0xEE; 12], ciphertext, 5);
    let wire = bincode::serialize(&hint).unwrap();

    println!("HintPayload (plain):     {:>4} bytes", payload_bytes.len());
    println!("HintPacket (on the wire):{:>4} bytes", wire.len());

    assert!(
        wire.len() <= HINT_SIZE_BUDGET,
        "Hint が {} バイトに増えた（上限 {}）。\
         全ノードにブロードキャストされる構造体なので、増やす前に 18.3-E の試算を見直すこと",
        wire.len(),
        HINT_SIZE_BUDGET
    );
}

/// スループット計測を含むため既定では走らせない。
/// `cargo test --release --test wire_overhead -- --ignored --nocapture`
#[test]
#[ignore = "計測用。--release で明示実行すること"]
fn onion_layer_overhead_and_throughput() {
    let relays: Vec<SocketAddr> = vec![
        "10.0.0.1:8080".parse().unwrap(),
        "10.0.0.2:8080".parse().unwrap(),
        "10.0.0.3:8080".parse().unwrap(),
    ];

    let mut circuit = OnionCircuit::new();
    let mut secrets = Vec::new();
    for addr in &relays {
        let relay_static = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        circuit
            .add_hop(*addr, x25519_dalek::PublicKey::from(&relay_static).to_bytes())
            .unwrap();
        secrets.push(relay_static);
    }

    println!("\n--- 3-Hop Onion のペイロード膨張 ---");
    println!("{:>12} | {:>12} | {:>8}", "payload", "wrapped", "overhead");
    for size in [64usize, 1024, 64 * 1024, 256 * 1024] {
        let body = vec![0u8; size];
        let wrapped = circuit.wrap_packet(&body).unwrap();
        println!(
            "{:>12} | {:>12} | {:>7}B",
            size,
            wrapped.len(),
            wrapped.len() - size
        );
    }

    // 中継1ホップあたりの CPU コスト = 剥がす処理のスループット
    // これが回線速度より十分速くないと、リレーが CPU 律速になる
    let chunk = vec![0u8; 256 * 1024];
    let wrapped = circuit.wrap_packet(&chunk).unwrap();

    const ITERS: u32 = 200;
    let start = Instant::now();
    for _ in 0..ITERS {
        let _ = aether_core::net::onion::process_layer(&secrets[0], &wrapped).unwrap();
    }
    let elapsed = start.elapsed();

    let bytes = (wrapped.len() as f64) * f64::from(ITERS);
    let mbps = (bytes / elapsed.as_secs_f64()) / (1024.0 * 1024.0);

    println!("\n--- 中継1ホップの処理速度 (256KB チャンク) ---");
    println!("unwrap x{}: {:?}", ITERS, elapsed);
    println!("スループット: {:.0} MB/s", mbps);
    println!("→ 1Gbps = 125 MB/s なので、{}", if mbps > 125.0 {
        "CPU は律速にならない（回線律速）"
    } else {
        "CPU が律速になりうる"
    });
}
