//! スケール限界の算出
//!
//! Broadcast Veil は「全 Hint が全ノードに届く」設計なので、
//! 帯域・CPU・重複排除キャッシュのどれが最初に律速するかを明示する。
//!
//! `cargo test --release --test scaling_limits -- --nocapture`

use aether_core::net::seen_cache::{SeenCache, DEFAULT_CAPACITY, DEFAULT_TTL_SECS};
use aether_core::protocol::hint::{HintPacket, MAX_TIME_DRIFT_SECS};

/// ワイヤ上の Hint サイズ + フレーミング (u32 len + u8 type)
const HINT_WIRE_BYTES: f64 = 90.0 + 5.0;

/// UDP/IP/QUIC ヘッダの実測見積もり
const PACKET_OVERHEAD_BYTES: f64 = 48.0;

/// 1 Hint あたりの実効送出バイト数
const BYTES_PER_HINT: f64 = HINT_WIRE_BYTES + PACKET_OVERHEAD_BYTES;

/// NodeServer::GOSSIP_FANOUT と揃えること
const FANOUT: f64 = 3.0;

fn hints_per_day_from_bandwidth(mbps: f64) -> f64 {
    let bytes_per_sec = mbps * 1_000_000.0 / 8.0;
    let hints_per_sec = bytes_per_sec / (BYTES_PER_HINT * FANOUT);
    hints_per_sec * 86_400.0
}

#[test]
fn broadcast_veil_ceiling() {
    println!("\n=== 1 Hint あたりの送出コスト ===");
    println!("Hint 本体 + フレーミング : {:.0} B", HINT_WIRE_BYTES);
    println!("パケットヘッダ           : {:.0} B", PACKET_OVERHEAD_BYTES);
    println!("fanout {}                : x{:.0}", FANOUT, FANOUT);
    println!("→ 1 Hint = {:.0} B の送出", BYTES_PER_HINT * FANOUT);

    println!("\n=== 帯域から決まる上限（1ノードのゴシップ用上り帯域）===");
    println!("{:>10} | {:>16} | {:>14}", "帯域", "Hint/日", "Hint/秒");
    for mbps in [0.5f64, 1.0, 5.0, 10.0] {
        let per_day = hints_per_day_from_bandwidth(mbps);
        println!(
            "{:>8.1}Mbps | {:>16} | {:>14.0}",
            mbps,
            per_day as u64,
            per_day / 86_400.0
        );
    }

    println!("\n=== ユーザー数への換算 ===");
    println!("(1ユーザーあたりの投稿数で割る)");
    println!("{:>10} | {:>18} | {:>18}", "帯域", "10投稿/人/日", "100投稿/人/日");
    for mbps in [1.0f64, 10.0] {
        let per_day = hints_per_day_from_bandwidth(mbps);
        println!(
            "{:>8.1}Mbps | {:>18} | {:>18}",
            mbps,
            format!("{:.1}M 人", per_day / 10.0 / 1e6),
            format!("{:.1}M 人", per_day / 100.0 / 1e6)
        );
    }
}

#[test]
fn seen_cache_no_longer_caps_the_network() {
    // 旧実装 (HashMap + 件数上限 50,000) は、レートが容量を食い潰すと
    // TTL 前にエントリを排出し、重複排除窓が黙って縮んでいた。
    const OLD_MAX_SIZE: f64 = 50_000.0;
    let old_crossover = OLD_MAX_SIZE / DEFAULT_TTL_SECS as f64;

    println!("\n=== 旧実装 (HashMap + LRU 50,000件) の実効重複排除窓 ===");
    println!(
        "容量を使い切るレート: {:.1} Hint/秒 = {:.2}M Hint/日",
        old_crossover,
        old_crossover * 86_400.0 / 1e6
    );
    println!("\n{:>10} | {:>12} | {:>14}", "Hint/秒", "実効窓", "時刻検査との差");
    for per_sec in [10.0f64, 55.6, 100.0, 291.0, 1000.0] {
        let window = (OLD_MAX_SIZE / per_sec).min(DEFAULT_TTL_SECS as f64);
        let gap = MAX_TIME_DRIFT_SECS as f64 - window;
        println!(
            "{:>10.1} | {:>9.1} 秒 | {:>14}",
            per_sec,
            window,
            if gap > 0.0 { format!("{:.0}秒の穴", gap) } else { "穴なし".into() }
        );
    }
    println!("\n→ 穴の時間帯は「重複排除からは消えたが時刻検査は通る」状態。");
    println!("  攻撃者は PoW を再計算せずに古い Hint を再投入して再フラッドできた。");

    // 現行実装: 世代交代式 Bloom フィルタ
    let cache = SeenCache::default();
    println!("\n=== 現行実装 (世代交代式 Bloom) ===");
    println!(
        "想定容量 {} 件 / 生存期間 {}〜{} 秒 / メモリ {:.2} MB",
        DEFAULT_CAPACITY,
        DEFAULT_TTL_SECS,
        DEFAULT_TTL_SECS * 2,
        cache.memory_bytes() as f64 / 1_048_576.0
    );
    println!(
        "想定容量を使い切るレート: {:.0} Hint/秒 = {:.1}M Hint/日",
        DEFAULT_CAPACITY as f64 / DEFAULT_TTL_SECS as f64,
        DEFAULT_CAPACITY as f64 / DEFAULT_TTL_SECS as f64 * 86_400.0 / 1e6
    );

    // 容量を超過しても「忘れる」ことはない
    let mut cache = SeenCache::new(1_000, DEFAULT_TTL_SECS);
    let first = [0xA5u8; 32];
    cache.insert(first);
    for n in 0..50_000u32 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&n.to_be_bytes());
        id[31] = 0x5A;
        cache.insert(id);
    }
    assert!(
        cache.contains(&first),
        "Bloom は誤検知が「既知」側にしか倒れないため、容量超過でも忘れない"
    );

    println!("\n✓ 容量を50倍超過しても忘れない（リプレイ窓は構造的に開かない）");
    println!("  超過時に劣化するのは誤検知率＝配送の取りこぼしであって、安全性ではない。");
}

#[test]
fn relay_list_ceiling() {
    // 18.5.2 で DHT クエリを廃した代わりに、
    // 各ノードがリレーリスト全体をローカル保持する必要がある（Tor の consensus と同型）
    const ENTRY_BYTES: f64 = 32.0 + 18.0 + 8.0 + 8.0; // NodeId + Addr + position + epoch/PoW

    println!("\n=== リレーリストのローカル保持コスト ===");
    println!("1エントリ {:.0} B (NodeId + Addr + position + epoch)", ENTRY_BYTES);
    println!("{:>14} | {:>12} | {:>22}", "リレー数", "リスト", "日次更新(churn 10%)");
    for relays in [10_000f64, 100_000.0, 1_000_000.0, 10_000_000.0] {
        let list_mb = relays * ENTRY_BYTES / 1e6;
        let churn_mb = relays * 0.1 * ENTRY_BYTES / 1e6;
        println!(
            "{:>14} | {:>9.1} MB | {:>19.1} MB",
            relays as u64, list_mb, churn_mb
        );
    }

    println!("\n参考: Tor は約6,000〜8,000リレー / consensus 約2MB。");
    println!("      同じ構造なので同じ壁に当たる。");
    println!("      全ユーザーがリレーである必要はない（10%なら リレー100万 = ユーザー1000万）。");
}

#[test]
fn hint_packet_size_is_the_scaling_lever() {
    // Hint の1バイトは全ノード数倍で効く。
    // auth_tag 削除(-16B)がどれだけ効いたかを可視化する。
    let payload_len = 48 + 16; // HintPayload + Poly1305 tag
    let current = bincode::serialize(&HintPacket::new(
        [0; 4],
        [0; 12],
        vec![0u8; payload_len],
        5,
    ))
    .unwrap()
    .len();
    let before = current + 16; // auth_tag ダミーがあった頃

    println!("\n=== Hint サイズがスケール上限に与える影響 ===");
    println!("auth_tag 削除前: {} B", before);
    println!("現在           : {} B  ({:.0}% 削減)", current,
        (1.0 - current as f64 / before as f64) * 100.0);

    let ceiling = |hint_bytes: f64| {
        let bytes_per_sec = 1_000_000.0 / 8.0; // 1 Mbps
        bytes_per_sec / ((hint_bytes + PACKET_OVERHEAD_BYTES + 5.0) * FANOUT) * 86_400.0
    };

    println!(
        "\n1Mbps 予算での上限: {:.2}M → {:.2}M Hint/日 ({:+.1}%)",
        ceiling(before as f64 - 5.0) / 1e6,
        ceiling(current as f64 - 5.0) / 1e6,
        (ceiling(current as f64 - 5.0) / ceiling(before as f64 - 5.0) - 1.0) * 100.0
    );
    println!("\n→ パケットヘッダが支配的なので、Hint 本体を削る効果は頭打ち。");
    println!("  複数 Hint をまとめて1パケットで送る方が効く。");
}
