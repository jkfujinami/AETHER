//! PoW のコスト実測
//!
//! Broadcast Veil では全ノードが全 Hint を受け取るため、
//! **検証コストは N 回、生成コストは 1 回**しか払われない。
//! この非対称性がパラメータ選定を支配する。
//!
//! `cargo test --release --test pow_cost -- --nocapture`

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use std::time::Instant;

fn bench<F: FnMut()>(iters: u32, mut f: F) -> f64 {
    // ウォームアップ
    for _ in 0..(iters / 10).max(1) {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed().as_secs_f64() / f64::from(iters)
}

fn argon2_cost(m_cost_kib: u32, t_cost: u32, iters: u32) -> f64 {
    let params = Params::new(m_cost_kib, t_cost, 1, Some(32)).unwrap();
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let input = [0xABu8; 90];
    let salt = [0xCDu8; 16];
    let mut out = [0u8; 32];

    bench(iters, || {
        hasher.hash_password_into(&input, &salt, &mut out).unwrap();
    })
}

fn sha256_cost(iters: u32) -> f64 {
    let input = [0xABu8; 90];
    bench(iters, || {
        let _: [u8; 32] = Sha256::digest(input).into();
    })
}

/// 生成コスト = 1ハッシュ * 2^difficulty (期待値)
fn gen_secs(hash_secs: f64, difficulty: u32) -> f64 {
    hash_secs * 2f64.powi(difficulty as i32)
}

/// 計測なので既定では走らせない（debug ビルドの数値は26倍ずれて無意味）。
/// `cargo test --release --test pow_cost -- --ignored --nocapture`
#[test]
#[ignore = "計測用。--release で明示実行すること"]
fn pow_verification_budget() {
    let sha = sha256_cost(200_000);
    let argon_1mb = argon2_cost(1024, 1, 200);
    let argon_64mb = argon2_cost(64 * 1024, 3, 10);

    println!("\n=== 1ハッシュあたりのコスト（= 検証1回のコスト）===");
    println!("SHA-256              : {:>10.3} us", sha * 1e6);
    println!("Argon2id  1MB / t=1  : {:>10.3} us  ({:.0}x SHA256)", argon_1mb * 1e6, argon_1mb / sha);
    println!("Argon2id 64MB / t=3  : {:>10.3} us  ({:.0}x SHA256)", argon_64mb * 1e6, argon_64mb / sha);

    // Broadcast Veil では受信レート = ネットワーク全体の Hint 生成レート
    println!("\n=== 検証負荷: 受信 Hint レート別の CPU 使用率（1コア比）===");
    println!("{:>16} | {:>10} | {:>12} | {:>12}", "Hint/日", "Hint/秒", "SHA-256", "Argon2 1MB");
    for per_day in [1_000_000f64, 10_000_000.0, 100_000_000.0] {
        let per_sec = per_day / 86_400.0;
        println!(
            "{:>16} | {:>10.1} | {:>11.4}% | {:>11.2}%",
            per_day as u64,
            per_sec,
            per_sec * sha * 100.0,
            per_sec * argon_1mb * 100.0
        );
    }

    println!("\n=== 生成コスト: 難易度別（投稿1件あたり）===");
    println!("{:>10} | {:>14} | {:>14}", "difficulty", "SHA-256", "Argon2 1MB");
    for d in [11u32, 16, 20, 22, 24] {
        println!(
            "{:>10} | {:>13.2}s | {:>13.1}s",
            d,
            gen_secs(sha, d),
            gen_secs(argon_1mb, d)
        );
    }

    // 攻撃者が全ノードの1コアを飽和させるのに必要な並列度
    //   攻撃者の生成レート = M / (2^D * C)   [Hint/秒]
    //   各ノードの検証負荷 = 生成レート * C = M / 2^D
    //   飽和条件: M / 2^D >= 1  →  M >= 2^D
    println!("\n=== 全ノードを飽和させるのに必要な攻撃者のコア数 = 2^difficulty ===");
    println!("(ハッシュ関数の種類によらない。難易度だけで決まる)");
    for d in [11u32, 16, 20, 22, 24] {
        println!("  difficulty {:>2} : {:>15} コア", d, 2u64.pow(d));
    }

    println!("\n=== 結論 ===");
    let d = 22;
    println!(
        "SHA-256 難易度{}: 生成 {:.2}秒 / 検証 {:.3}us / 飽和に {} コア必要",
        d,
        gen_secs(sha, d),
        sha * 1e6,
        2u64.pow(d)
    );
    println!(
        "Argon2 1MB 難易度11: 生成 {:.2}秒 / 検証 {:.1}us / 飽和に {} コアで足りる",
        gen_secs(argon_1mb, 11),
        argon_1mb * 1e6,
        2u64.pow(11)
    );

    // メモリハード関数は「生成側の専用ハード優位」を潰す代わりに
    // 検証コストを N 倍で払わされる。ブロードキャスト網では割に合わない。
    assert!(
        argon_1mb > sha * 100.0,
        "Argon2 の検証コストが SHA-256 と同等なら、この分析の前提が崩れる"
    );
}
