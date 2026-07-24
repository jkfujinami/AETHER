/**
 * AETHER Web-Lite: Dandelion++ Stem Failure & Bandwidth Stress Test
 *
 * Tests:
 * 1. Stem failure rate: What % of messages are lost when stem nodes disconnect?
 * 2. Blackhole attack: Attacker nodes intentionally drop stem packets
 * 3. Bandwidth load: Total bytes per node per second under various traffic levels
 */

const NUM_NODES = 10000;
const DEGREE = 6;
const TRIALS = 10000;

// --- Scenario Parameters ---
const scenarios = {
    stemFailure: {
        name: "Stem切断（自然離脱）",
        desc: "Stemノードがタブ閉じ/回線断で消える確率",
        disconnectRates: [0.01, 0.03, 0.05, 0.10, 0.15, 0.20],
        stemHops: 3,
    },
    blackhole: {
        name: "ブラックホール攻撃",
        desc: "攻撃者がStemパケットを意図的にドロップ",
        attackerRates: [0.05, 0.10, 0.15, 0.20, 0.30, 0.50],
        stemHops: 3,
    },
    bandwidth: {
        name: "帯域負荷テスト",
        desc: "Broadcast Veilの全ノード受信量",
        configs: [
            { postsPerSec: 10,  postSizeB: 500,  label: "過疎（平和）" },
            { postsPerSec: 50,  postSizeB: 500,  label: "通常（VIPピーク）" },
            { postsPerSec: 50,  postSizeB: 2000, label: "長文多め" },
            { postsPerSec: 100, postSizeB: 1000, label: "炎上中" },
            { postsPerSec: 200, postSizeB: 2000, label: "全板炎上（最悪）" },
            { postsPerSec: 200, postSizeB: 5000, label: "巨大AA + 炎上" },
            { postsPerSec: 500, postSizeB: 5000, label: "パケ代テロ想定" },
        ]
    }
};

// ============================================================
// Test 1: Stem Failure (Natural Dropout)
// ============================================================
console.log("=== Test 1: Dandelion++ Stem 切断によるパケットロスト率 ===\n");
console.log("条件: Stem長=3ホップ, 10,000回試行\n");

console.log("┌──────────────────┬──────────────────┬──────────────────┐");
console.log("│ ノード離脱率     │ パケット到達率   │ ロスト率         │");
console.log("├──────────────────┼──────────────────┼──────────────────┤");

for (const rate of scenarios.stemFailure.disconnectRates) {
    let delivered = 0;
    for (let t = 0; t < TRIALS; t++) {
        let lost = false;
        for (let hop = 0; hop < scenarios.stemFailure.stemHops; hop++) {
            if (Math.random() < rate) {
                lost = true;
                break;
            }
        }
        if (!lost) delivered++;
    }
    const deliveryRate = (delivered / TRIALS * 100).toFixed(2);
    const lostRate = (100 - delivered / TRIALS * 100).toFixed(2);
    console.log(`│ ${(rate*100).toFixed(0).padStart(3)}%             │ ${deliveryRate.padStart(7)}%          │ ${lostRate.padStart(7)}%          │`);
}
console.log("└──────────────────┴──────────────────┴──────────────────┘\n");

// ============================================================
// Test 2: Blackhole Attack
// ============================================================
console.log("=== Test 2: ブラックホール攻撃（意図的Stemドロップ） ===\n");
console.log("条件: 攻撃者はStemパケットを100%ドロップ, Stem長=3\n");

console.log("┌──────────────────┬──────────────────┬──────────────────┐");
console.log("│ 攻撃者支配率     │ パケット到達率   │ ロスト率         │");
console.log("├──────────────────┼──────────────────┼──────────────────┤");

for (const rate of scenarios.blackhole.attackerRates) {
    let delivered = 0;
    for (let t = 0; t < TRIALS; t++) {
        let lost = false;
        for (let hop = 0; hop < scenarios.blackhole.stemHops; hop++) {
            if (Math.random() < rate) { // This hop is an attacker → drop
                lost = true;
                break;
            }
        }
        if (!lost) delivered++;
    }
    const deliveryRate = (delivered / TRIALS * 100).toFixed(2);
    const lostRate = (100 - delivered / TRIALS * 100).toFixed(2);
    console.log(`│ ${(rate*100).toFixed(0).padStart(3)}%             │ ${deliveryRate.padStart(7)}%          │ ${lostRate.padStart(7)}%          │`);
}
console.log("└──────────────────┴──────────────────┴──────────────────┘\n");

// ============================================================
// Test 3: Bandwidth Load
// ============================================================
console.log("=== Test 3: Broadcast Veil 帯域負荷（全ノードの受信量） ===\n");
console.log("条件: 10,000ノード, Degree=6, 全パケットが全ノードに到達\n");

console.log("┌──────────────────────┬──────────┬──────────┬──────────────┬──────────────────┐");
console.log("│ シナリオ             │ 件数/秒  │ 1件サイズ│ ノード受信量 │ 月間パケ代(概算) │");
console.log("├──────────────────────┼──────────┼──────────┼──────────────┼──────────────────┤");

for (const cfg of scenarios.bandwidth.configs) {
    const totalBytesPerSec = cfg.postsPerSec * cfg.postSizeB;
    const perNodeBytesPerSec = totalBytesPerSec; // Broadcast = every node gets everything
    const perNodeKBps = (perNodeBytesPerSec / 1024).toFixed(1);
    const perNodeMBps = (perNodeBytesPerSec / (1024 * 1024)).toFixed(2);

    // Monthly data usage (assuming 8 hours/day active)
    const monthlyGB = (perNodeBytesPerSec * 3600 * 8 * 30 / (1024 ** 3)).toFixed(2);

    let status;
    if (perNodeBytesPerSec < 100 * 1024) status = "✅ 余裕";
    else if (perNodeBytesPerSec < 500 * 1024) status = "⚠️ 注意";
    else status = "❌ 危険";

    const label = cfg.label.padEnd(14);
    const pps = `${cfg.postsPerSec}`.padStart(4);
    const size = `${cfg.postSizeB}B`.padStart(6);
    const recv = `${perNodeKBps} KB/s`.padStart(12);
    const monthly = `${monthlyGB} GB/月`.padStart(12);

    console.log(`│ ${label}       │ ${pps}     │ ${size}   │${recv}  │${monthly} ${status}│`);
}

console.log("└──────────────────────┴──────────┴──────────┴──────────────┴──────────────────┘");

// Analysis
console.log(`
=== 分析と対策案 ===

【Stem切断問題】
  ノード離脱率5%（現実的な平常値）で約15%のパケットがロスト。
  → 6〜7回に1回「書き込んだのに反映されない」が発生。UXとして致命的。

  ブラックホール攻撃で攻撃者が20%いると約49%がロスト。
  → 書き込みの半分が消える。

【帯域問題】
  通常運用（50件/秒 × 500B）: 25KB/s → 問題なし
  炎上時（200件/秒 × 2KB）:   400KB/s → Wi-Fiなら耐えるがモバイルには厳しい
  最悪ケース（500件/秒 × 5KB）: 2.4MB/s → 完全に破綻（月120GB超え）

【対策案】
  1. Stem切断対策:
     - タイムアウト付きリトライ: 作者が自分の投稿のエコーを5秒以内に検知できなければ再送
     - 冗長Stem: 2本の平行Stemを送信（匿名性を維持しつつ到達率を向上）

  2. 帯域対策:
     - ペイロードサイズ上限: 2KB/パケット（ハードリミット）
     - ノード別帯域予算: 受信200KB/sを超えたらランダムドロップ
     - PoW難易度をサイズに比例: 大きいパケット = 高い難易度
     - トピック単位のレート制限: 1スレッドあたり秒間X件まで
`);
