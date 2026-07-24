/**
 * AETHER Web-Lite: 超大規模シミュレーション（100万〜1億人）
 *
 * Probabilistic Cache Seeding (p=20%) で
 * 100万人、1000万人、1億人の現実を直視する
 */

const DEGREE = 6;
const CACHE_P = 0.20;
const TRIALS = 100000;

console.log("╔═══════════════════════════════════════════════════════════════════╗");
console.log("║   超大規模シミュレーション: 100万 / 1000万 / 1億 ノード          ║");
console.log("╚═══════════════════════════════════════════════════════════════════╝\n");

// ============================================================
// ヒット率（ノード数に依存しない。p と degree だけで決まる）
// ============================================================
console.log("═══ ヒット率（p=20%, degree=6）: ノード数に依存しない ═══\n");

let hit1 = 0, hit2 = 0, miss = 0;
for (let t = 0; t < TRIALS; t++) {
    let found = false;
    for (let i = 0; i < DEGREE; i++) {
        if (Math.random() < CACHE_P) { hit1++; found = true; break; }
    }
    if (found) continue;
    const hop2 = DEGREE * (DEGREE - 1);
    for (let i = 0; i < hop2; i++) {
        if (Math.random() < CACHE_P) { hit2++; found = true; break; }
    }
    if (found) continue;
    miss++;
}

console.log(`  1hop ヒット率: ${(hit1/TRIALS*100).toFixed(2)}%`);
console.log(`  2hop ヒット率: ${((hit1+hit2)/TRIALS*100).toFixed(2)}%`);
console.log(`  失敗率:        ${(miss/TRIALS*100).toFixed(4)}%`);
console.log(`  → ✅ 何億人いても同じ。ヒット率はネットワーク規模に依存しない。\n`);

// ============================================================
// 各規模でのトラフィック推定
// ============================================================
console.log("═══ 各規模でのトラフィック推定 ═══\n");

// ROM率を考慮した現実的な投稿頻度
// 2ch: 10万人同接で ~100件/秒 → ROM率 99.9%
// Twitter: DAU 5億で ~6000 tweets/sec → ROM率 99.9998%
// 掲示板はTwitterより投稿率が高い（スレが活発）

const scales = [
    { nodes: 10000,     label: "1万人",     postsPerSec: 50,    postSize: 500 },
    { nodes: 100000,    label: "10万人",    postsPerSec: 200,   postSize: 500 },
    { nodes: 1000000,   label: "100万人",   postsPerSec: 1000,  postSize: 500 },
    { nodes: 10000000,  label: "1000万人",  postsPerSec: 5000,  postSize: 500 },
    { nodes: 100000000, label: "1億人",     postsPerSec: 20000, postSize: 500 },
];

console.log("前提: ROM率 99.9%（2ch全盛期と同等）, 1レス=500B, p=20%キャッシュ\n");

console.log("┌────────────┬─────────┬──────────────┬──────────────┬──────────────┬──────────┐");
console.log("│ 規模       │ 件/秒   │ Full Bcast   │ Cache(p=20%) │ 月間(8h/日)  │ 判定     │");
console.log("├────────────┼─────────┼──────────────┼──────────────┼──────────────┼──────────┤");

for (const s of scales) {
    const fullBW = s.postsPerSec * s.postSize;
    // Cache方式: notification(50B) + content*p(cached fraction)
    const cacheBW = s.postsPerSec * 50 + s.postsPerSec * s.postSize * CACHE_P;
    // + pull for subscribed content (assume 5% of posts are relevant)
    const pullBW = s.postsPerSec * 0.05 * s.postSize;
    const totalCacheBW = cacheBW + pullBW;

    const fullKB = (fullBW / 1024).toFixed(0);
    const cacheKB = (totalCacheBW / 1024).toFixed(0);
    const fullMB = (fullBW / (1024*1024)).toFixed(2);
    const cacheMB = (totalCacheBW / (1024*1024)).toFixed(2);

    // Monthly (8h/day, 30 days)
    const monthlyGB_full = (fullBW * 3600 * 8 * 30 / (1024**3)).toFixed(1);
    const monthlyGB_cache = (totalCacheBW * 3600 * 8 * 30 / (1024**3)).toFixed(1);

    let status;
    if (totalCacheBW < 100 * 1024) status = "✅ 余裕";
    else if (totalCacheBW < 625 * 1024) status = "⚠️ 1080p以下";
    else if (totalCacheBW < 2 * 1024 * 1024) status = "❌ 厳しい";
    else status = "💀 破綻";

    const useUnit = totalCacheBW > 1024 * 1024;
    const cacheDisp = useUnit ? `${cacheMB} MB/s` : `${cacheKB} KB/s`;
    const fullDisp = useUnit ? `${fullMB} MB/s` : `${fullKB} KB/s`;

    console.log(`│ ${s.label.padEnd(8)}   │ ${String(s.postsPerSec).padStart(6)}  │ ${fullDisp.padStart(10)}   │ ${cacheDisp.padStart(10)}   │ ${(monthlyGB_cache+" GB").padStart(10)}   │ ${status}   │`);
}
console.log("└────────────┴─────────┴──────────────┴──────────────┴──────────────┴──────────┘");

// ============================================================
// Pull負荷の分散（超大規模）
// ============================================================
console.log("\n═══ Pull負荷の分散（超祭りスレ想定, p=20%） ═══\n");

const pullScales = [
    { nodes: 1000000,   subs: 100000,  label: "100万人中10万人が閲覧" },
    { nodes: 10000000,  subs: 1000000, label: "1000万人中100万人が閲覧" },
    { nodes: 100000000, subs: 5000000, label: "1億人中500万人が閲覧" },
];

console.log("┌──────────────────────────────┬────────────────┬────────────────┬─────────┐");
console.log("│ シナリオ                     │ DHT(K=5)       │ Cache(p=20%)   │ 判定    │");
console.log("├──────────────────────────────┼────────────────┼────────────────┼─────────┤");

for (const s of pullScales) {
    const cacheNodes = Math.round(s.nodes * CACHE_P);
    const dhtPerNode = (s.subs / 5).toFixed(0);
    const cachePerNode = (s.subs / cacheNodes).toFixed(2);

    console.log(`│ ${s.label.padEnd(28)} │ ${(dhtPerNode+" 回/node").padStart(14)} │ ${(cachePerNode+" 回/node").padStart(14)} │ ✅      │`);
}
console.log("└──────────────────────────────┴────────────────┴────────────────┴─────────┘");

// ============================================================
// 限界点の分析
// ============================================================
console.log(`
═══ ブレークポイント分析 ═══

帯域上限を「1080p動画配信相当 = 625KB/s」としたとき:

  Cache方式の帯域 = posts/sec × (50 + 500 × 0.2) + posts/sec × 0.05 × 500
                  = posts/sec × (50 + 100 + 25)
                  = posts/sec × 175 B

  625KB/s = 640,000 B/s
  640,000 / 175 = 3,657 件/秒

  → 全板合計 秒間3,657件までは1080p以下で収まる

  2chの全盛期のピーク:
    秒間 ~100件（10万人同接）

  AETHERが3,657件/秒を超えるのは:
    ROM率99.9%として → 同時接続 ~3,657,000人（365万人）

  つまり:
    ┌────────────────────────────────────────────────────┐
    │ 同接365万人まで、1080pの帯域で全パケットを処理可能  │
    │                                                    │
    │ 2chの全盛期（10万人）の36倍の規模まで耐えられる     │
    └────────────────────────────────────────────────────┘

    1000万人以上: 帯域設定を「標準モード」に下げれば対応可能
    1億人:       Broadcast Veil 自体の限界。Rust版に移行するべき

═══ 結論 ═══

  ┌──────────────┬────────────────────────────────────────┐
  │ 規模         │ 判定                                   │
  ├──────────────┼────────────────────────────────────────┤
  │ ~10万人      │ ✅ 余裕。Full Broadcastでも問題なし    │
  │ ~100万人     │ ✅ Cache方式で快適                     │
  │ ~365万人     │ ⚠️ 1080p帯域ギリギリ（限界点）        │
  │ ~1000万人    │ ⚠️ 帯域設定を下げれば動く             │
  │ ~1億人       │ ❌ ブラウザP2Pの構造的限界             │
  │              │    → Rust版 AETHER Core に移行         │
  └──────────────┴────────────────────────────────────────┘
`);
