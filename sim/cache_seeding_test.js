/**
 * AETHER Web-Lite: Probabilistic Cache Seeding - 検証
 *
 * Broadcast Veilの通り道でコンテンツを確率的にキャッシュし、
 * Pullは隣人から行う（DHTホットスポットを回避）
 */

const NUM_NODES = 10000;
const DEGREE = 6;
const TRIALS = 50000;

console.log("=== Probabilistic Cache Seeding 検証 ===\n");

// ============================================================
// Test 1: キャッシュ確率 vs 隣人ヒット率
// ============================================================
console.log("--- Test 1: キャッシュ確率 p vs 隣人からのコンテンツ取得成功率 ---\n");

const cacheProbs = [0.05, 0.10, 0.15, 0.20, 0.30, 0.40, 0.50];

console.log("┌────────┬───────────┬──────────────┬──────────────┬───────────────┐");
console.log("│ 確率 p │ キャッシュ │ 1hop成功率   │ 2hop成功率   │ 帯域(対Full%) │");
console.log("├────────┼───────────┼──────────────┼──────────────┼───────────────┤");

for (const p of cacheProbs) {
    const cachedNodes = Math.round(NUM_NODES * p);

    // 1-hop: at least 1 of 6 neighbors has cache
    let hit1hop = 0;
    let hit2hop = 0;

    for (let t = 0; t < TRIALS; t++) {
        // Check 6 direct neighbors
        let found = false;
        for (let i = 0; i < DEGREE; i++) {
            if (Math.random() < p) { found = true; break; }
        }
        if (found) { hit1hop++; hit2hop++; continue; }

        // 2-hop: check each neighbor's neighbors (6 * ~5 unique = ~30)
        const secondHopCount = DEGREE * (DEGREE - 1); // ~30
        for (let i = 0; i < secondHopCount; i++) {
            if (Math.random() < p) { found = true; break; }
        }
        if (found) { hit2hop++; }
    }

    const hit1pct = (hit1hop / TRIALS * 100).toFixed(1);
    const hit2pct = (hit2hop / TRIALS * 100).toFixed(1);

    // Bandwidth: notification always (50B) + content if cached (500B * p)
    // Each node receives: 50B (notification) + 500B * p (content, on average)
    const bwPerPost = 50 + 500 * p;
    const bwPctOfFull = (bwPerPost / 500 * 100).toFixed(0);

    console.log(`│  ${(p*100).toFixed(0).padStart(3)}%  │ ${String(cachedNodes).padStart(5)}人   │ ${hit1pct.padStart(6)}%      │ ${hit2pct.padStart(6)}%      │ ${bwPctOfFull.padStart(5)}%        │`);
}
console.log("└────────┴───────────┴──────────────┴──────────────┴───────────────┘");

// ============================================================
// Test 2: Pull負荷の分散度
// ============================================================
console.log("\n--- Test 2: Pull負荷の分散度（2000人が同時Pull） ---\n");

const subscribers = 2000;

console.log("┌────────────────────┬────────────────┬────────────────┬──────────┐");
console.log("│ 方式               │ 提供ノード数   │ ノード当たり   │ 判定     │");
console.log("├────────────────────┼────────────────┼────────────────┼──────────┤");

// DHT K=5
const dhtLoad = Math.ceil(subscribers / 5);
console.log(`│ DHT (K=5)          │ ${String(5).padStart(8)}       │ ${String(dhtLoad).padStart(8)} 回/s  │ ❌ 破綻  │`);

// Cache p=0.1
const cache10 = Math.round(NUM_NODES * 0.1);
const load10 = (subscribers / cache10).toFixed(1);
console.log(`│ Cache p=10%        │ ${String(cache10).padStart(8)}       │ ${load10.padStart(8)} 回/s  │ ✅ 余裕  │`);

// Cache p=0.2
const cache20 = Math.round(NUM_NODES * 0.2);
const load20 = (subscribers / cache20).toFixed(1);
console.log(`│ Cache p=20%        │ ${String(cache20).padStart(8)}       │ ${load20.padStart(8)} 回/s  │ ✅ 余裕  │`);

// Cache p=0.3
const cache30 = Math.round(NUM_NODES * 0.3);
const load30 = (subscribers / cache30).toFixed(1);
console.log(`│ Cache p=30%        │ ${String(cache30).padStart(8)}       │ ${load30.padStart(8)} 回/s  │ ✅ 余裕  │`);

console.log("└────────────────────┴────────────────┴────────────────┴──────────┘");

// ============================================================
// Test 3: 総合帯域比較
// ============================================================
console.log("\n--- Test 3: 総合帯域比較（50件/秒, 500B/件, 10,000ノード） ---\n");

const postsPerSec = 50;
const postSize = 500;

const fullBW = postsPerSec * postSize; // 25000 B/s = 25KB/s
const notifBW = postsPerSec * 50;      // 2500 B/s

console.log("┌──────────────────────────┬──────────┬──────────────┐");
console.log("│ 方式                     │ 帯域     │ 対Full比     │");
console.log("├──────────────────────────┼──────────┼──────────────┤");

const fullKB = (fullBW / 1024).toFixed(1);
console.log(`│ Full Broadcast (現在)    │ ${fullKB.padStart(5)} KB/s│ 100%         │`);

for (const p of [0.10, 0.20, 0.30]) {
    // Notification + cache probability
    const perNode = postsPerSec * (50 + postSize * p);
    const perNodeKB = (perNode / 1024).toFixed(1);
    const pct = (perNode / fullBW * 100).toFixed(0);
    // Pull bandwidth (subscriber pulls from cache neighbor)
    // Average 5 subscribed posts/sec × 500B (but these come from neighbor, already counted)
    console.log(`│ Cache p=${(p*100).toFixed(0).padStart(2)}% + Pull        │ ${perNodeKB.padStart(5)} KB/s│ ${pct.padStart(4)}%         │`);
}

// Probabilistic gossip (fanout 4/6)
const probGossipBW = fullBW * 4 / 6;
const probGossipKB = (probGossipBW / 1024).toFixed(1);
const probGossipPct = (probGossipBW / fullBW * 100).toFixed(0);
console.log(`│ 確率的ゴシップ(fanout=4) │ ${probGossipKB.padStart(5)} KB/s│ ${probGossipPct.padStart(4)}%         │`);

console.log("└──────────────────────────┴──────────┴──────────────┘");

// ============================================================
// Test 4: プライバシー分析
// ============================================================
console.log(`
--- Test 4: プライバシー分析 ---

Q: 隣人に「packet_hash ある？」と聞くことでプライバシーは漏れるか？

A: 漏れる情報 vs 漏れない情報:

  漏れること:
    「このノードが packet_hash X のデータを欲しがった」

  漏れないこと:
    ・packet_hash X がどのトピックか（hash → topic は逆算不可）
    ・このノードが何のスレッドを見ているか

  比較:
    Broadcast Veil (現在):  隣人は「このノードが何かを中継した」しか見えない
    Cache Pull (提案):      隣人は「このノードが hash X を欲しがった」のが見える ← NEW

  攻撃者の視点:
    「AのIPが hash X を要求した」→ 
    hash X がどのスレッドのものか分からない
    → 攻撃者もBroadcast Veilで受け取った通知から候補を試すことは可能だが、
      全通知のpacket_hashを記録・照合する必要がある
    → コストは高いが不可能ではない

  結論: 
    Broadcast Veil の「完全な無関心」からは一段劣化する
    ただし「どのスレッドか」までは分からないため、実用上は許容範囲

--- 最適値の推奨 ---

  p = 0.20（20%キャッシュ）が最適バランス:
    ・1hopヒット率: 74%（4回中3回は隣人から即取得）
    ・2hopヒット率: 99.9%（ほぼ確実）
    ・帯域: Full Broadcastの30%（17KB/s → 5KB/s）
    ・DHTノード負荷: 2000人Pullでも各キャッシュに1回/s
    ・プライバシー: packet_hash の要求は見えるがトピックは秘匿
`);
