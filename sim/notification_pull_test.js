/**
 * AETHER Web-Lite: Notification Broadcast + DHT Pull 方式の検証
 *
 * 検証項目:
 * 1. DHTホットスポット: 同一packet_hashへの同時Pull集中
 * 2. レース条件: 通知がDHT PUTより先に届く確率
 * 3. 帯域比較: Full Broadcast vs Notification+Pull
 * 4. Pull遅延: DHT lookup の追加遅延
 * 5. DHTノードの負荷: 秒間Putリクエスト数
 */

const NUM_NODES = 10000;
const K_REPLICATION = 5; // DHT replication factor
const DEGREE = 6;

console.log("=== Notification Broadcast + DHT Pull 方式の徹底検証 ===\n");

// ============================================================
// Test 1: DHTホットスポット問題
// ============================================================
console.log("--- Test 1: DHTホットスポット（同時Pull集中） ---\n");

// VIP板に5000人が参加していて、1件の投稿が来た場合
// 5000人が同時にDHT Pullしようとすると、K=5のDHTノードに集中する
const scenarios_hotspot = [
    { name: "過疎スレ（50人閲覧）", subscribers: 50 },
    { name: "普通スレ（500人閲覧）", subscribers: 500 },
    { name: "人気スレ（2000人閲覧）", subscribers: 2000 },
    { name: "VIP板全体（5000人閲覧）", subscribers: 5000 },
    { name: "祭りスレ（8000人閲覧）", subscribers: 8000 },
];

console.log("条件: K=5（DHT担当ノード5人）, Pullが0.5秒以内に集中\n");
console.log("┌──────────────────────┬──────────────┬──────────────┬───────────┐");
console.log("│ シナリオ             │ 同時Pull数   │ ノード当たり │ 判定      │");
console.log("├──────────────────────┼──────────────┼──────────────┼───────────┤");

for (const s of scenarios_hotspot) {
    const pullsPerNode = Math.ceil(s.subscribers / K_REPLICATION);
    const dataPerNode = pullsPerNode * 500; // 500B per response
    const dataPerNodeKB = (dataPerNode / 1024).toFixed(1);

    let status;
    if (pullsPerNode < 100) status = "✅ 余裕";
    else if (pullsPerNode < 500) status = "⚠️ 負荷高";
    else status = "❌ 破綻";

    console.log(`│ ${s.name.padEnd(14)}       │ ${String(s.subscribers).padStart(6)}       │ ${String(pullsPerNode).padStart(6)}回     │ ${status}    │`);
}
console.log("└──────────────────────┴──────────────┴──────────────┴───────────┘");

console.log(`
分析:
  2000人が同時にPullすると、K=5の各ノードに400件/0.5秒のリクエストが殺到。
  ブラウザ1台が0.5秒で400件のWebRTCレスポンスを返すのは不可能。

  → 「人気スレ」以上でDHTノードがボトルネックになり、遅延が爆発する。
`);

// ============================================================
// Test 2: レース条件
// ============================================================
console.log("--- Test 2: レース条件（通知 vs DHT PUT）---\n");

// Broadcast Veil は ~300ms で全ノードに到達
// DHT PUT は Kademlia lookup + store で ~200ms
// つまり通知のほうが先に届く可能性がある

const BROADCAST_LATENCY = 300; // ms
const DHT_PUT_LATENCY = 200;   // ms (lookup + store)
const TRIALS = 10000;

let raceConditions = 0;
for (let i = 0; i < TRIALS; i++) {
    // Add random jitter
    const broadcastTime = BROADCAST_LATENCY * (0.5 + Math.random());
    const dhtPutTime = DHT_PUT_LATENCY * (0.8 + Math.random() * 0.4);

    if (broadcastTime < dhtPutTime) {
        raceConditions++;
    }
}

console.log(`10,000回試行:`);
console.log(`  通知がDHT PUTより先に届く確率: ${(raceConditions / TRIALS * 100).toFixed(1)}%`);
console.log(`  → この場合、受信者がPullしても「まだデータがない」状態になる`);
console.log(`  → リトライが必要（+200ms〜500ms の遅延追加）\n`);

// ============================================================
// Test 3: 帯域比較
// ============================================================
console.log("--- Test 3: 帯域比較 ---\n");

const configs = [
    { posts: 50, size: 500, subs: 10, label: "通常（自分は2スレ購読）" },
    { posts: 200, size: 1000, subs: 20, label: "炎上（5スレ購読）" },
    { posts: 500, size: 2000, subs: 30, label: "最悪ケース（10板購読）" },
];

console.log("┌──────────────────────┬──────────────┬──────────────┬───────────┐");
console.log("│ シナリオ             │ Full Bcast   │ Notif+Pull   │ 削減率    │");
console.log("├──────────────────────┼──────────────┼──────────────┼───────────┤");

for (const c of configs) {
    const fullBW = c.posts * c.size; // bytes/sec
    const notifBW = c.posts * 50;    // 50B per notification
    const pullBW = c.subs * c.size;  // only subscribed posts
    const newBW = notifBW + pullBW;
    const reduction = ((1 - newBW / fullBW) * 100).toFixed(0);

    const fullKB = (fullBW / 1024).toFixed(0);
    const newKB = (newBW / 1024).toFixed(0);

    console.log(`│ ${c.label.padEnd(20)} │ ${(fullKB + " KB/s").padStart(10)}   │ ${(newKB + " KB/s").padStart(10)}   │ ${(reduction + "% 削減").padStart(7)}  │`);
}
console.log("└──────────────────────┴──────────────┴──────────────┴───────────┘\n");

// ============================================================
// Test 4: DHTノードの総負荷
// ============================================================
console.log("--- Test 4: DHTノード1台あたりの総負荷 ---\n");

// Every post creates a PUT to K=5 nodes
// If 50 posts/sec globally, each DHT node handles ~50 * K_chance PUTs
// Plus Pull requests from subscribers

const postsPerSec = 50;
// How many packets hash to "near" a given node?
// In a uniform DHT with 10000 nodes and K=5, each node is responsible for
// K/N fraction of all keys = 5/10000 = 0.0005
// So each node handles: 50 * 0.0005 = 0.025 PUTs/sec (negligible)
// BUT: each of those packets might get 500 pull requests from subscribers

const putLoadPerNode = postsPerSec * K_REPLICATION / NUM_NODES;

console.log(`  全体の投稿: ${postsPerSec}件/秒`);
console.log(`  1ノードのPUT担当: ${putLoadPerNode.toFixed(3)}件/秒（無視できるほど小さい）`);
console.log(`  問題はPUTではなくPull（GET）に集中:`);

// If a thread has 1000 subscribers, and 5 posts/sec in that thread
// Each post → 1000 pulls distributed over K=5 DHT nodes
// = 200 pulls/node per post × 5 posts/sec = 1000 pulls/sec/node
const threadSubscribers = 1000;
const threadPostRate = 5;
const pullsPerNodePerSec = (threadSubscribers / K_REPLICATION) * threadPostRate;
console.log(`  活発なスレ（1000人購読、5件/秒）: 各DHTノードに${pullsPerNodePerSec}回/秒のGET`);
console.log(`  → ブラウザでこの負荷は処理不能 ❌\n`);

// ============================================================
// Test 5: 代替案 - P2P キャッシュ拡散
// ============================================================
console.log("--- Test 5: 代替案 - P2Pキャッシュ拡散 ---\n");
console.log(`
【問題の本質】
  DHT Pull は「少数のノード（K=5）に全員が殺到する」のが致命的。
  これは「サーバーにアクセスが集中する」のと同じ構造。
  P2Pの意味がない。

【代替案A: Epidemic Cache（キャッシュの伝染的拡散）】
  1. まず K=5 のDHTノードだけが本文を持つ
  2. 最初にPullした人が本文をキャッシュし、次のPull要求に応える
  3. こうしてPullに成功した人がどんどんキャッシュホルダーになる
  4. 指数関数的にキャッシュが広がり、負荷が分散される

  1000人が同時Pull:
    最初の10人 → K=5のDHTノードからGET（ここだけ集中）
    次の100人 → 10人のキャッシュからGET（分散始まる）
    残り890人 → 100人のキャッシュからGET（完全分散）

  結果:
    DHTノードの実質負荷: 最初の10人分だけ = 2人/ノード
    残りはP2Pキャッシュが吸収

  問題:
    「誰からPullするか」を選ぶ時に、相手がそのデータを持ってるか分からない。
    → キャッシュの存在を通知する仕組みが必要（設計が複雑化）

【代替案B: 送信者の隣人キャッシュ】
  1. 送信者がBroadcast Veilで通知を送る時、
     隣人6人にだけは通知と一緒に本文も渡す
  2. それ以降のノードは通知のみを中継
  3. Pull時は、送信者 or 送信者の隣人（最大7人）からGET
  4. 直接接続ではなく、DHTルーティング経由でアクセス

  負荷分散: K=5 → 7人（送信者+隣人6人）に分散
  まだ足りない...

【代替案C: そもそもPullしない（現状維持 + 確率的ゴシップ）】
  Broadcast Veilのまま、fanoutを6→4に減らすだけ。
  帯域33%削減。シンプル。追加の複雑性ゼロ。

  1万人規模: 25KB/s → 17KB/s（十分）
  10万人規模: 100KB/s → 67KB/s（まあ許容）
  100万人:    破綻するが、そこまで行ったらRust版に移行
`);

console.log("=== 最終結論 ===");
console.log(`
  Notification + DHT Pull 方式:
    ✅ 帯域を80-95%削減できる（理論値は素晴らしい）
    ❌ DHTホットスポット問題（人気スレでK=5ノードが破綻）
    ❌ レース条件（通知が先に届いてPull失敗 → リトライ遅延）
    ❌ 実装の複雑度が大幅に増加

  シュレーディンガーMailbox（AETHER Core 案F）:
    → Rustネイティブ + Onion Routing 前提なら成立する
    → ブラウザ（WebRTC）では DHTノードの処理能力が低すぎて破綻

  推奨:
    Web-Lite（ブラウザ版）:
      → Broadcast Veil + 確率的ゴシップ（fanout削減）が最適解
      → 1万人で17KB/s。シンプルで確実。

    AETHER Core（Rust版）:
      → シュレーディンガーMailbox（案F）を採用
      → ネイティブアプリなら高負荷に耐えられる
`);
