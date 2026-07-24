/**
 * AETHER Web-Lite: End-to-End Latency Simulation
 *
 * Simulates the full user journey:
 *   1. Connect to tracker (WebSocket)
 *   2. WebRTC signaling with 6 peers
 *   3. Kademlia DHT lookup to find board's Mailbox
 *   4. Retrieve thread list from Mailbox
 *   5. Retrieve thread data (past posts)
 *   6. Decrypt and display
 *
 * All with realistic per-hop latency modeling.
 */

const crypto = require('crypto');

const NUM_NODES = 10000;
const DEGREE = 6;
const K_BUCKET_SIZE = 20; // Kademlia k parameter

// Realistic latency model (milliseconds)
const LATENCY = {
    TRACKER_CONNECT: 150,       // WebSocket handshake to tracker
    SDP_EXCHANGE: 80,           // Per-peer SDP exchange via tracker
    WEBRTC_HANDSHAKE: 120,      // Per-peer WebRTC DTLS handshake
    HOP_MIN: 20,                // Minimum inter-node latency (same region)
    HOP_MAX: 80,                // Maximum inter-node latency (cross-region)
    HOP_AVG: 40,                // Average inter-node latency
    MAILBOX_READ: 30,           // IndexedDB read on Mailbox node
    DECRYPTION: 2,              // ChaCha20 decryption (negligible)
};

function sha256(data) {
    return crypto.createHash('sha256').update(data).digest();
}

function xorDistance(a, b) {
    const result = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) result[i] = a[i] ^ b[i];
    return result;
}

function distanceLessThan(a, b) {
    for (let i = 0; i < 32; i++) {
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return false;
}

class DHTNode {
    constructor(id, nodeId) {
        this.id = id;
        this.nodeId = nodeId; // 32-byte hash (Kademlia ID)
        this.neighbors = new Set();
        this.routingTable = []; // Known nodes for DHT
        this.storedKeys = new Map(); // topic_hash -> data (if this node is a Mailbox)
    }

    addNeighbor(peer) {
        if (peer.id === this.id || this.neighbors.size >= 12) return;
        this.neighbors.add(peer);
        peer.neighbors.add(this);
        // Add to routing table
        if (this.routingTable.length < K_BUCKET_SIZE * 10) {
            this.routingTable.push(peer);
        }
        if (peer.routingTable.length < K_BUCKET_SIZE * 10) {
            peer.routingTable.push(this);
        }
    }

    // Find K closest nodes to target from routing table
    findClosest(targetHash, k = K_BUCKET_SIZE) {
        return this.routingTable
            .filter(n => n.id !== this.id)
            .sort((a, b) => {
                const distA = xorDistance(a.nodeId, targetHash);
                const distB = xorDistance(b.nodeId, targetHash);
                return distanceLessThan(distA, distB) ? -1 : 1;
            })
            .slice(0, k);
    }
}

// Build mesh
console.log("Building 10,000-node mesh...");
const nodes = [];
for (let i = 0; i < NUM_NODES; i++) {
    const nodeId = sha256(Buffer.from(`node-${i}-${crypto.randomBytes(8).toString('hex')}`));
    nodes.push(new DHTNode(i, nodeId));
}

// Connect mesh (random sparse connections)
nodes.forEach(node => {
    while (node.neighbors.size < DEGREE) {
        const target = nodes[Math.floor(Math.random() * NUM_NODES)];
        node.addNeighbor(target);
    }
});

// Expand routing tables via PEX (each node learns about friends of friends)
nodes.forEach(node => {
    for (const neighbor of node.neighbors) {
        for (const fof of neighbor.neighbors) {
            if (fof.id !== node.id && node.routingTable.length < K_BUCKET_SIZE * 15) {
                if (!node.routingTable.find(n => n.id === fof.id)) {
                    node.routingTable.push(fof);
                }
            }
        }
    }
});

// Setup: Create a board and assign Mailbox nodes via DHT
const BOARDKEY = crypto.randomBytes(32);
const THREAD_ID = '12345';
const threadKey = crypto.createHmac('sha256', BOARDKEY).update(`thread:${THREAD_ID}`).digest();
const topicHash = sha256(threadKey);

// Find K=5 closest nodes to topicHash → they become Mailbox holders
const allByDistance = nodes.slice().sort((a, b) => {
    const distA = xorDistance(a.nodeId, topicHash);
    const distB = xorDistance(b.nodeId, topicHash);
    return distanceLessThan(distA, distB) ? -1 : 1;
});
const mailboxNodes = allByDistance.slice(0, 5);
mailboxNodes.forEach(n => {
    n.storedKeys.set(topicHash.toString('hex'), {
        threads: [
            { title: "キタ━━━(゜∀゜)━━━!!", id: "12345", posts: 150 },
            { title: "VIPでゲーム", id: "12346", posts: 42 },
        ],
        posts: Array.from({ length: 150 }, (_, i) => ({
            id: i, content: `Post #${i}`, ts: Date.now() - (150 - i) * 60000
        }))
    });
});

console.log(`Mailbox nodes assigned: [${mailboxNodes.map(n => n.id).join(', ')}]`);
console.log("Mesh and DHT ready.\n");

// === Simulate new user joining and finding the board ===

function simulateUserJourney(userId) {
    const user = nodes[userId];
    let totalLatencyMs = 0;
    let hops = 0;
    const timeline = [];

    // Phase 1: Connect to Tracker
    totalLatencyMs += LATENCY.TRACKER_CONNECT;
    timeline.push({ phase: "1. Tracker接続 (WebSocket)", ms: LATENCY.TRACKER_CONNECT, total: totalLatencyMs });

    // Phase 2: WebRTC Signaling (SDP exchange for 6 peers via tracker)
    const signalingTime = LATENCY.SDP_EXCHANGE * 2; // Offer + Answer (parallel for all 6)
    const handshakeTime = LATENCY.WEBRTC_HANDSHAKE;  // DTLS (parallel)
    totalLatencyMs += signalingTime + handshakeTime;
    timeline.push({ phase: "2. WebRTCシグナリング (6人分、並列)", ms: signalingTime + handshakeTime, total: totalLatencyMs });

    // Phase 3: Kademlia DHT Lookup (find Mailbox for topicHash)
    // Simulate iterative lookup: ask closest known, get closer, repeat
    let currentNode = user;
    let bestDistance = xorDistance(user.nodeId, topicHash);
    let lookupHops = 0;
    let lookupLatency = 0;
    const visited = new Set([user.id]);

    while (lookupHops < 20) {
        const closest = currentNode.findClosest(topicHash, 3)
            .filter(n => !visited.has(n.id));

        if (closest.length === 0) break;

        const next = closest[0];
        visited.add(next.id);
        const newDist = xorDistance(next.nodeId, topicHash);

        const hopLatency = LATENCY.HOP_MIN + Math.random() * (LATENCY.HOP_MAX - LATENCY.HOP_MIN);
        lookupLatency += hopLatency;
        lookupHops++;

        // Check if we found a Mailbox node
        if (next.storedKeys.has(topicHash.toString('hex'))) {
            currentNode = next;
            break;
        }

        if (distanceLessThan(newDist, bestDistance)) {
            bestDistance = newDist;
            currentNode = next;
        } else {
            break; // No improvement, stop
        }
    }

    totalLatencyMs += lookupLatency;
    hops += lookupHops;
    timeline.push({ phase: `3. DHT探索 (Mailbox発見)`, ms: Math.round(lookupLatency), hops: lookupHops, total: Math.round(totalLatencyMs) });

    // Phase 4: Retrieve thread list from Mailbox
    const readLatency = LATENCY.HOP_AVG + LATENCY.MAILBOX_READ; // 1 hop + DB read
    totalLatencyMs += readLatency;
    timeline.push({ phase: "4. スレッド一覧取得 (Mailbox→ユーザー)", ms: readLatency, total: Math.round(totalLatencyMs) });

    // Phase 5: Retrieve thread posts (past 150 posts)
    const postReadLatency = LATENCY.HOP_AVG + LATENCY.MAILBOX_READ; // Same Mailbox, 1 round trip
    totalLatencyMs += postReadLatency;
    timeline.push({ phase: "5. 過去ログ取得 (150件)", ms: postReadLatency, total: Math.round(totalLatencyMs) });

    // Phase 6: Decrypt and render
    totalLatencyMs += LATENCY.DECRYPTION;
    timeline.push({ phase: "6. 復号＆画面描画", ms: LATENCY.DECRYPTION, total: Math.round(totalLatencyMs) });

    const foundMailbox = currentNode.storedKeys.has(topicHash.toString('hex'));

    return { totalLatencyMs: Math.round(totalLatencyMs), hops, timeline, foundMailbox };
}

// Run multiple trials from random starting nodes
console.log("=== End-to-End Latency Test (10,000 nodes) ===\n");

const TRIALS = 100;
const results = [];

for (let i = 0; i < TRIALS; i++) {
    const startNode = Math.floor(Math.random() * NUM_NODES);
    results.push(simulateUserJourney(startNode));
}

// Show one detailed example
console.log("--- 詳細タイムライン (1回のアクセス例) ---");
const example = results[0];
for (const step of example.timeline) {
    const hopsStr = step.hops !== undefined ? ` [${step.hops} hops]` : '';
    console.log(`  ${step.phase}: +${step.ms}ms${hopsStr} → 累計 ${step.total}ms`);
}

// Statistics
const latencies = results.map(r => r.totalLatencyMs);
const foundAll = results.every(r => r.foundMailbox);
const dhtHops = results.map(r => r.hops);

const avg = Math.round(latencies.reduce((a, b) => a + b, 0) / TRIALS);
const min = Math.min(...latencies);
const max = Math.max(...latencies);
const p50 = latencies.sort((a, b) => a - b)[Math.floor(TRIALS * 0.5)];
const p95 = latencies.sort((a, b) => a - b)[Math.floor(TRIALS * 0.95)];
const p99 = latencies.sort((a, b) => a - b)[Math.floor(TRIALS * 0.99)];
const avgHops = (dhtHops.reduce((a, b) => a + b, 0) / TRIALS).toFixed(1);

console.log(`\n--- ${TRIALS}回試行の統計 ---`);
console.log(`  Mailbox発見率:  ${foundAll ? '100%' : results.filter(r => r.foundMailbox).length + '/' + TRIALS}`);
console.log(`  DHT探索ホップ:  平均 ${avgHops} hops`);
console.log(`  総遅延 (Min):   ${min}ms`);
console.log(`  総遅延 (P50):   ${p50}ms`);
console.log(`  総遅延 (Avg):   ${avg}ms`);
console.log(`  総遅延 (P95):   ${p95}ms`);
console.log(`  総遅延 (P99):   ${p99}ms`);
console.log(`  総遅延 (Max):   ${max}ms`);

console.log(`\n--- 内訳ブレークダウン (平均) ---`);
console.log(`  1. Tracker接続:           ${LATENCY.TRACKER_CONNECT}ms`);
console.log(`  2. WebRTCシグナリング:    ${LATENCY.SDP_EXCHANGE * 2 + LATENCY.WEBRTC_HANDSHAKE}ms`);
console.log(`  3. DHT探索 (${avgHops} hops):   ~${Math.round(parseFloat(avgHops) * LATENCY.HOP_AVG)}ms`);
console.log(`  4. スレッド一覧取得:      ${LATENCY.HOP_AVG + LATENCY.MAILBOX_READ}ms`);
console.log(`  5. 過去ログ取得:          ${LATENCY.HOP_AVG + LATENCY.MAILBOX_READ}ms`);
console.log(`  6. 復号＆描画:            ${LATENCY.DECRYPTION}ms`);

console.log(`\n=== 結論 ===`);
if (avg < 1000) {
    console.log(`[EXCELLENT] 平均${avg}ms（約${(avg/1000).toFixed(1)}秒）で板の表示完了。`);
    console.log(`2chの専ブラ（初回接続）と同等以上の体感速度。`);
} else if (avg < 3000) {
    console.log(`[GOOD] 平均${avg}ms（約${(avg/1000).toFixed(1)}秒）で板の表示完了。`);
    console.log(`Webページのロードと同程度の体感速度。`);
} else {
    console.log(`[SLOW] 平均${avg}ms（約${(avg/1000).toFixed(1)}秒）。改善が必要。`);
}
