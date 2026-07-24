/**
 * AETHER Web-Lite: 離散事象シミュレータ (Discrete Event Simulator)
 * 
 * 暗号処理などの重い処理をバイパスし、純粋なネットワークトポロジ、
 * ルーティング、遅延、ノード離脱（Churn）などの「物理現象」をシミュレートします。
 */

// ============================================================
// 1. シミュレーター設定パラメータ
// ============================================================
const CONFIG = {
    NUM_NODES: process.argv[2] ? parseInt(process.argv[2], 10) : 2000, // 総ノード数 (引数で指定可能)
    NUM_ZONES: 256,           // 総Zone数
    ZONES_PER_NODE: 16,       // 1ノードが参加するZone数
    DEGREE: 6,                // Gossipメッシュの接続数（fanout）
    K_REPLICATION: 5,         // Mailboxへの保管ノード数
    BASE_LATENCY_MS: 50,      // 基準通信遅延（Ping）
    JITTER_MS: 50,            // 遅延の揺らぎ（0〜50ms）
    CHURN_RATE: 0.20,         // ネットワーク切断率（途中で20%が突然死する）
};

// ============================================================
// 2. 離散事象エンジン (Priority Queue)
// ============================================================
class PriorityQueue {
    constructor() { this.events = []; }
    push(e) { 
        this.events.push(e); 
        this.events.sort((a,b) => a.time - b.time); 
    }
    pop() { return this.events.shift(); }
    isEmpty() { return this.events.length === 0; }
}

const sim = {
    time: 0,
    q: new PriorityQueue(),
    schedule: (delay, action) => {
        sim.q.push({ time: sim.time + delay, action });
    },
    run: () => {
        let eventCount = 0;
        while(!sim.q.isEmpty()) {
            const e = sim.q.pop();
            sim.time = e.time;
            e.action();
            eventCount++;
        }
        return eventCount;
    }
};

// ============================================================
// 3. ネットワークとノード定義
// ============================================================
class Node {
    constructor(id) {
        this.id = id;
        this.isOnline = true;
        this.zones = new Set();               // 所属する16個のZone
        this.mesh = new Map();                // ZoneID -> Set<NodeID> (隣接ピア)
        this.mailbox = new Set();             // 保管しているパケットID (DHT)
        this.seenPackets = new Set();         // ゴシップでの重複排除用
    }

    // ネットワーク遅延をシミュレートしてパケットを送信
    send(targetNode, packet, handler) {
        if (!this.isOnline || !targetNode.isOnline) return;
        const latency = CONFIG.BASE_LATENCY_MS + Math.random() * CONFIG.JITTER_MS;
        sim.schedule(latency, () => {
            if (targetNode.isOnline) handler(targetNode, packet);
        });
    }
}

const network = {
    nodes: [],
    zoneMap: new Map(), // ZoneID -> Set<NodeID>
    metrics: {
        totalGossipSent: 0,
        totalGossipReceived: 0,
        mailboxHits: 0,
        deliveries: new Map(), // packetId -> [{nodeId, time}]
    }
};

// ランダム選択ユーティリティ (O(K) に最適化)
const getRandomElements = (arr, count) => {
    if (count >= arr.length) return arr;
    const result = new Set();
    while(result.size < count) {
        result.add(arr[Math.floor(Math.random() * arr.length)]);
    }
    return Array.from(result);
};

const getLatency = () => CONFIG.BASE_LATENCY_MS + Math.random() * CONFIG.JITTER_MS;

// ============================================================
// 4. メインルーチン
// ============================================================

console.log("╔═══════════════════════════════════════════════════════════════════╗");
console.log("║     AETHER Web-Lite: ネットワーク動的シミュレーター              ║");
console.log("╚═══════════════════════════════════════════════════════════════════╝");
console.log(`設定: ${CONFIG.NUM_NODES} nodes, ${CONFIG.NUM_ZONES} zones, Churn: ${CONFIG.CHURN_RATE*100}%, Delay: ${CONFIG.BASE_LATENCY_MS}ms\n`);

// [Step 1] ノードの初期化とZoneの割り当て
console.log("[Phase 1] ネットワークの自律配備 (Bootstrap)...");
for (let i = 0; i < CONFIG.NUM_NODES; i++) {
    const node = new Node(i);
    // 256のうち16個のZoneをランダムに選択
    const allZones = Array.from({length: CONFIG.NUM_ZONES}, (_, k) => k);
    const selectedZones = getRandomElements(allZones, CONFIG.ZONES_PER_NODE);
    
    selectedZones.forEach(z => {
        node.zones.add(z);
        if (!network.zoneMap.has(z)) network.zoneMap.set(z, new Set());
        network.zoneMap.get(z).add(i);
    });
    network.nodes.push(node);
}

// 参照速度の最適化のため配列キャッシュを作成
network.zoneArrMap = new Map();
network.zoneMap.forEach((set, z) => network.zoneArrMap.set(z, Array.from(set)));

// [Step 2] libp2p-gossipsub メッシュの自律形成
for (let i = 0; i < CONFIG.NUM_NODES; i++) {
    const node = network.nodes[i];
    node.zones.forEach(z => {
        node.mesh.set(z, new Set());
        // IDが自分と同じになるのを防ぐための簡易フィルタ
        let occupants = network.zoneArrMap.get(z);
        if (occupants.length <= 1) return;
        
        let attempts = 0;
        while(node.mesh.get(z).size < Math.min(CONFIG.DEGREE, occupants.length - 1) && attempts < 20) {
            const p = occupants[Math.floor(Math.random() * occupants.length)];
            if (p !== node.id) node.mesh.get(z).add(p);
            attempts++;
        }
        const peers = Array.from(node.mesh.get(z));
        // 双方向リンクの構築（WebRTC）
        peers.forEach(p => {
            if (!network.nodes[p].mesh.has(z)) network.nodes[p].mesh.set(z, new Set());
            network.nodes[p].mesh.get(z).add(node.id);
        });
    });
}

// 分析: メッシュの形成状態
let emptyZones = 0;
let avgOccupants = 0;
for (let z = 0; z < CONFIG.NUM_ZONES; z++) {
    const size = network.zoneMap.get(z)?.size || 0;
    avgOccupants += size;
    if (size === 0) emptyZones++;
}
console.log(`  - 完了: 1Zoneあたりの平均住民数 = ${(avgOccupants/CONFIG.NUM_ZONES).toFixed(1)}人`);
console.log(`  - 空のZone数: ${emptyZones} / ${CONFIG.NUM_ZONES}\n`);


// [Step 3] パケット配信ロジック定義
const processStem = (node, packet) => {
    // 10%でFluff（拡散）へ移行、90%でStem継続
    if (Math.random() < 0.10) {
        // Fluff: ターゲットのZoneにInjectする
        processFluffInject(node, packet);
    } else {
        // Stem: ランダムな隣接ピア（全接続中から1つ）へバケツリレー
        const allPeers = new Set();
        node.mesh.forEach(peers => peers.forEach(p => {
            if (network.nodes[p].isOnline) allPeers.add(p);
        }));
        if (allPeers.size === 0) return processFluffInject(node, packet); // 逃げ道
        
        const randomPeerId = getRandomElements(Array.from(allPeers), 1)[0];
        const randomPeer = network.nodes[randomPeerId];
        node.send(randomPeer, packet, processStem);
    }
};

const processFluffInject = (flufferNode, packet) => {
    // 1. DHT Mailboxへの保存 (非同期)
    // モック: パケットIDに最も近いKノードをMailboxとする
    const kClosest = network.nodes.slice().sort((a,b) => 
        Math.abs(a.id - packet.targetHash) - Math.abs(b.id - packet.targetHash)
    ).slice(0, CONFIG.K_REPLICATION);

    kClosest.forEach(target => {
        flufferNode.send(target, packet, (n, p) => {
            n.mailbox.add(p.id);
            network.metrics.mailboxHits++;
        });
    });

    // 2. 対象Zoneのメッシュへの投入
    // Flufferが対象Zoneに繋がっていなければ、DHTで誰かを探して投下する
    let injected = false;
    if (flufferNode.zones.has(packet.zoneId)) {
        processGossip(flufferNode, packet);
        injected = true;
    } else {
        const zoneMembers = network.zoneArrMap.get(packet.zoneId) || [];
        // Extract random online member
        let targetMember = null;
        for (let i = 0; i < 20; i++) {
            const candidateId = zoneMembers[Math.floor(Math.random() * zoneMembers.length)];
            if (network.nodes[candidateId] && network.nodes[candidateId].isOnline) {
                targetMember = network.nodes[candidateId];
                break;
            }
        }
        
        if (targetMember) {
            flufferNode.send(targetMember, packet, processGossip);
            injected = true;
        }
    }
};

const processGossip = (node, packet) => {
    if (packet.targetZone !== undefined && packet.targetZone !== packet.zoneId) return; // fail-safe
    if (node.seenPackets.has(packet.id)) return; // 重複排除
    
    node.seenPackets.add(packet.id);
    network.metrics.totalGossipReceived++;

    // 計測: 受け取った時間を記録 (作者以外)
    if (node.id !== packet.authorId) {
        if (!network.metrics.deliveries.has(packet.id)) {
            network.metrics.deliveries.set(packet.id, []);
        }
        network.metrics.deliveries.get(packet.id).push({ nodeId: node.id, time: sim.time });
    }

    // Gossip中継 (fanout)
    const peers = Array.from(node.mesh.get(packet.zoneId) || []);
    // fanout=4の確率的ゴシップ
    const targets = getRandomElements(peers, 4);
    
    targets.forEach(peerId => {
        network.metrics.totalGossipSent++;
        node.send(network.nodes[peerId], packet, processGossip);
    });
};

// テスト実行関数
const runPublishTest = (testName, targetZone) => {
    // Reset specific metrics for this run
    network.metrics.totalGossipSent = 0;

    console.log(`[Phase] ${testName} を開始...`);
    const packetId = Math.floor(Math.random() * 1000000);
    const onlineNodes = network.nodes.filter(n => n.isOnline);
    const author = onlineNodes[Math.floor(Math.random() * onlineNodes.length)];
    
    // 作者(author)はTarget Zoneにいなくても書き込める (Dandelion++)
    const packet = {
        id: packetId,
        zoneId: targetZone,
        authorId: author.id,
        targetHash: Math.floor(Math.random() * CONFIG.NUM_NODES), // for Mailbox routing
        postedAt: sim.time
    };

    // 発射！ (作者がStemフェーズを開始)
    sim.schedule(0, () => processStem(author, packet));
    sim.run();

    // 結果の集計
    const targetMembers = Array.from(network.zoneMap.get(targetZone) || []).filter(id => network.nodes[id].isOnline);
    const expectedCount = targetMembers.length - (author.zones.has(targetZone) ? 1 : 0);
    
    const deliveries = network.metrics.deliveries.get(packetId) || [];
    const deliveredCount = deliveries.length;
    const deliveryRate = expectedCount > 0 ? ((deliveredCount / expectedCount) * 100).toFixed(1) : 100;

    let maxDelay = 0;
    let sumDelay = 0;
    deliveries.forEach(d => {
        const delay = d.time - packet.postedAt;
        if (delay > maxDelay) maxDelay = delay;
        sumDelay += delay;
    });
    const avgDelay = deliveredCount > 0 ? (sumDelay / deliveredCount).toFixed(0) : 0;

    console.log(`  - ターゲットの生還ノード数: ${expectedCount}人`);
    console.log(`  - 配達成功数: ${deliveredCount}人 (${deliveryRate}%)`);
    if (deliveredCount > 0) {
        console.log(`  - 遅延 (作者から全ノードへ): 平均 ${avgDelay} ms, 最大 ${maxDelay.toFixed(0)} ms`);
    } else {
        console.log(`  - 誰もいない！ (DHTにのみ格納されました)`);
    }
    console.log(`  - 消費帯域 (1件のメッセージで発生した全通信回数): Gossip ${network.metrics.totalGossipSent} 回`);
    console.log("");
};


// [Step 4] シナリオ実行

// シナリオ1: 安定状態での送信
runPublishTest("通常テスト(安定状態・人気板 Zone12 への書き込み)", 12);

// シナリオ2: 過疎板への送信
runPublishTest("過疎板テスト(Zone230 への書き込み)", 230);

// [Step 5] ネットワーク切断テロ (Churn) の発生
console.log(`[Phase] ⚠️ 突然のネットワーク障害発生！ (Churn Rate: ${CONFIG.CHURN_RATE*100}%)`);
let offlineCount = 0;
network.nodes.forEach(node => {
    if (Math.random() < CONFIG.CHURN_RATE) {
        node.isOnline = false;
        offlineCount++;
    }
});
console.log(`  - ${offlineCount} 個のノードが突然ダウン（切断・タブ閉じ）しました。メッシュの修復は行いません。\n`);

// シナリオ3: 障害発生直後の送信 (自己修復を待たずに送信)
// Meshは物理的に寸断されている可能性があるが、冗長性(degree=6/fanout=4)でどこまで耐えるか？
runPublishTest("障害直後テスト(切断状態で人気板 Zone12 への書き込み)", 12);

console.log("╔═══════════════════════════════════════════════════════════════════╗");
console.log("║                       シ ミ ュ レ ー シ ョ ン 完 了               ║");
console.log("╚═══════════════════════════════════════════════════════════════════╝");
