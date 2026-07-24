/**
 * AETHER Web-Lite Mesh Simulator
 * 
 * Purpose: Verify resilience and uniformity of a sparse mesh 
 * with degree=6, PEX, and Random shuffling.
 */

const NUM_NODES = 10000;
const IDEAL_DEGREE = 6;
const MIN_DEGREE = 4;
const PEX_PROB = 0.5; // Prob to share peer on request
const SHUFFLE_PROB = 0.2; // Regular edge swap probability

class Node {
    constructor(id) {
        this.id = id;
        this.neighbors = new Set();
        this.alive = true;
    }

    addNeighbor(peer) {
        if (peer.id === this.id) return false;
        if (this.neighbors.size >= 12) return false; // Hard browser limit
        this.neighbors.add(peer);
        peer.neighbors.add(this);
        return true;
    }

    removeNeighbor(peer) {
        if (this.neighbors.has(peer)) {
            this.neighbors.delete(peer);
            peer.neighbors.delete(this);
            return true;
        }
        return false;
    }

    // PEX: Peer Exchange
    requestNewPeer() {
        if (this.neighbors.size === 0) return null;
        const friends = Array.from(this.neighbors);
        const friend = friends[Math.floor(Math.random() * friends.length)];
        const friendsOfFriend = Array.from(friend.neighbors).filter(f => f.id !== this.id && !this.neighbors.has(f));
        if (friendsOfFriend.length === 0) return null;
        return friendsOfFriend[Math.floor(Math.random() * friendsOfFriend.length)];
    }

    maintainDegree(allNodes) {
        if (!this.alive) return;

        // Cleanup dead neighbors
        this.neighbors.forEach(n => {
            if (!n.alive) this.removeNeighbor(n);
        });

        // If below limit, get more
        while (this.neighbors.size < MIN_DEGREE) {
            let newPeer = this.requestNewPeer();
            if (!newPeer) {
                // Limited tracker scan for performance in 10k nodes
                for(let i=0; i<5; i++) {
                    const candidate = allNodes[Math.floor(Math.random() * allNodes.length)];
                    if(candidate.alive && candidate.id !== this.id && !this.neighbors.has(candidate)) {
                        newPeer = candidate;
                        break;
                    }
                }
            }
            if (newPeer) this.addNeighbor(newPeer);
            else break;
        }
    }

    shuffle() {
        if (!this.alive || this.neighbors.size <= MIN_DEGREE) return;
        if (Math.random() < SHUFFLE_PROB) {
            const list = Array.from(this.neighbors);
            const toCut = list[Math.floor(Math.random() * list.length)];
            this.removeNeighbor(toCut);
        }
    }
}

// Global simulation
const nodes = Array.from({ length: NUM_NODES }, (_, i) => new Node(i));

// 1. Initial connection via "Tracker"
console.log("--- Phase 1: Initial Signaling (10,000 Nodes) ---");
nodes.forEach(node => {
    while (node.neighbors.size < IDEAL_DEGREE) {
        const target = nodes[Math.floor(Math.random() * NUM_NODES)];
        node.addNeighbor(target);
    }
});

function calculateStats() {
    const aliveNodes = nodes.filter(n => n.alive);
    if (aliveNodes.length === 0) return { avgDegree: 0, isolatedCount: 0, aliveCount: 0 };

    const degrees = aliveNodes.map(n => n.neighbors.size);
    const avgDegree = degrees.reduce((a, b) => a + b, 0) / aliveNodes.length;
    
    // Connectivity: BFS
    let visited = new Set();
    let q = [aliveNodes[0]];
    visited.add(aliveNodes[0].id);
    let head = 0;
    while(head < q.length) {
        let curr = q[head++];
        for (let n of curr.neighbors) {
            if (!visited.has(n.id)) {
                visited.add(n.id);
                q.push(n);
            }
        }
    }

    const isolatedCount = aliveNodes.length - visited.size;
    return { avgDegree, isolatedCount, aliveCount: aliveNodes.length };
}

console.log("Start Stats:", calculateStats());

// 2. Continuous iterations (Churn & Shuffling)
console.log("\n--- Phase 2: Running Churn Simulation (5 steps) ---");
for (let step = 1; step <= 5; step++) {
    const candidates = nodes.filter(n => n.alive);
    const killCount = Math.floor(candidates.length * 0.05); // 5% churn
    for (let i = 0; i < killCount; i++) {
        const victim = candidates[Math.floor(Math.random() * candidates.length)];
        victim.alive = false;
        victim.neighbors.forEach(n => victim.removeNeighbor(n));
    }

    nodes.filter(n => n.alive).forEach(n => {
        n.maintainDegree(nodes);
        n.shuffle();
    });

    const stats = calculateStats();
    console.log(`Step ${step}: Alive=${stats.aliveCount}, AvgDegree=${stats.avgDegree.toFixed(2)}, Isolated=${stats.isolatedCount}`);
}

// --- Phase 3: Gradual Decay & Bias Analysis ---
console.log("\n--- Phase 3: Gradual Decay & Bias Analysis (Repair in every step) ---");

function printDistribution(nodes) {
    const alive = nodes.filter(n => n.alive);
    const degrees = alive.map(n => n.neighbors.size);
    const max = Math.max(...degrees);
    const min = Math.min(...degrees);
    const avg = degrees.reduce((a, b) => a + b, 0) / alive.length;

    // Histogram
    const histogram = {};
    degrees.forEach(d => histogram[d] = (histogram[d] || 0) + 1);

    console.log(`Stats: Alive=${alive.length}, Min=${min}, Max=${max}, Avg=${avg.toFixed(2)}`);
    console.log("Degree Distribution (Degree: Count):", JSON.stringify(histogram));
}

// Reset all nodes to alive for a fresh test
nodes.forEach(n => {
    n.alive = true;
    n.neighbors.clear();
});
// Initial signaling
nodes.forEach(node => {
    while (node.neighbors.size < IDEAL_DEGREE) {
        const target = nodes[Math.floor(Math.random() * NUM_NODES)];
        node.addNeighbor(target);
    }
});

console.log("\nInitial Mesh Distribution:");
printDistribution(nodes);

console.log("\nSimulation: 50 Iterations of Gradual Decay (1.5% death + repair per step)");
for (let i = 1; i <= 50; i++) {
    const alive = nodes.filter(n => n.alive);
    const toKill = Math.floor(alive.length * 0.015);
    
    // Kill nodes
    for (let j = 0; j < toKill; j++) {
        const victim = alive[Math.floor(Math.random() * alive.length)];
        victim.alive = false;
        victim.neighbors.forEach(n => victim.removeNeighbor(n));
    }

    // Repair loop (Everyone tries to fix their degree)
    nodes.filter(n => n.alive).forEach(n => {
        n.maintainDegree(nodes);
        n.shuffle(); // Shuffle keeps it uniform
    });

    if (i % 10 === 0) {
        process.stdout.write(`Step ${i}: `);
        const stats = calculateStats();
        console.log(`Survivors=${stats.aliveCount}, Isolated=${stats.isolatedCount}`);
    }
}

console.log("\nFinal Mesh Distribution (After 50 steps of decay):");
const finalStats = calculateStats();
printDistribution(nodes);

if (finalStats.isolatedCount === 0) {
    console.log("\n[SUCCESS] Unified mesh maintained throughout gradual decay.");
} else {
    console.log(`\n[WARNING] Network split detected: ${finalStats.isolatedCount} nodes isolated.`);
}

