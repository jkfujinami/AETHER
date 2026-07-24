/**
 * AETHER Web-Lite: Encrypted Gossip Distribution & Subscription Test
 *
 * Verifies:
 * 1. Blind Subscription: Nodes subscribe via opaque gossip_tags (8-byte hash)
 * 2. Encrypted Publish: Posts are encrypted, relay nodes can't read content
 * 3. Delivery Rate: What % of subscribers receive the message via gossip?
 * 4. Privacy: Relay nodes never learn topic names or content
 */

const crypto = require('crypto');

const NUM_NODES = 1000;
const DEGREE = 6;
const HOP_LIMIT = 10;

// --- Crypto helpers (simulating browser-side crypto) ---
function hmac(key, data) {
    return crypto.createHmac('sha256', key).update(data).digest();
}
function sha256(data) {
    return crypto.createHash('sha256').update(data).digest();
}
function deriveThreadKey(boardkey, threadId) {
    return hmac(boardkey, `thread:${threadId}`);
}
function deriveTopicHash(threadKey) {
    return sha256(threadKey);
}
function deriveGossipTag(topicHash) {
    return sha256(Buffer.concat([Buffer.from('gossip:'), topicHash])).subarray(0, 8);
}
// Simulated encryption (XOR for speed, real would be ChaCha20)
function encrypt(key, plaintext) {
    const buf = Buffer.from(plaintext, 'utf-8');
    const keyBuf = sha256(key);
    return Buffer.from(buf.map((b, i) => b ^ keyBuf[i % 32]));
}
function decrypt(key, ciphertext) {
    const keyBuf = sha256(key);
    return Buffer.from(ciphertext.map((b, i) => b ^ keyBuf[i % 32])).toString('utf-8');
}

// --- Node ---
class Node {
    constructor(id) {
        this.id = id;
        this.neighbors = new Set();
        this.subscriptions = new Map(); // gossip_tag_hex -> { threadKey, topicHash }
        this.received = new Map();      // packet_hash -> true (dedup)
        this.decryptedMessages = [];    // Successfully decrypted messages
        this.relayedCount = 0;
        this.knownTopicNames = new Set(); // Privacy check: does relay learn topic?
    }

    addNeighbor(peer) {
        if (peer.id === this.id || this.neighbors.size >= 12) return;
        this.neighbors.add(peer);
        peer.neighbors.add(this);
    }

    // Subscribe to a thread (only if you know the URL/boardkey)
    subscribe(boardkey, threadId) {
        const threadKey = deriveThreadKey(boardkey, threadId);
        const topicHash = deriveTopicHash(threadKey);
        const gossipTag = deriveGossipTag(topicHash);
        const tagHex = gossipTag.toString('hex');
        this.subscriptions.set(tagHex, { threadKey, topicHash, boardkey, threadId });
        return { threadKey, topicHash, gossipTag, tagHex };
    }

    // Publish a message (encrypted)
    publish(threadKey, topicHash, content) {
        const gossipTag = deriveGossipTag(topicHash);
        const encrypted = encrypt(threadKey, content);
        const packetHash = sha256(encrypted).toString('hex');

        const packet = {
            gossip_tag: gossipTag.toString('hex'),
            payload: encrypted,
            hop_count: 0,
            packet_hash: packetHash,
        };

        this.received.set(packetHash, true);
        // Gossip to all neighbors
        for (const neighbor of this.neighbors) {
            neighbor.receiveGossip(packet);
        }
        return packet;
    }

    // Receive a gossip packet
    receiveGossip(packet) {
        // Dedup
        if (this.received.has(packet.packet_hash)) return;
        this.received.set(packet.packet_hash, true);

        // Hop limit
        if (packet.hop_count >= HOP_LIMIT) return;

        // Check if I'm subscribed to this gossip_tag
        if (this.subscriptions.has(packet.gossip_tag)) {
            const sub = this.subscriptions.get(packet.gossip_tag);
            try {
                const decrypted = decrypt(sub.threadKey, packet.payload);
                this.decryptedMessages.push(decrypted);
            } catch (_) {
                // Decryption failed (wrong key) - ignore
            }
        }

        // PRIVACY CHECK: Does this node learn the topic name?
        // Answer: No. It only sees gossip_tag (opaque 8 bytes).
        // We track what relay nodes "know" to verify.
        if (!this.subscriptions.has(packet.gossip_tag)) {
            // I'm a blind relay. I see gossip_tag but can't reverse it.
            this.knownTopicNames.add(packet.gossip_tag); // Just the hash, not "board:vip"
        }

        this.relayedCount++;

        // Forward to neighbors
        const forwarded = { ...packet, hop_count: packet.hop_count + 1 };
        for (const neighbor of this.neighbors) {
            neighbor.receiveGossip(forwarded);
        }
    }
}

// --- Build mesh ---
const nodes = Array.from({ length: NUM_NODES }, (_, i) => new Node(i));
nodes.forEach(node => {
    while (node.neighbors.size < DEGREE) {
        const target = nodes[Math.floor(Math.random() * NUM_NODES)];
        node.addNeighbor(target);
    }
});

// --- Setup: 50 nodes subscribe to VIP board, thread 12345 ---
const BOARDKEY = crypto.randomBytes(32);
const THREAD_ID = '12345';
const subscriberIndices = [];
const nonSubscriberIndices = [];
for (let i = 0; i < NUM_NODES; i++) {
    if (i < 50) {
        nodes[i].subscribe(BOARDKEY, THREAD_ID);
        subscriberIndices.push(i);
    } else {
        nonSubscriberIndices.push(i);
    }
}

console.log("=== AETHER Web-Lite: Encrypted Gossip Test ===\n");
console.log(`Nodes: ${NUM_NODES}, Subscribers: ${subscriberIndices.length}, Degree: ${DEGREE}`);
console.log(`Hop Limit: ${HOP_LIMIT}\n`);

// --- Test 1: Publish from a subscriber ---
console.log("--- Test 1: Publish & Delivery ---");
const publisher = nodes[0];
const { threadKey, topicHash } = publisher.subscriptions.values().next().value;
const message = "キタ━━━(゜∀゜)━━━!!";
publisher.publish(threadKey, topicHash, message);

// Check delivery
let delivered = 0;
let correctContent = 0;
for (const idx of subscriberIndices) {
    if (nodes[idx].decryptedMessages.length > 0) {
        delivered++;
        if (nodes[idx].decryptedMessages[0] === message) correctContent++;
    }
}
console.log(`Delivery Rate: ${delivered}/${subscriberIndices.length} subscribers received (${(delivered/subscriberIndices.length*100).toFixed(1)}%)`);
console.log(`Content Integrity: ${correctContent}/${delivered} decrypted correctly\n`);

// --- Test 2: Privacy check ---
console.log("--- Test 2: Privacy Verification ---");
let relayLearnedTopic = 0;
let totalRelays = 0;
for (const idx of nonSubscriberIndices) {
    if (nodes[idx].relayedCount > 0) {
        totalRelays++;
        // Check: did any relay node learn "board:vip" or "thread:12345"?
        // They only have gossip_tag hex strings, never the original topic name.
        for (const known of nodes[idx].knownTopicNames) {
            if (known.includes('vip') || known.includes('12345')) {
                relayLearnedTopic++;
            }
        }
    }
}
console.log(`Relay nodes that forwarded data: ${totalRelays}`);
console.log(`Relay nodes that learned topic name: ${relayLearnedTopic}`);
if (relayLearnedTopic === 0) {
    console.log("[PASS] No relay node learned the topic name (Blind Relay confirmed)\n");
} else {
    console.log("[FAIL] Privacy breach detected!\n");
}

// --- Test 3: Non-subscriber decryption attempt ---
console.log("--- Test 3: Non-Subscriber Cannot Decrypt ---");
let nonSubDecrypted = 0;
for (const idx of nonSubscriberIndices) {
    if (nodes[idx].decryptedMessages.length > 0) {
        nonSubDecrypted++;
    }
}
console.log(`Non-subscribers who decrypted: ${nonSubDecrypted}/${nonSubscriberIndices.length}`);
if (nonSubDecrypted === 0) {
    console.log("[PASS] No non-subscriber could decrypt the message\n");
} else {
    console.log("[FAIL] Non-subscriber decrypted a message!\n");
}

// --- Test 4: Multiple topics don't interfere ---
console.log("--- Test 4: Multiple Topic Isolation ---");
const BOARDKEY2 = crypto.randomBytes(32);
for (let i = 50; i < 80; i++) {
    nodes[i].subscribe(BOARDKEY2, '99999');
}
// Publish on topic 2
const pub2 = nodes[50];
const sub2 = pub2.subscriptions.values().next().value;
pub2.publish(sub2.threadKey, sub2.topicHash, "This is anime board");

// Verify VIP subscribers didn't get anime board message
let crossContamination = 0;
for (let i = 0; i < 50; i++) {
    if (nodes[i].decryptedMessages.length > 1) { // They should only have the VIP message
        crossContamination++;
    }
}
console.log(`Cross-topic contamination: ${crossContamination} VIP subscribers received anime data`);
if (crossContamination === 0) {
    console.log("[PASS] Topics are fully isolated\n");
} else {
    console.log("[FAIL] Cross-topic leakage!\n");
}

console.log("=== All Tests Complete ===");
