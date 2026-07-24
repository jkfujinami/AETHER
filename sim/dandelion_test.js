/**
 * AETHER Web-Lite: Dandelion++ vs No-Dandelion Deanonymization Simulation
 *
 * Measures: For a given attacker control %, how likely is the author identified?
 *
 * Model:
 * - Without Dandelion: Author sends to 6 neighbors with hop_count=0.
 *   If ANY neighbor is attacker → author identified.
 *
 * - With Dandelion++: Author sends through a stem of S hops (1 peer each).
 *   Then last stem node broadcasts (fluff). 
 *   Attacker can identify author ONLY if:
 *     a) First stem node is attacker AND
 *     b) Attacker can distinguish "author" from "stem relay"
 *   Plausible deniability: author also relays other people's stem packets,
 *   so attacker sees both "authored" and "relayed" stems from the same IP.
 */

const TRIALS = 100000;
const DEGREE = 6;

function simulateNoDandelion(attackerRatio) {
    let identified = 0;
    for (let t = 0; t < TRIALS; t++) {
        // Author sends to 6 neighbors. If ANY is attacker → caught.
        let caught = false;
        for (let i = 0; i < DEGREE; i++) {
            if (Math.random() < attackerRatio) {
                caught = true;
                break;
            }
        }
        if (caught) identified++;
    }
    return (identified / TRIALS * 100).toFixed(2);
}

function simulateDandelion(attackerRatio, stemHops) {
    let identified = 0;
    for (let t = 0; t < TRIALS; t++) {
        // Stem phase: author passes to 1 random peer, chain of stemHops
        // Attacker identifies author ONLY if first stem node is attacker
        // AND the attacker can distinguish author from relay.
        //
        // Plausible deniability model:
        // Author also relays ~2 other people's stem packets per minute on average.
        // If attacker sees 3 stem packets from author's IP (1 authored + 2 relays),
        // they can only guess which one is authored = 1/3 chance.
        // With more network activity, this ratio improves further.

        const firstStemIsAttacker = Math.random() < attackerRatio;

        if (!firstStemIsAttacker) {
            // First stem node is honest → author is completely safe.
            // Even if later stem nodes are attackers, they see a different IP (not author).
            continue;
        }

        // First stem is attacker. Can they distinguish?
        // The author also relays other stem packets, providing cover.
        // Assume author relays on average `relayCount` other stems in same time window.
        const relayCount = 2; // Other people's stems passing through author
        const totalStemsFromAuthor = 1 + relayCount; // 1 authored + relays
        const correctGuess = Math.random() < (1 / totalStemsFromAuthor);

        if (correctGuess) identified++;
    }
    return (identified / TRIALS * 100).toFixed(2);
}

function simulateDandelionWorstCase(attackerRatio, stemHops) {
    // Worst case: no cover traffic. Attacker at first hop = 100% identification.
    let identified = 0;
    for (let t = 0; t < TRIALS; t++) {
        const firstStemIsAttacker = Math.random() < attackerRatio;
        if (firstStemIsAttacker) identified++;
    }
    return (identified / TRIALS * 100).toFixed(2);
}

console.log("=== Deanonymization Probability: Dandelion++ vs No Protection ===\n");
console.log("条件: 10,000ノード, Degree=6, 10万回試行\n");

const attackerRatios = [0.05, 0.10, 0.15, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80];

console.log("┌────────────┬──────────────────┬──────────────────┬──────────────────┐");
console.log("│ 攻撃者の   │ Dandelionなし    │ Dandelion++      │ Dandelion++      │");
console.log("│ 支配率     │ (現在の設計)     │ (最悪ケース)     │ (実運用想定)     │");
console.log("├────────────┼──────────────────┼──────────────────┼──────────────────┤");

for (const p of attackerRatios) {
    const noDande = simulateNoDandelion(p);
    const dandeWorst = simulateDandelionWorstCase(p, 3);
    const dandeBest = simulateDandelion(p, 3);

    const pStr = `${(p * 100).toFixed(0)}%`.padStart(4);
    const noD = `${noDande}%`.padStart(8);
    const dW = `${dandeWorst}%`.padStart(8);
    const dB = `${dandeBest}%`.padStart(8);

    console.log(`│ ${pStr}       │ ${noD}          │ ${dW}          │ ${dB}          │`);
}

console.log("└────────────┴──────────────────┴──────────────────┴──────────────────┘");

console.log(`
用語:
  Dandelionなし:    hop_count=0 を隣人6人に送信。1人でも攻撃者なら特定される。
  最悪ケース:       Stemの最初の1ホップが攻撃者 → 即特定。カバートラフィックなし。
  実運用想定:       作者は他人のStemも中継するため、攻撃者は3本のStemから
                    1本を選ぶ確率勝負（1/3）になる。

分析:
`);

// Analysis
const threshold50NoDande = attackerRatios.find(p => parseFloat(simulateNoDandelion(p)) > 50);
const threshold50DandeBest = attackerRatios.find(p => parseFloat(simulateDandelion(p, 3)) > 50);

console.log(`  Dandelionなしで特定率50%を超える攻撃者支配率: ${threshold50NoDande ? (threshold50NoDande*100) + '%' : '>80%'}`);
console.log(`  Dandelion++(実運用)で特定率50%を超える攻撃者支配率: ${threshold50DandeBest ? (threshold50DandeBest*100) + '%' : '>80%'}`);

console.log(`
結論:
  Dandelionなし → 攻撃者が10%いるだけで約47%の確率で特定される
  Dandelion++   → 攻撃者が50%を支配しても特定率は約17%にとどまる
                → 攻撃者が80%を支配して初めて特定率が約27%
`);
