*English translation of [analysis.md](analysis.md). If the two differ, the Japanese original is authoritative.*

# AETHER Anonymity: A Quantitative Analysis

This document evaluates AETHER's anonymity **quantitatively**, grounded in the actual constants in the code.
The procedure for reproducing the numbers is `docs/anonymity/compute.py` (running `python3 docs/anonymity/compute.py` reprints every table).

> **Reviewed**: errors in the first draft (replication was not included in the censorship probability; the cumulative probability ignored guard rotation; the explanation of holder obliviousness) were corrected, and the timing confirmation attack and grinding cost were added. §6 summarizes the design conclusions drawn from the numbers.

**The stance of this document**: most of the probability formulas shown here are **estimates** under simplifying assumptions such as "independent choices," "a uniformly random placement of adversaries," and "the attacker behaves exactly according to previously known parameters" — they are not **proofs** in the cryptographic sense. What can be called a proof is only a conditional statement of the form "under this assumption, probability ≤ x," not an unconditional security proof. Every number in the body text that is not explicitly labeled a proof is an estimate or approximation.

---

## 0. Premise: key points of the 3 core mechanisms (as implemented in code)

**Notation**: `s` = the shared secret between sender and receiver (private message) or a board's key (derived from the board ID). `K` = the number of Ring+K replicas (`K_REPLICAS = 5`). The first draft also wrote the shared secret as `K`, which was confusing, so it has been unified as `s`.

| Mechanism | What it hides | Implementation |
|---|---|---|
| Broadcast Veil | The destination (who the receiver is) | `core/src/protocol/hint.rs`, `core/src/net/gossip*.rs`, `core/src/net/dandelion.rs`, `core/src/mailbox/hint_release.rs` |
| Schrödinger Mailbox | The body's content, destination, and the sender–receiver link | `core/src/mailbox/schrodinger.rs`, `sharding.rs`, `client/src/pull.rs`, `core/src/net/tunnel.rs` |
| Ring+K | Search visibility — "who is looking for what" | `core/src/net/ring.rs`, `relay_list.rs`, `epoch.rs` |
| (Peripheral) 3-hop Onion / fixed guard / fetch delay and dummies | Source IP, receive timing | `core/src/net/onion.rs`, `guard.rs`, `client/src/receive.rs` |

---

## 1. Adversary model and parameters (list of assumptions)

### Adversaries
- **A1 Local observer**: A passive observer who sees only the packets passing over some links / some relays. Cannot decrypt IPs or content.
- **A2 Sybil relay operator**: Operates a fraction `f` of the network's relays. Can become a guard, middle, exit, or Mailbox holder. We consider `f ∈ {0.01, 0.05, 0.1, 0.2}` (a range often referenced in empirical Tor studies, adopted here as an assumption).
- **A3 ISP subpoena requester**: Can obtain, after the fact, the destinations, timing, and volume for a specific node's IP (assuming a legal request).
- **A4 Device seizure**: Can obtain the keys and state on a specific node's disk (guard list, key store, Mailbox cache).
- **A5 Global passive adversary (GPA)**: Can observe the timing of all links in the network. Like most anonymization systems, AETHER has no effective defense against this. We state honestly here that "this does not hold."

### Load / scale parameters (assumptions, made explicit because they cannot be read from the code)
- Network size `N ∈ {1,000, 10,000, 100,000}`
- Circuits one user builds per day: **10** (an assumption; no default value in the code)
- Observation period: 1 circuit / 1 year (`10 × 365 = 3,650` circuits, an assumption)
- Ring+K's adversarial node placement is approximated as "independently, uniformly at random with probability `f`" (in reality Sybils try to land on targeted coordinates, so this approximation may be too favorable to the attacker; this is discussed as a limitation in §5)

### Actual constants in the code (footnote)
| Constant | Value | Source |
|---|---|---|
| Onion max hop count `MAX_HOPS` | 3 | `core/src/net/onion.rs:43` |
| Guard sample size `GUARD_SAMPLE_SIZE` | 3 | `core/src/net/guard.rs:35` |
| Guard rotation period `GUARD_ROTATION_SECS` | 60 days (5,184,000 seconds) | `core/src/net/guard.rs:41` |
| Consecutive failures before guard demotion | 3 | `core/src/net/guard.rs:44` |
| Dandelion++ fluff probability | 0.25 (expected stem length 4 hops) | `core/src/net/dandelion.rs:33` |
| Dandelion++ fixed epoch for stem successor | 10 minutes | `core/src/net/dandelion.rs:36` |
| Hint PoW difficulty (SHA-256) | 10 bits (default) | `core/src/config.rs:79` |
| NodeId/Directory PoW difficulty (Argon2id) | 16 bits (default) | `core/src/crypto/pow.rs:116`, `core/src/config.rs:80,82` |
| Number of Mailbox holders `K_REPLICAS` | 5 | `core/src/mailbox/schrodinger.rs:32` |
| Reed-Solomon data/parity/total shard count | 3 / 2 / 5 | `core/src/mailbox/sharding.rs:25,28,31` |
| Fetch jitter upper bound `FETCH_JITTER_MAX` | 60 seconds (uniform) | `client/src/receive.rs:37` |
| Cover fetch mean interval `COVER_FETCH_MEAN` | 90 seconds (exponential distribution, clipped at 6x the mean) | `client/src/receive.rs:39,46-51` |
| Receive tunnel rebuild period | 10 minutes | `client/src/receive.rs:24` |
| Ring epoch (drand daily seed) | 1 day (86,400 seconds) | `core/src/net/epoch.rs:39` |
| Target anonymity set for Hint release (default) | 100 items | `core/src/mailbox/hint_release.rs:72` |
| Upper bound on Hint release delay (default) | 6 hours | `core/src/mailbox/hint_release.rs:78` |
| Transmission size deemed to blend into relay traffic | relay_throughput × 8 seconds | `core/src/mailbox/hint_release.rs:40` |
| Circuit hop diversity constraint | Does not select multiple hops from the same IPv4 /16 or IPv6 /32 | `core/src/net/relay_list.rs:125-153, 385-416` |

---

## 2. Summary table (5 configurations × 8 properties)

Legend: ○ = holds (high confidence under this assumption), △ = conditional (depends on scale, adversary ratio, mode), × = does not hold (not preserved by design, or fundamentally impossible against A5). Representative values are estimates at `f=0.05`, `N=10,000`.

| Property | (1) Broadcast Veil alone | (2) Schrödinger Mailbox alone | (3) Ring+K alone | (4) The three combined | (5) Combination + peripheral technology |
|---|---|---|---|---|---|
| Sender anonymity | × (hides the destination but leaves the sender defenseless) | × (Mailbox does not ask who computed it — irrelevant) | × (no search visibility, but unrelated to the sender) | × (none of the three has a mechanism to hide the sender's IP) | △ (f²=0.0025 per circuit. But this accumulates through guard rotation: ≈0.30 over 1 year, ≈0.62 over 3 years. §3.1, Table 3) |
| Receiver anonymity | ○ (the Hint is distributed to all relays, and the check is done locally only. Anonymity set = all relays N that receive the Hint) | △ (the holder does not know the destination, but the fetch's source depends on a different layer) | △ (computing the position requires `s`, so an observer who doesn't know `s` cannot enumerate holders) | ○ (for a passive observer the set ≈ N) | △ (**if the sender is the attacker and can observe the suspect's communication timing, ≈1 bit leaks per message; with 1,000 suspects, 16 messages are enough for 99% identification**. §3.2, Table 6) |
| Sender–Receiver unlinkability | × | × | △ (unlinkable unless the key is known) | △ | ○ (for A2, f=0.05, the probability that "both guard and exit are adversarial" for a single circuit is f²=0.0025) |
| Message–Sender unlinkability | △ (the Hint contains no sender information — only PoW nonce and timestamp) | △ (shards are ciphertext only, no sender information) | Low applicability | ○ | ○ (Onion protects the source IP; combined with Dandelion++, it attenuates the correlation of the exit's point-of-first-appearance) |
| Message–Receiver unlinkability | △ (since the same Hint is delivered to every node, the successful decryptor = receiver is invisible to the network) | △ (shards are unreadable even to the holder) | Low applicability | ○ | ○ |
| Mailbox unlinkability | Low applicability | △ (`position = H(mailbox_key‖s)` makes position computation impossible without `s`; it collapses immediately if `s` is obtained) | ○ (key mixing prevents an observer from enumerating holders) | ○ | ○ |
| Holder obliviousness | Low applicability | ○ (shards are authenticated ciphertext only; the holder sees only the length and the shard number) | ○ (the holder knows it is holding something, but cannot tell which mailbox or whose it is without `s`) | ○ | ○ |
| Session unlinkability | △ (a different blind_tag/nonce every time. But if many Hints come from the same key, there is room for estimation from the appearance pattern) | △ (the receive tunnel is rebuilt every 10 minutes) | Low applicability | △ | △ (constant cover fetches make it harder to distinguish from real fetches, but this is unverified against long-term intersection attacks) |

**The values in this table are approximate; the formulas and numeric tables in each property's section are the more accurate basis.**

---

## 3. Details by property

For each property below, we proceed in the order: definition → discussion across the 5 configurations → formula → numeric table → conditions under which it fails.

### 3.1 Sender anonymity

**Definition**: The attacker cannot identify the real node (IP) that actually sent a given message.

- **(1) Broadcast Veil alone**: The Hint is injected into gossip from someone's node. If the injection point can be observed directly, the sender is identified immediately. Broadcast Veil itself is a mechanism for "hiding the destination"; hiding the source IP is out of scope. **Without Onion, there is no sender anonymity**.
- **(2) Schrödinger Mailbox alone**: If the IP of the node that performed the operation of placing the body into the Mailbox is directly visible, Mailbox does not hide the sender either.
- **(3) Ring+K alone**: The absence of search visibility and hiding the sender's IP are different properties. Alone, they are unrelated.
- **(4) The three combined**: They complement each other, but none of them includes a mechanism to hide the source IP of the communication. Without Onion, the IP that first injected the Hint into gossip, or the IP that came to write to the Mailbox, is directly observed.
- **(5) Combination + peripheral technology**: With the 3-hop Onion (`core/src/net/onion.rs`, `MAX_HOPS=3`), the sender's IP is visible only to the guard, and the guard cannot decrypt the content (Sphinx-style fixed-length header). In addition, the Hint itself is injected into gossip **at the exit relay**, so what a gossip observer can learn is "first appeared at exit relay X" — not the original sender (see the header comment in `core/src/net/dandelion.rs`). Dandelion++ further spreads this "point of first appearance at the exit" statistic via stem/fluff, weakening the correlation between a single exit and a single statistical origin.

**Formula**:
- Identifying the sender requires "the guard is adversarial (IP is visible)" and "the exit is adversarial (content is visible)" to both belong to the same attacker. For a single circuit this is `f²`.
- Guards rotate every 60 days (`GUARD_ROTATION_SECS`). Over `d` days, `g = 1 + ⌊d/60⌋` guards are used, and the probability that at least one of them is adversarial is `1-(1-f)^g`. During the period an adversarial guard is in use, the exit is drawn many times, so the probability the exit is also adversarial approaches nearly 1. Therefore **the long-term probability of sender identification is approximately `1-(1-f)^g`** (Table 3).
- Note: Of the 3 sampled candidates, only the first is actually used; the next is used only on failure. The first draft's "at least one adversary among the 3 samples" is an upper bound, not the actual exposure probability.
- The Dandelion++ expected stem length `= 1/fluff_probability = 1/0.25 = 4` hops (confirmed statistically by the test `expected_stem_length_matches_fluff_probability` in `core/src/net/dandelion.rs:33`, expected value 4).

**Numeric table** (`compute.py` Tables 1 and 3. Assuming 10 circuits/day):

| f | 1 circuit (f²) | 30 days | 1 year | 3 years |
|---|---|---|---|---|
| 0.01 | 0.0001 | 0.0095 | 0.062 | 0.172 |
| 0.05 | 0.0025 | 0.050 | 0.299 | 0.623 |
| 0.10 | 0.0100 | 0.100 | 0.521 | 0.865 |
| 0.20 | 0.0400 | 0.200 | 0.790 | 0.986 |

A fixed guard is far better than "a random entry point every time" (which would converge to probability 1 within a few hundred circuits), but **as long as there is rotation, the risk certainly accumulates over the span of years**. Lengthening the rotation period slows this down, but also extends the harm period if an adversarial guard is drawn.

**Conditions under which this fails**:
- If the guard is adversarial, the source IP is visible to the attacker for **every circuit for the rest of that user's lifetime** (the benefit of a fixed guard is that "the exposure probability does not increase over time," but once exposed, the damage is permanent — see the comment in `core/src/net/guard.rs`).
- Since A5 (a global passive observer) can see all links of the Onion, it may be able to reconstruct the path from packet timing and size. Fixed-length headers and padding (`MIN_PADDED_LEN=1024`) prevent simple size correlation but are powerless against timing correlation. **This is a statement of a limitation, not a proof.**

---

### 3.2 Receiver anonymity

**Definition**: The attacker cannot identify who the receiver is.

- **(1) Broadcast Veil alone**: The Hint is distributed to all N nodes (gossip flooding), and the receiver attempts decryption **locally, on their own**. Since no query at all is issued to the network, ideally "all nodes that received the Hint" = N forms the anonymity set of receiver candidates. This is Broadcast Veil's greatest strength, a property that other designs (DHT-query-based) cannot achieve in principle.
  - However, if the **fetch (going to retrieve the body)** timing is concentrated right after the Hint appears, the fact that "this user received something" leaks to a guard observer of Onion. This is not about Broadcast Veil alone but about the Mailbox fetch part.
- **(2) Schrödinger Mailbox alone**: The body is placed as shards at the positions of K=5 holders. The holder sees only ciphertext and does not know the destination either (Holder obliviousness, §3.7). However, "who came to fetch it" is not directly visible from the holder since it goes through a 3-hop circuit. Alone, this hides the receiver's identity from the holder, but the timing of the fetch action itself is a matter for a different layer.
- **(3) Ring+K alone**: Since position computation requires `s` (`position = H(mailbox_key ‖ s)`, `core/src/net/ring.rs:72-78`), an observer who does not know the key cannot even enumerate the holders. This is irrelevant to those who know the key (the sender and receiver themselves).
- **(4) The three combined**: For every observer who does not know the key, the set of receiver candidates theoretically remains N. Even a holder who knows the key cannot see the content or destination.
- **(5) Combination + peripheral technology**: Fetch jitter (a uniform random value in 0–60 seconds) and cover fetches (an exponential distribution with mean 90 seconds, clipped at 6x the mean) break the direct temporal correlation of "a fetch arrived right after the Hint appeared."

**Formula**:
- Anonymity set of receiver candidates (from the viewpoint of an observer who does not know the key): `|AS| ≈ N` (an ideal value; in practice it gradually shrinks due to the fetch-timing correlation described below).
- Normalized entropy (per the definition of Serjantov & Danezis 2002): under the assumption of a uniform distribution, `H_norm = log2(N) / log2(N) = 1`.
- **Confirmation attack (most important)**: If the attacker, acting as the **sender**, sends a message to the suspect, they know the Hint release time `t0`. If they can observe the suspect's communication timing (ISP interception A3, or an adversarial guard A2), they can observe "did a fetch occur within 60 seconds of `t0`?" If the suspect is the receiver, one always occurs. If not, it occurs only with probability `p0 = 1-exp(-60/90) ≈ 0.487` that a dummy (a Poisson process with mean 90 seconds) falls in the window. The likelihood ratio per message is `1/p0 ≈ 2.05` (about 1 bit). Over `n` messages, the ratio narrows by a factor of `2.05^n` (`compute.py` Table 6).

| Number of suspects | Messages needed for 99% identification |
|---|---|
| 2 | 7 |
| 10 | 10 |
| 1,000 | 16 |
| 10,000 | 20 |

  **The current fetch delay and dummies have almost no effect against this attack.** The countermeasure is in §6-2.

**Numeric table**:

| N | log2(N) [bits] | Normalized entropy (ideal) |
|---|---|---|
| 1,000 | 9.97 | 1.0 |
| 10,000 | 13.29 | 1.0 |
| 100,000 | 16.61 | 1.0 |

**Conditions under which this fails**:
- The claim above that "N as a whole is the anonymity set" assumes that the Hint truly reaches all nodes evenly and that there is no identifiable bias whatsoever in fetch behavior. In reality:
  - If the guard is adversarial (probability f), or is the target of ISP interception, the confirmation attack above holds directly.
  - Gathering the pattern of reacting to Hints from the same party over a long period may allow A2 (a Sybil holding a fraction f) to narrow down the receiver set via a statistical correlation attack (**unverified; this document leaves it as an estimate**).
  - Against A5 (a global passive observer), the effect of fetch jitter and dummies is likely limited. Since a GPA can see all links, there is a risk that it can correlate the network-wide pattern of fetch occurrences with the pattern of Hint propagation, rather than a single node's apparent "reason for fetching." **This should be considered as not holding.**

---

### 3.3 Sender–Receiver unlinkability

**Definition**: The relationship itself of "A sent to B" cannot be linked.

- **(1)(2)(3) alone**: None of them alone has a complete mechanism to hide both the sender's IP and the receiver's identity (Broadcast Veil hides the destination, Ring+K removes search visibility, Mailbox hides the body's content. But hiding the "source IP" is Onion's job).
- **(4) The three combined**: For an observer who does not know the key, there is no direct in-network signal linking A's send to B's receive (the Hint is scattered to all nodes, and the Mailbox holder's position is hidden by key mixing). But without Onion, the source IP is directly visible, so a temporal correlation remains between "A sent something" and the Hint's appearance, and if A2 controls the exit, A's send content is directly visible.
- **(5) Combination + peripheral technology**: Only in the case where an attacker controls both the guard and exit of a single circuit is "the content A sent" directly observed. Even so, who it is addressed to is still protected by the Hint's encryption and the Mailbox's concealment (the destination blind_tag is an HMAC using the shared secret). Therefore, linking "A→B" is thought to require **both** exposure of A's send content (via compromise of guard + exit) **and** correlation with the timing of B's fetch in response to that Hint.

**Formula**:
- Probability that both the guard and exit of a single circuit are adversarial: `P = f^2` (under the assumption of independent choice, `compute.py` Table 1).

**Numeric table**:

| f | P(both guard and exit adversarial, single circuit) |
|---|---|
| 0.01 | 0.000100 |
| 0.05 | 0.002500 |
| 0.10 | 0.010000 |
| 0.20 | 0.040000 |

- Looking at one year (10 circuits/day × 365 days = 3,650 circuits, an assumption), the cumulative exposure probability for the exit alone, `1-(1-f)^3650`, effectively reaches 1.0 even for f=0.01. **Correcting an error in the first draft**: the first draft stated that "since guards are fixed, the probability of an adversarial guard stays at f regardless of the number of years," which is wrong. Guards rotate every 60 days, and each rotation draws a new f-probability chance of an adversary, accumulating to about 6 draws over a year, `1-(1-f)^7` (≈0.30 for f=0.05) (Table in §3.1). What fixed guards prevent is "drawing anew each circuit and reaching probability 1 within a few days" — not accumulation over the span of years.

**Conditions under which this fails**:
- If A4 (device seizure) obtains B's guard list, keys, and Mailbox cache directly from B's device, linking A→B is established trivially, bypassing the cryptography.
- No proof exists against A5.

---

### 3.4 Message–Sender unlinkability

**Definition**: The content of a particular message and the person who sent it cannot be linked.

- **(1) Broadcast Veil**: `HintPacket` (`core/src/protocol/hint.rs:11-22`) has no field indicating the sender (`version, ttl, blind_tag, nonce, pow_nonce, ciphertext`). Since `id()` is computed excluding `ttl` and `pow_nonce` (see the comment on lines 67-79 of the same file), no matter how a relay node forwards it, no sender information is added.
- **(2) Schrödinger Mailbox**: The shard (`core/src/mailbox/sharding.rs`) also has no sender information, and the authentication tag (`SHARD_TAG_LEN=16`, forgery probability `2^-128`) only guarantees integrity with respect to `mailbox_key`.
- **(4)(5)**: Combined with Onion's concealment of the source IP, linking the content to its sender is possible only when the guard and exit are simultaneously adversarial (the same `f^2` as in §3.3).

**Conditions under which this fails**: A guard observer alone can only see the fact that "an encrypted packet went out" — the content is protected at the Onion layer. However, if the exit is adversarial, the decrypted content of the Hint/shard itself is visible, and if the guard is adversarial, the source IP is visible. Only when the same attacker controls both are the content and the sender directly linked.

---

### 3.5 Message–Receiver unlinkability

**Definition**: The content of a particular message and the person who received it cannot be linked.

- **(1) Broadcast Veil**: Since the Hint is distributed to all nodes in identical form, a gossip observer has no means of knowing "who succeeded in decrypting it" — the receive determination is entirely local.
- **(2) Schrödinger Mailbox**: The holder has only ciphertext, and the identity of whoever calls `open()` (`core/src/mailbox/sharding.rs:121-136`) — i.e., the fetcher — is protected by the 3-hop Onion.
- **(4)(5)**: Only when the receiver actually goes to fetch the body (via the 3-hop circuit) might the correspondence between that fetch action's destination and the holder become visible to the guard side. Even here, the requester's identity is not visible from the holder.

**Conditions under which this fails**: If the receiver's device is seized (A4), the decryption key and received messages are obtained directly. This is outside the scope of the cryptographic protocol.

---

### 3.6 Mailbox unlinkability

**Definition**: A specific user (NodeId or identity) and the position of the Mailbox that user uses cannot be linked.

- **(3) Ring+K alone is the core**: `position_of_mailbox(mailbox_key, key)` hashes in the Hint's decryption key `key` (`core/src/net/ring.rs:69-78`), so an observer who does not know the key cannot compute the Mailbox's position. The test `mailbox_position_depends_on_the_key` (same file, lines 181-193) confirms this.
- **Limitation**: The comment at `core/src/net/ring.rs:16-19` states that "keys in public mode are subject to dictionary attack," but this is **outdated**, dating from the keyword-based scheme era (boards have already migrated to random IDs). Currently, the only positions that are public are the built-in board (which embeds an ID) and the prekey bundle, and these are intentionally public.

**Formula/numbers**: A board's key is derived from a **random 256-bit board ID** (`BoardId::key` in `client/src/boards.rs`). Derivation from a keyword has been abolished, so dictionary attacks do not succeed. The cost of guessing a private board's position is 2^256. However, the following two **do** have public positions:
- The index of the built-in board (whose ID is embedded in the app)
- Each user's prekey bundle (its position is `H("aether_prekey_v1" ‖ NodeId)`, computable by anyone who knows the NodeId; `prekey_location` in `core/src/mailbox/schrodinger.rs`)

These are subject to targeted grinding (§3.7, §6-1).

**Conditions under which this fails**: Even for a private message, if `s` leaks to the attacker (device seizure A4, or collusion by the counterparty), it collapses immediately. In public mode, it is expected to collapse from the outset.

---

### 3.7 Holder obliviousness

**Definition**: Even the node holding a Mailbox shard itself cannot learn the destination or content.

- **(2) Schrödinger Mailbox alone is the core**: What the holder receives is only the shard sealed by `seal()` (`[index(1)][original_len(4)][data][tag(16)]`, `core/src/mailbox/sharding.rs:95-116`). The contents are ciphertext, and the AEAD cannot be opened without knowing `mailbox_key`. Since the tag is computed including `mailbox_key`, contamination with a shard from a different message is also prevented (see the comment on lines 109-110 of the same file).
- **(3) Ring+K**: The holder does know that it is holding a shard (naturally, since it is storing it). However, since `s` is mixed into `position_of_shard` (`core/src/net/ring.rs:80-92`), **which mailbox it is, or whom it is addressed to, cannot be determined without `s`**.
- **Role of Reed-Solomon**: Since each holder has only part of the whole (1 out of 5), even if the cryptography were broken, no single holder alone could reconstruct the whole (`DATA_SHARDS=3` are required, `core/src/mailbox/sharding.rs:25`).

**Formula (correcting the first draft)**: Each shard is replicated onto `K = 5` machines. A single shard becomes unobtainable only when all 5 machines are adversarial (`q = f^5`). To prevent reconstruction of the body, 3 or more of the 5 shards must be made unobtainable:

`P(censorship succeeds) = P(Binomial(5, q) ≥ 3),  q = f^K`

The first draft omitted the replication and used `P(Binomial(5, f) ≥ 3)`, which overestimated the probability by orders of magnitude.

**Numeric table** (`compute.py` Table 4. Applies to independent, uniform placement — i.e., a private message body whose position is unknown to the attacker):

| f | All 5 machines for one shard are adversarial | Censorship succeeds (3/5 or more shards) |
|---|---|---|
| 0.01 | 1.0×10⁻¹⁰ | 1.0×10⁻²⁹ |
| 0.05 | 3.1×10⁻⁷ | 3.1×10⁻¹⁹ |
| 0.10 | 1.0×10⁻⁵ | 1.0×10⁻¹⁴ |
| 0.20 | 3.2×10⁻⁴ | 3.3×10⁻¹⁰ |

**Conditions under which this fails**:
- The above is a vulnerability with respect to "whether delivery succeeds (censorship)," not "concealment of content"; Holder obliviousness itself (concealment of content and destination) holds cryptographically regardless of f (as long as the key is not held).
- The table above gives values for the case where "the holder's position is unknown to the attacker" (a private message body). **It does not hold for targets whose position is public (the built-in board's index, prekey bundles)**. A node's position is `H(NodeId ‖ seed)`, and **the NodeId's PoW plays no part in computing the position**. The attacker can generate key pairs and compute positions cheaply, solving PoW only for the ones that land closer to the target position than the nearest honest node. Since the probability of landing closer in is roughly `1/N`, this needs `K·N` position computations for K machines' worth (even at N=100,000, only 500,000 hashes) plus `K` PoW solves (about 90 seconds). **Regardless of network size, about 90 seconds of computation is enough to take over all the holders of the built-in board's index or a given person's prekey bundle** (`compute.py` Table 5).
- The seed is fixed by default (`epoch_beacon = false`, `EPOCH_SEED_PLACEHOLDER`). Even if the daily seed is enabled, **as long as a new node can become a holder immediately, paying 90 seconds every day reproduces this**. Furthermore, the positions of the Mailbox and shard themselves do not incorporate the seed (`position_of_mailbox` / `position_of_shard`), so rotating the seed only moves the node's own position. The countermeasure is in §6-1.

---

### 3.8 Session unlinkability

**Definition**: Multiple communications by the same user (multiple messages, multiple logins, etc.) cannot be linked.

- **(1) Broadcast Veil**: `HintPacket.blind_tag` is `HMAC(SharedSecret, Nonce)[0..4]`, and since a different nonce is used each time it is sent, the Hint alone provides no mechanical way to link multiple messages from the same sender (however, statistical estimation from the frequency pattern of the same blind_tag repeatedly appearing for the same shared key is a separate problem. **Unverified**).
- **(2)(3)**: The Mailbox position and shard position are also designed to change depending on the per-send nonce and key.
- **(5)**: The receive tunnel is rebuilt every 10 minutes (`SESSION_LIFETIME=600 seconds`, `client/src/receive.rs:24`), and constant cover fetches lower the distinguishability of "when the real fetch occurred."

**Conditions under which this fails**:
- Since the guard is fixed (60 days), the very fact of continuing to use the same guard is, to A2 (an adversary holding that guard), an obvious clue linking "multiple connections by the same user." This is the **intended** trade-off of the fixed-guard scheme (in exchange for not increasing the exposure probability over time, once exposed, the entire lifetime's worth becomes visible all at once), and from the standpoint of Session unlinkability, a fixed guard is a weak point.
- Long-term intersection attack: from a pattern in which the same receiver repeatedly comes online during the same time windows, A2 or A5 may be able to statistically narrow down the receiver. **This document has not verified this** (§5 Limitations).

---

## 4. Summary of attack success probabilities (tables)

Output of `python3 docs/anonymity/compute.py` (table numbers correspond to those in the script).

### 4.1 Sender identification (Tables 1 and 3, assuming 10 circuits/day)

| f | 1 circuit | 30 days | 1 year | 3 years |
|---|---|---|---|---|
| 0.01 | 0.0001 | 0.0095 | 0.062 | 0.172 |
| 0.05 | 0.0025 | 0.050 | 0.299 | 0.623 |
| 0.10 | 0.0100 | 0.100 | 0.521 | 0.865 |
| 0.20 | 0.0400 | 0.200 | 0.790 | 0.986 |

### 4.2 Censorship of a private message's body (Table 4, when the position is unknown to the attacker)

| f | Censorship succeeds |
|---|---|
| 0.05 | 3.1×10⁻¹⁹ |
| 0.20 | 3.3×10⁻¹⁰ |

### 4.3 Targeted grinding of an object whose position is public (Table 5)

| N | Position computations | PoW | CPU |
|---|---|---|---|
| 1,000〜100,000 | 5N times | 5 times | About 90 seconds |

### 4.4 Receiver confirmation attack (Table 6)

About 1.04 bits per message. With 1,000 suspects, 16 messages; with 10,000 suspects, 20 messages, for 99% identification.

## 5. Limitations (stated honestly)

- **Global passive adversary (A5)**: If the timing of all links can be observed, then even with fixed-length padding, jitter, and cover fetches, given a sufficiently long observation period it is likely possible to narrow down the server/receiver via statistical timing correlation. AETHER has no formal defense against this (other practical anonymization systems are the same; this is not a weakness specific to AETHER but a general limitation).
- **Long-term intersection attacks**: This document does not perform a quantitative evaluation of an attack that gathers correlations over a long period across multiple online periods and multiple Hint-response patterns for the same user (this would require simulation and is out of scope for this task).
- **When the Sybil takes its time**: The guard scheme weights by operational track record so that "a brand-new node is not suddenly treated as a guard" (see the `prefers_long_running_candidates` test in `core/src/net/guard.rs`), but the defensive strength against an attacker who patiently builds up an operational track record over months to years is not captured by this document's constant-`f` model.
- **When Ring+K's consistency breaks down**: If there is drift between nodes in the propagation of the epoch seed (dependent on the republish loop mentioned in the comment at `core/src/net/relay_list.rs:279-285`), the sender side and receiver side will compute different K-nearest results, degrading availability. This document assumes that "the epoch is consistent across all nodes," and does not evaluate the impact on anonymity when this assumption breaks down (for example, an attack exploiting a temporary inconsistency).
- **The built-in board and prekey bundle** have publicly known positions, and Mailbox unlinkability is intentionally not held for them (§3.6). Vulnerability to targeted grinding is discussed in §6-1.
- The probability formulas in this document are a simplified model assuming independence and uniformity, and do not fully reflect the correlation structure arising from the actual Sybil coordinate-grinding strategy or from network diversity constraints (exclusion of the same /16, `relay_list.rs`).

---

## 6. Design conclusions drawn from the numbers

Expressed numerically, the properties protected by the 3 core mechanisms (Broadcast Veil, Schrödinger Mailbox, Ring+K) — passive anonymity of the receiver, holder obliviousness, censorship resistance of a private message's body — are very strong, while **3 peripheral spots determine the overall strength**.

**6-1. Targeted grinding of an object whose position is public (achievable in about 90 seconds)**
- Cause: PoW plays no part in a node's position, and a new node can become a holder immediately.
- Countermeasure: Impose a **tenure** requirement on holder eligibility (having been in the network before that epoch's seed was published). A node that ground its position after learning the seed does not qualify, making targeted grinding impossible, returning to the independent-uniform model of Table 4. Also enable the daily seed (drand) by default.
- Alternative: Derive the position from the output of PoW (`H(PoW solution ‖ seed)`). Then a PoW would be required for each grind attempt, at a cost of about `K·N·18` seconds (about 10 CPU-days for N=10,000). This is insufficient against a nation-state-scale adversary, so tenure is the primary recommendation.

**6-2. Receiver confirmation attack (about 1 bit per message)**
- Cause: A real fetch "always occurs within 60 seconds after the Hint," while dummies occur independently, so the presence or absence of a fetch within the window carries information.
- Countermeasure: Switch to **constant-rate fetch slots**. Fetches always occur exactly once, at a fixed interval (e.g., every 60 seconds), and if there is a real one, it is emitted in that slot in place of the dummy. Since the observed fetch timing does not change regardless of whether a real one exists, the likelihood ratio becomes 1 (no number of messages can narrow it down). The cost is a delay in reception (on average, half the slot interval) and a constant amount of bandwidth. This is the same idea as a Loopix-type mixnet.
- Note: A resident node's fetch comes from a UDP port separate from the one used for relaying (the RelayClient's independent endpoint). Since an observer of the node's traffic can tell its relay traffic apart from the node's own fetches, no benefit from blending into relay traffic should be expected.

**6-3. Accumulation of sender identification (about 30% over 1 year, at f=0.05)**
- The fixed guard is effective, but accumulates over the span of years. Lengthening the rotation period slows the accumulation, but also extends the harm period when an adversarial guard is drawn.
- The essential improvement is to lower f itself (the tenure requirement of 6-1, /16 distribution of circuits, eclipse countermeasures).

## 7. Answers to unresolved questions from the first draft

1. **Gossip fanout**: `GOSSIP_FANOUT = 3` (`core/src/node/server.rs:32`). The propagation targets are chosen at random from the directory. Since the Hint flows **only among relays**, the receiver's anonymity set is "the whole relay population," not "all users." This is also why receiving requires being resident (a relay).
2. **Board keys**: Derived from a random 256-bit board ID (`client/src/boards.rs`). Dictionary attacks do not succeed. Only the built-in board has a public position (§3.6).
3. **Self-reported tier**: It is signed, but the content itself is self-reported. A Sybil can claim to be "reachable (Open)," entering it into the candidate pool for holders and circuits. The tenure requirement of 6-1 substantially suppresses this as well.
4. **Epoch beacon**: Disabled by default (`epoch_beacon: false`). The position uses a fixed seed. As in §3.7 and 6-1, even if enabled, targeted grinding cannot be prevented without the tenure requirement.
5. **Circuits per day**: There is no fixed value in the code. One send builds 2 circuits (one for the body, one for the Hint), and one fetch builds 1 circuit (up to 3 with rebuilding), so 10/day is a reasonable estimate for "a user who exchanges messages several times a day."
6. **Dandelion wiring**: When the Onion's exit receives an `InnerPacketType::GossipHint`, it calls `inject_hint`, and the stem begins from there (`process_packet` in `core/src/node/server.rs`). Therefore the stem's starting point is the exit relay, not the sender themself.

---

## 8. References

- Serjantov, A., & Danezis, G. (2002). *Towards an Information Theoretic Metric for Anonymity*. Privacy Enhancing Technologies (PET).
- Díaz, C., Seys, S., Claessens, J., & Preneel, B. (2002). *Towards Measuring Anonymity*. Privacy Enhancing Technologies (PET).
- Fanti, G., Venkatakrishnan, S. B., Bakshi, S., & Denby, B. (2018). *Dandelion++: Lightweight Cryptocurrency Networking with Formal Anonymity Guarantees*. SIGMETRICS.
- Danezis, G., & Goldberg, I. (2009). *Sphinx: A Compact and Provably Secure Mix Format*. IEEE Symposium on Security and Privacy.
- Johnson, A., Wacek, C., Jansen, R., Sherr, M., & Syverson, P. (2013). *Users Get Routed: Traffic Correlation on Tor by Realistic Adversaries*. ACM CCS. (An empirical study of Tor's fixed-guard scheme, referenced as background for the discussion of guard operation.)
- drand (League of Entropy) — a distributed randomness beacon. A public randomness source mentioned in the comments of `core/src/net/epoch.rs`.

**References whose existence could not be confidently confirmed have not been included in this section.**

---
