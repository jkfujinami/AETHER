# AETHER: A Metadata-Private Messaging and Bulletin-Board Protocol

**Status: experimental, not audited. Do not use for anything where real safety
depends on it.**

This document describes the design of AETHER, a peer-to-peer protocol for
private messaging and public bulletin boards. It is intended for reviewers
who want to evaluate the design or run a test-network node. It describes what
the code currently does; where the implementation is incomplete or a
mitigation is only partial, this is called out explicitly rather than glossed
over.

## Abstract

Most privacy tools protect the *content* of communication (end-to-end
encryption is now common and well understood) but leave *metadata* —
who talked to whom, when, how much, and from where — visible to anyone who
can watch the network or compel a provider. That metadata is frequently
enough to identify participants even when the payload is unreadable. AETHER
is an attempt at a protocol where the metadata itself is hidden from
observers, including observers who participate in the network as relays.
It combines three mechanisms — a flooded "hint" layer for addressing
messages without querying for a recipient, content-addressed storage at a
location only sender and recipient can compute, and a locally-computed
"nearest holder" scheme that replaces DHT lookups — on top of onion-routed
transport. It supports both private messages and public, threaded
bulletin-board content under the same anonymity substrate.

## Motivation

Content encryption answers "can an eavesdropper read the message." It does
not answer "can an eavesdropper (or a party who later compels a relay
operator, an ISP, or a device owner) determine that two specific parties
communicated, how often, and roughly when." In practice, this second
question is what de-anonymizes people: traffic analysis, timing
correlation, and contact-graph reconstruction do not require breaking any
cipher. A design that only encrypts payloads leaves this exposed. AETHER's
goal is to make the *metadata* — sender, recipient, and content location —
unavailable to anyone who is not one of the two parties to a private
message, or, for public content, at least to make it impossible to bind an
*author* to a public post from network observation alone.

## Threat Model

**In scope.** The adversary can:
- Run some fraction of relays in the network (a participating, not purely
  passive, attacker).
- Observe traffic at a subset of vantage points and correlate timing
  across the hops it controls.
- Compel an ISP to produce connection records for an IP address it has
  identified.
- Seize a device and perform forensic analysis on its storage.
- Enumerate the public relay list and the public board/content directory
  (both are, by design, visible to everyone — see Ring+K below).

The design goal against this adversary is threefold:
1. Prevent the adversary from binding an IP address to a sender,
   recipient, or content holder through network observation.
2. Ensure that seizing a device does not expose past communications
   (forward secrecy) and that data at rest is unreadable without a
   passphrase.
3. Make content resistant to takedown by a party that controls only part
   of the relay population (replication, no single-point storage).

**Explicitly out of scope.** A **global passive adversary** — one able to
observe *all* links in the network simultaneously and correlate timing
across the entire graph — is not defended against. Several design choices
(persistent entry guards, epoch-beacon fetches, NAT traversal via STUN)
trade a small amount of exposure to such a global observer for much
stronger protection against the in-scope, participating adversary. This is
a deliberate trade-off, not an oversight, and it means AETHER's guarantees
are weaker than, e.g., a mix network built for global-adversary resistance.
Also out of scope at present: unsolicited first contact (v1 assumes both
parties have already exchanged a NodeId or contact string out of band; a
proper "inbox" channel for cold-contact is future work), and defense
against an adversary that has already compromised one of the two
communicating endpoints.

## Design Overview

AETHER's core protocol combines three mechanisms. Each addresses a
different way that metadata would otherwise leak.

### 1. Broadcast Veil (addressing without queries)

Instead of a recipient announcing interest in content (which a query itself
would leak) small encrypted **Hint** packets are gossip-flooded to every
node in the network. Each `HintPacket` (`core/src/protocol/hint.rs`) carries
a 4-byte `blind_tag` (a truncated HMAC over the shared secret and nonce,
used as a cheap pre-filter) and a ChaCha20-Poly1305-encrypted payload; a recipient can determine "is this for me?" only by attempting
local decryption — there is no network query a recipient makes, so no
observer sees who is looking for what.

Because Hints are flooded network-wide, they must stay cheap per-byte
(any field added there costs every node, network-wide) and must resist
flood/spam. This is enforced with a **SHA-256 proof-of-work** on each Hint
(`core/src/crypto/pow.rs`, `hint::seal_pow`/`verify_pow`). The code's own
rationale for choosing SHA-256 specifically (rather than a memory-hard
function) is notable: because every node verifies every Hint it receives,
verification cost dominates, and a cheaper hash function does not weaken
flood resistance (which is set purely by the leading-zero-bit difficulty),
it only lowers the tax on honest senders. A separate, memory-hard function
(Argon2id) is used where verification is rare — see NodeId proof-of-work
below.

Flooding an origin point is itself a metadata leak (a gossip observer can
learn "this Hint first appeared at exit relay X"), so injection is further
hidden with **Dandelion++** (`core/src/net/dandelion.rs`): a Hint first
travels a short, single-successor "stem" phase before switching
probabilistically to normal broadcast ("fluff", probability 0.25 per
hop), per Fanti et al.'s Dandelion++ construction. The stem successor is
fixed for a 10-minute Dandelion epoch (re-drawing it per message would let
an intersection attack recover the source); this is unrelated to the daily
ring epoch described under Ring+K.

A related, smaller-scale timing correlation is addressed in
`core/src/mailbox/hint_release.rs`: an entry guard that watches "this IP
uploaded for duration D ending at time T" could still correlate that with
"a Hint appeared at T+ε" even though onion routing hides the exit relay's
identity from the guard. The code's mitigation deliberately does *not* use
an arbitrary fixed delay; it computes a release-delay window sized relative
to the locally-observable rate of *other* Hints (a property unique to
Broadcast Veil — every Hint reaches every node, so the ambient rate is
directly measurable) and skips delay entirely for small messages that are
already smaller than the noise floor of ordinary relay traffic.

### 2. Schrödinger Mailbox (storage without recipient-visible location)

Message bodies are Reed-Solomon sharded (`core/src/mailbox/sharding.rs`,
3 data shards + 2 parity shards, any 3 of 5 reconstruct the message). Each
shard `i` is placed at a ring position derived from
`H(mailbox_key ‖ s ‖ i)`, where `s` is the secret shared by sender and
recipient (the same secret that protects the associated Hint), and is
replicated to the `K = 5` holders nearest that position
(`K_REPLICAS` in `core/src/mailbox/schrodinger.rs`) — 25 holder slots per
message in total. A holder therefore sees only a ciphertext shard and has
no way to determine who the intended recipient is; without `s` it cannot
even tell private content from public-board content. No single holder ever
has the complete message. To censor a message, an adversary must make at
least 3 of the 5 shards unavailable, i.e. control *all* `K` replicas of
each of those shards.

Recipients fetch shards over 3-hop circuits (never a direct request to the
holder, which would expose the requester's IP to it) and receive them back
through **inbound tunnels** (see below) rather than a direct reply, so the
holder never learns the requester's address either.

Board content uses the same storage mechanism with the board ID in place
of `s`. Boards are identified by random 256-bit IDs, so a private board is
as hard to locate as a private mailbox. The few *built-in* public boards
ship their IDs with the client; for those, anyone (including an adversary)
can compute the holder positions — a deliberate trade-off for boards that
are meant to be public (see Known Limitations).

### 3. Ring+K (no DHT lookups)

Rather than a Kademlia-style iterative lookup — which inherently reveals
"who is looking for what" to the nodes queried along the path — every node
locally holds the full relay directory (`core/src/net/relay_list.rs`,
documented as scaling to roughly one million relay descriptors before
requiring hierarchy) and computes the K nearest holders for a given ring
position entirely locally (`core/src/net/ring.rs`). No query ever leaves
the node to answer "who holds X." Ring positions are derived as
`H(NodeId ‖ epoch_seed)` (relays) or `H(mailbox_key ‖ s ‖ i)` (shards).
The epoch seed can be rotated daily from a public randomness beacon (see
Epoch Beacon below) so that an adversary cannot grind NodeIds indefinitely
to land next to a target's position. **This rotation is currently opt-in
and off by default**; without it the seed is a fixed constant and
grinding resistance rests on NodeId proof-of-work alone.

### How the three compose

A sender computes the recipient's shared secret, shards and places the
body via Schrödinger Mailbox, floods a Hint that only the recipient can
recognize via Broadcast Veil, and does all network I/O for both over 3-hop
onion circuits so no relay observed along the way learns the sender's real
address. The recipient runs as a relay itself (Hints only flow between
relays), using a relay key that is separate from its messaging identity so
that its published relay address cannot be looked up from the NodeId
people send to; it sees every Hint that flows through the network (it has to, to find its own), decrypts the one
addressed to it, computes the same ring position via Ring+K, and fetches
the shards through its own circuit with replies routed back through an
inbound tunnel. At no point does any single relay see both "who is
addressed" and "what address they are reachable at," and no relay is ever
asked a lookup query that would reveal interest in a specific piece of
content.

## Supporting Components

- **3-hop onion routing with fixed-length headers** (`core/src/net/onion.rs`):
  a Sphinx-style construction (Danezis & Goldberg 2009) — fixed-size
  header regardless of hop count, per-packet ephemeral keys (so relays
  cannot link packets on the same circuit by static key), and
  per-purpose keys derived from the DH output via HKDF.
- **Persistent entry guards** (`core/src/net/guard.rs`): the code's stated
  rationale mirrors Tor's 2014 move to fixed guards — for a
  participating adversary with relay fraction f, randomizing the entry
  relay on every connection drives lifetime exposure probability toward
  1 as connection count grows; a small, persisted guard sample bounds
  exposure to a single initial draw instead.
  A sample of 3 guards is kept (`GUARD_SAMPLE_SIZE`), one is used, and the
  sample is rotated after 60 days (`GUARD_ROTATION_SECS`).
- **Inbound tunnels** (`core/src/net/tunnel.rs`), an I2P-style construction
  where the recipient builds a receive-only tunnel and only publishes the
  tunnel's gateway address, so a sender or holder replying to a request
  never learns the recipient's real address. Tunnel hops preserve packet
  length across the path (a fixed `[nonce][body]` shape) so adjacent
  observers cannot use length changes to infer tunnel position.
- **Signed relay descriptors with NodeId proof-of-work**
  (`core/src/net/relay_list.rs`): each descriptor is Ed25519-signed by the
  key matching its NodeId (preventing descriptor spoofing/impersonation)
  and the NodeId itself must satisfy an Argon2id proof-of-work
  (`core/src/crypto/pow.rs`), chosen specifically because it is
  memory-hard and verified only rarely (on new-peer registration), so
  raising its cost does not tax honest, ongoing operation the way raising
  Hint PoW would.
  Guard/relay selection explicitly ignores self-reported uptime (any Sybil
  node can lie about it) and instead weights on locally-observed tenure.
- **Fetch jitter and cover fetches** (`client/src/receive.rs`): real
  fetches are delayed by a random 0–60s jitter, and dummy ("cover") fetches
  are issued on an exponentially-distributed schedule, so an observer of
  fetch timing cannot distinguish "a real Hint was just received" from
  ambient cover traffic.
  Note for reviewers: this is jitter/cover traffic against a local
  timing observer, not a guarantee against a global adversary correlating
  fetch times across many vantage points (out of scope, see Threat Model).
- **X3DH + Double Ratchet for private messages** (`core/src/crypto/x3dh.rs`,
  `ratchet.rs`): asynchronous initial key agreement following the
  Signal X3DH design, feeding a Double Ratchet
  (https://signal.org/docs/specifications/doubleratchet/) implementation
  described in-code as following the Signal specification directly
  (KDF_RK = HKDF-SHA256, KDF_CK = HMAC-SHA256, ChaCha20-Poly1305 message
  encryption, skipped-message-key handling for out-of-order delivery).
  Motivation stated in-code: under this threat model (device seizure),
  a static pre-shared secret means one seizure decrypts *all* past
  messages; forward secrecy bounds that to messages after the last ratchet
  step. The X3DH implementation additionally combines X25519 with a Kyber768
  key encapsulation (round-3 Kyber via the `pqcrypto-kyber` crate, not the
  final ML-KEM / FIPS 203), i.e. a hybrid classical/post-quantum initial
  key agreement: the X25519 DH outputs and the KEM shared secret are
  concatenated after a 32-byte `0xFF` prefix (as in Signal's X3DH) and fed
  to HKDF-SHA256 (`kdf_sk` in `core/src/crypto/x3dh.rs`). Only this initial
  agreement is hybrid; the Double Ratchet that follows uses classical
  X25519. This is similar in spirit to Signal's PQXDH but is not PQXDH,
  and it has not been reviewed; it is a priority for cryptographic review.
- **Epoch beacon** (`core/src/net/epoch.rs`, **opt-in, off by default**):
  when enabled, ring positions mix in a seed rotated daily, drawn from the public drand ("League of Entropy")
  randomness beacon, specifically to stop an adversary from grinding
  NodeIds offline to land next to a target's ring position — a ground
  NodeId is invalidated at the next epoch rotation. As the code's own
  comments state, this only checks internal hash-chain consistency of the
  fetched value, not the drand BLS signature itself; authenticity
  currently rests on TLS to the drand endpoint, and a MITM on this fetch
  only harms the one node's own placement, not the network's grinding
  resistance broadly. Full BLS verification is listed as future
  hardening.
- **Boards identified by random 256-bit IDs** (`client/src/boards.rs`,
  `client/src/bbs.rs`): a classic threaded bulletin board where the board
  itself is a random ID rather than a guessable keyword (preventing
  dictionary enumeration of private boards), while a small set of
  built-in board IDs are shipped with the client as intentionally public.
  Within a board, per-thread posting identities are derived
  deterministically from a device secret and the thread ID and are
  Ed25519-signed, so an identity cannot be spoofed by another party,
  though (as the code itself notes) if the device secret is seized, past
  thread identities on that device become linkable in retrospect —
  this is why at-rest encryption of that secret matters.
- **At-rest encryption** for identity keys, contact/ratchet state, friend
  and board lists, talk history, and local mailbox data, gated behind a
  user-supplied passphrase (`core/src/storage/at_rest.rs`): Argon2id
  (32 MiB, 3 passes) derives the key and each value is sealed with
  ChaCha20-Poly1305 under a random nonce. Without a passphrase data is
  stored in plaintext; the GUI requires an explicit acknowledgement for
  that.
- **No-burn, access-extended TTL storage** (`core/src/mailbox/server.rs`):
  shard reads do not delete the shard (unlike a naive "burn on read"
  scheme, which would make popular content disappear fastest); reads
  extend the entry's lifetime instead, and expired entries are pruned
  lazily. Holders can also `reseed` and `republish` content they hold,
  which is how the design claims a late-joining subscriber can still
  discover content whose original publisher has since gone offline.

## Security Properties (Qualitative)

- No relay that only sees network traffic (not both communicating
  endpoints' local state) should be able to link a Hint's recipient to an
  IP address, absent controlling the recipient's own guard.
- No holder of a Schrödinger Mailbox shard should be able to determine the
  intended recipient of a private message, or the requester's IP when the
  content is fetched.
- Compromise of a device's persisted key material should not expose
  message content sent or received before the compromise (forward
  secrecy via Double Ratchet), and should not expose anything at all
  without also compromising the user's passphrase (at-rest encryption).
- A censor should not be able to prevent retrieval unless it makes at
  least 3 of a message's 5 shards unavailable, which requires controlling
  all 5 replicas of each of those shards (Reed-Solomon 3-of-5, with each
  shard replicated to `K = 5` holders).
- These are design intentions read from the code and its own comments,
  not properties established by a proof or by external review. Several of
  the mechanisms above (epoch beacon authenticity, guard rotation, cover
  traffic) are explicitly described in-code as partial mitigations rather
  than complete guarantees — see Known Limitations.

### Quantitative analysis

A quantitative treatment is in `docs/anonymity/analysis.md` (Japanese), with
every number reproducible by `python3 docs/anonymity/compute.py`. The models
assume adversarial relays placed independently with fraction `f`; they are
estimates under stated assumptions, not proofs. Headline figures at `f = 0.05`:

| Question | Result |
|---|---|
| Sender identified on a single circuit (guard and exit both adversarial) | `f² = 0.0025` |
| Sender identified at least once over 1 year / 3 years (guards rotate every 60 days, 10 circuits/day) | ≈ 0.30 / ≈ 0.62 |
| Private message censored (≥ 3 of 5 shards lost, each shard on `K = 5` holders) | ≈ 3 × 10⁻¹⁹ |
| Receiver anonymity set against passive observers | all relays (normalized entropy 1.0) |

The same analysis identified three weaknesses that dominate the overall
strength, all outside the three core mechanisms:

1. **Targeting publicly-computable positions.** Node positions do not depend
   on the NodeId proof-of-work, so an adversary can cheaply grind identities
   and pay the PoW only for those that land next to a known position. Taking
   over all `K` holders of a built-in board index or of a user's prekey
   bundle costs about `K` PoW solutions (≈ 90 CPU-seconds) regardless of
   network size. Planned fix: holder eligibility requires presence before the
   epoch seed was published, with the epoch beacon enabled by default.
2. **Receiver confirmation by a malicious sender.** An adversary who sends a
   message (and so knows when its Hint was released) and can observe a
   suspect's traffic timing gains ≈ 1 bit per message against the current
   0–60 s fetch jitter and Poisson cover fetches (mean 90 s): about 16
   messages identify the recipient among 1,000 suspects with 99% confidence.
   Planned fix: constant-rate fetch slots, where real fetches replace cover
   fetches, making the fetch schedule independent of message arrival.
3. **Cumulative guard exposure.** Persistent guards prevent the rapid
   convergence of per-circuit entry selection, but guard rotation still
   accumulates risk over years (table above). Reducing the effective `f`
   (Sybil and eclipse resistance) is the main lever.

## Known Limitations and Open Problems

- **Sybil resistance.** NodeId proof-of-work (Argon2id) and relay-descriptor
  signatures make identity creation *costly*, not *bounded*. There is no
  mechanism limiting the absolute number of identities an adversary with
  sufficient compute can create; several other mitigations (guard
  weighting by observed tenure, not self-reported uptime; epoch rotation
  invalidating grinding) reduce the value of a large Sybil population but
  do not cap it.
- **Eclipse attacks / directory consistency.** Every node holds a local
  copy of the full relay directory (Ring+K), which avoids DHT-style query
  leakage, but the design does not yet specify a mechanism ensuring all
  honest nodes converge on the *same* directory contents, or detecting a
  node that has been fed a manipulated subset of descriptors (a classic
  eclipse setup). This is listed in the repository's own roadmap as
  unresolved.
- **Bootstrap seeds.** Joining the network currently requires knowing at
  least one existing relay's address out of band (a seed). There is no
  in-protocol bootstrap discovery, and no analysis yet of what an
  adversary who controls or observes the commonly-shared seed list can
  learn or manipulate.
- **Scalability of flooding.** Broadcast Veil sends every Hint to every
  node; the relay directory itself is documented as scaling to roughly a
  million descriptors before requiring hierarchy. Neither the flooding
  cost nor the directory-size ceiling has been validated at any scale
  beyond small local test networks.
- **Epoch beacon.** Rotation is off by default. When enabled, the drand
  fetch is integrity-checked but not signature-verified, and the fetch
  itself goes directly to a public HTTPS endpoint (a weak fingerprint);
  routing it through a circuit is future work.
- **No external audit.** The cryptographic and protocol design has not
  been reviewed by anyone outside the project. Several components
  (notably the hybrid X25519/Kyber768 X3DH combiner) are novel
  compositions of standard primitives and specifically need independent
  cryptographic review before being trusted.
- **Cold-contact / unsolicited messages.** The current implementation
  assumes both parties already share a NodeId or contact string; there is
  no anonymous "first contact" inbox yet (tracked as future work in the
  project's own roadmap).
- **No large-scale or real-NAT testing.** Testing to date has been on
  local test networks; behavior under real-world NAT diversity and at
  meaningful node counts is unverified.

## Status

**AETHER is experimental and has not been security-audited. Do not rely on
it for anything where real safety depends on your identity, your
recipient's identity, or your content remaining hidden.** It is a research
project intended to be evaluated, attacked, and improved before anyone
treats it as production-grade.

## How to Help

- **Design and protocol review.** Read the mechanisms above against the
  code (paths are given throughout this document) and point out where the
  implementation diverges from the stated design, or where the design
  itself has a gap.
- **Cryptographic review**, in particular of: the X3DH + Kyber768 hybrid
  key agreement, the Double Ratchet implementation, the Sphinx-style
  onion header construction, and the at-rest encryption scheme.
- **Run a test-network seed node**, ideally in a jurisdiction different
  from other existing seeds, to help evaluate real-world NAT and network
  diversity and to reduce reliance on any single bootstrap point. This is
  a test network for evaluation, not a production deployment — see
  Status above.
- **Report design gaps**, especially around Sybil resistance, eclipse
  attacks, and bootstrap trust, which are open problems above rather than
  solved ones.
