# AETHER: Anonymous Bulletin Boards and File Sharing with Hidden Storage Holders

**Status: beta (protocol version 3). Not audited. Do not rely on it where
real safety depends on staying anonymous.**

This document describes the design of AETHER, a peer-to-peer protocol for
anonymous public bulletin boards and file sharing, with private messaging as
a secondary, experimental feature. It is written for reviewers who want to
evaluate the design against the code, and for people considering running a
node. It describes what the code currently does. Where a mitigation is only
partial, or a property has a known limitation, this is stated explicitly
rather than glossed over. File paths are given so every claim can be checked.

## Abstract

AETHER is a network where people publish and fetch files and threaded board
posts without revealing who they are. Content
encryption is not the hard part. The hard part is metadata: who uploaded,
who downloaded, and — the lesson of Winny's prosecutions — **who is holding
which piece of content**. AETHER hides all three from observers who
participate in the network as relays, and from parties who later compel an
ISP to identify an IP address.

It combines:

1. **Onion-routed transport** (3-hop circuits) and **inbound tunnels**, so
   neither a holder nor a relay learns the IP of the person putting or
   fetching content.
2. **Hidden storage holders.** Content is held not by public relays but by
   holders identified by a storage identity (SID) unrelated to their IP.
   Holders claim positions on a hash ring with per-slot proof-of-work and
   publish signed **leaseSets** listing inbound tunnels that end at them. Only
   a holder's own entry guard ever learns its IP.
3. **Locally computed placement** instead of DHT lookups. Every node holds
   the relay directory and the leaseSets and computes who holds what itself,
   so no query reveals interest in a piece of content.
4. **Erasure-coded storage sized to the transport.** Large files use
   per-stripe Reed–Solomon codes whose redundancy is chosen from an assumed
   holder absence rate. Shards are exactly as large as fits one onion padding
   bucket, so little bandwidth is wasted.
5. **A flooded Hint layer** ("Broadcast Veil") for private messages, which
   lets a recipient learn that something was left for it without querying
   for it.

## Motivation

Winny-era file sharing showed that anonymity for the uploader is not enough.
Every participant who *caches* content becomes a target: if an observer can
compute where a known file's pieces live and map those locations to IP
addresses, every holder of that file can be listed, identified through an
ISP, and searched. Content encryption does not help, because the observer
already knows the content (it is the file they are looking for).

AETHER's goal is therefore to make the following unavailable to a
participating observer:

- the IP of the person who uploaded a file or wrote a post;
- the IP of anyone who fetched it;
- the IP of anyone who holds a piece of it;
- for private messages, the relationship between sender and recipient.

## Threat Model

**In scope.** The adversary can:

- run some fraction `f` of relays (a participating attacker);
- observe traffic at the vantage points it controls and correlate timing
  across them;
- know the content it is looking for, including the keys of public boards;
- compel an ISP to produce connection records for an IP address it has
  identified;
- seize a device and perform forensic analysis on its storage.

The design goals against this adversary are to:

1. prevent binding an IP address to an uploader, a downloader, a holder, or
   a message recipient through network observation;
2. make seized devices yield as little as possible: data at rest is
   encrypted under a passphrase, private messages have forward secrecy, and
   holders keep no per-request records;
3. keep content available when part of the holder population is offline or
   hostile, and make flooding the network costly.

**Out of scope.** A **global passive adversary**, able to watch all links at
once and correlate timing across the whole graph, is not defended against.
Persistent entry guards and STUN trade a little exposure to such an observer
for much better protection against the in-scope one.

Also out of scope: an adversary that has compromised one of the two parties
to a private conversation.

## Design Overview

### 1. Roles and participation modes

| Role | Who | Listed publicly? | Holds content? |
|---|---|---|---|
| Relay | Nodes with a public, verified-reachable address that opt in | Yes (signed descriptor) | **No.** Relays carry onion traffic, Hint backlogs, board indexes and leaseSets only |
| Hidden holder | Every resident node | **No** | Yes: encrypted shards, behind its own inbound tunnels |
| Client | Everyone | No | No |

The client offers three participation modes (`NodeMode` in
`client/src/config.rs`):

- **one-shot**: send, search and fetch only, with throwaway node keys;
- **resident** (the default): a hidden holder, contributing storage while
  running; not listed anywhere;
- **resident + relay**: additionally carries relay traffic and is listed.

Receiving private messages currently requires the third mode, because Hints
flow only between listed relays.

Relays refuse content: `MailboxPut`, `MailboxGet` and onion
`MailboxForward` arriving from the network are dropped
(`core/src/node/server.rs`). All content reaches holders through their
inbound tunnels.

### 2. Hidden holders

**Storage identity and slots.** A holder has an Ed25519 storage identity
(SID, `storage.key`), separate from any relay key or messaging identity.

- **Slots.** It claims `2^n` slots, one per GiB of contributed capacity,
  rounded down to a power of two so that capacity is not a fingerprint.
- **Slot proof-of-work.** Each slot requires an Argon2id proof-of-work
  (`core/src/net/lease_set.rs`). The PoW is over
  `slot_id = SHA256("aether_storage_slot_v1" ‖ SID ‖ index)`.
- **Slot position.** The slot's ring position is
  `H("aether_ring_storage_v1" ‖ slot_id ‖ pow_nonce ‖ epoch_seed)`.
- **Caching.** Solutions are cached on disk, so the PoW is paid once per
  SID.

**Inbound tunnels ("inlets").** A holder `H` builds three 3-hop tunnels
`GW_h → M_h → G_h → H` (`client/src/storage.rs`):

- **`G_h`** is the holder's own entry guard.
- **`M_h`** is a middle hop pinned for 60 days (a "vanguard"), so that a
  hostile middle cannot be re-drawn until it is.
- **`GW_h`** is drawn uniformly from reachable relays with no exclusion
  rule. Exclusion rules make the excluded set — the guard's neighbourhood —
  stand out over time.
- **Building.** Build instructions for `M_h` and `GW_h` are sent through
  the holder's own circuit exit, never directly from `H`.

**Keeping tunnels alive.**

- Relays forget tunnel registrations after 30 minutes. Holders re-send
  identical build instructions every 10 minutes. A relay accepts an
  identical registration as a renewal and refuses any different one, so
  tunnels cannot be hijacked.
- Holders probe each inlet through their own circuit every 5 minutes and
  rebuild inlets that fail twice.

**leaseSets.**

- **Contents.** A leaseSet lists the SID, the slot proofs, and up to three
  inlets (relay NodeId + tunnel id; **no IP addresses**). It carries an
  issue time rounded down to 10 minutes and a 3-hour expiry, and is signed
  by the SID.
- **Publishing.** A holder sends its leaseSet to three random relays
  through its circuit exit (`LeaseSetPublish`); from there it spreads by PEX.
  A relay never serves its own SID's leaseSet over PEX, which would link
  the SID to its address.
- **Renewal.** A new leaseSet with fresh inlets is issued at a random point
  between 1/3 and 2/3 of the old one's lifetime. Old inlets stay alive until
  the old leaseSet expires.
- **Checking on receipt.** Receivers verify the signature, the rounding,
  the expiry and the slot PoW. Slots already verified for the same SID are
  not re-checked, so a renewal costs one signature check rather than
  hundreds of Argon2 runs.

**Who sees what** when a shard is put on, or fetched from, a holder:

| Party | Uploader/fetcher IP | Holder IP | Content | Placement key |
|---|---|---|---|---|
| Uploader's guard | sees | — | — (onion, padded) | — |
| Uploader's middle | — | — | — | — |
| Uploader's exit | — | — (only `GW_h`) | encrypted shard | sees |
| `GW_h` | — | — | — (tunnel-encrypted) | — |
| `M_h` | — | — | — | — |
| `G_h` (holder's guard) | — | sees | — | — |
| Holder | — | itself | encrypted shard | sees |

Replies take the reverse route. The holder sends them through *its own*
circuit to the fetcher's inbound tunnel gateway, so that gateway never sees
the holder's IP either.

Two properties are checked by integration tests that record every packet's
sender and destination in a local network:

- **R5:** the only node that ever sends to a holder's address is that
  holder's guard (`client/tests/e2e_holder_put.rs`).
- **R8:** a resident's address never appears in any node's directory
  (`client/tests/e2e_holder_tunnel.rs`).

### 3. Placement without lookups

Kademlia-style iterative lookups reveal who is looking for what to the nodes
queried along the way. AETHER does not use them.

- Every node holds the relay directory and the current leaseSets
  (`core/src/net/relay_list.rs`) and computes the holders for a position
  locally.
- Holders are the nearest slots on the ring, **at most one slot per SID**,
  so replicas land on different people.
- Slot positions are kept in a sorted table and found by binary search;
  placement is computed per shard.

Positions of content are derived from the content key and a secret: the
shared secret of a private conversation, or the board key for public
content:

```
shard i of a small object: H("aether_ring_shard_v1" ‖ mailbox_key ‖ secret ‖ i)
shard of a large file:     H("aether_ring_shard_v1" ‖ SHA256(shard) ‖ board_key ‖ 0)
```

For private messages only the two parties know the secret, so nobody else
can compute where a message lives. For public boards, anyone with the board
key can compute positions. That is acceptable only because holders are
hidden: knowing *where* a shard lives no longer reveals *who* holds it.

### 4. Storage formats

**Small objects** (board posts, private message bodies, manifests) are
sealed, split with Reed–Solomon 3+2 (`core/src/mailbox/sharding.rs`) and
each shard is placed on 5 holders: 25 placements, any 3 shards reconstruct.

- **Shard sealing.** Shards carry an HMAC seal, so a hostile holder cannot
  stall reconstruction with forged shards.
- **Fetching.** Fetchers first ask the 3 data shards from the nearest
  holder only. They widen to parity and further replicas after 2 and 5
  seconds (`client/src/fetch.rs`, `hedge_plan`).

**Large files (format v2)** (`core/src/mailbox/sharding_v2.rs`,
`core/src/mailbox/chunk.rs`):

- **Chunks.** Chunks are sealed with convergent encryption
  (`nonce = H(secret ‖ plaintext)`). Re-publishing the same file to the
  same board yields the same shards.
- **Stripes.** Every 16 chunks form a stripe protected by RS(16+m).
  `m` is chosen per file as the smallest value giving whole-file
  availability ≥ 0.999 under an assumed holder absence rate `q = 0.3`.
  Each shard goes to **one** holder.
- **Shard size.** Shards are 262,051 bytes. That is the largest size for
  which both the put (exit → holder inlet) and the reply (holder → fetcher's
  tunnel) fit exactly into the 256 KiB onion padding bucket. Tests build the
  real packets to check it.
- **Manifest.** A Manifest lists every shard's SHA-256, so each shard is
  verified individually and forgeries are discarded.
- **Size buckets.** File sizes are rounded up to power-of-two buckets
  (minimum 1 MiB). Padding chunks are derived per file from the board key
  and the file hash. Downloaders request every data position individually,
  so the fetched volume matches the bucket. This stops a guard from
  narrowing down which file was fetched by its size. It is on by default and
  can be switched off.
- **Fetching.** Fetchers keep at most 4 stripes in flight. A request is
  considered lost if a later-numbered request overtook it 3 seconds ago, or
  if nothing arrived for 8 seconds. Each lost request adds exactly one
  parity request. Measured on a local network (debug build, 8 nodes, 4 MiB):

  | | uploaded / file size | downloaded / file size |
  |---|---|---|
  | before (v1: RS 3+2 × 5 replicas, all-replica requests) | 12.54× | 12.51× (and fetch failed 1 time in 2) |
  | v2 | 2.45× | 1.06× |

- **Size limit.** A Manifest must fit one sealed object, which caps a file
  at about 800 MB. A tree of manifests is future work.

**Keeping files alive.** Holders keep content for a week, extended whenever
it is fetched. Downloaders only fetch data shards, so parity would otherwise
age out even for popular files. After a successful download, the client
helps keep the file alive (on by default, can be switched off):

- it sends a small `HOLDER_TOUCH` that extends the lifetime of the parity
  shards it did not need;
- it rebuilds any shard whose request was lost and re-places it on the
  current holder.

### 5. Broadcast Veil (private messages)

Private message bodies are stored like any small object. The recipient
learns about them from a **Hint**:

- **The packet.** A Hint is a small encrypted packet flooded to every relay.
  It carries a 4-byte `blind_tag` (a truncated HMAC used as a cheap
  pre-filter) and a ChaCha20-Poly1305 payload
  (`core/src/protocol/hint.rs`). Only the recipient can recognise it, by
  attempting decryption locally, so no query reveals who is looking.
- **Spam resistance.** Hints carry a SHA-256 proof-of-work. Every relay
  verifies every Hint, so verification cost dominates; a cheap hash does not
  weaken flood resistance, which is set by the difficulty alone.
- **Hiding the injection point.** Injection is hidden with **Dandelion++**
  (`core/src/net/dandelion.rs`): a short stem phase with a successor fixed
  for 10 minutes, then fluff with probability 0.25 per hop.
- **Release delay.** Hint release is delayed by a window sized from the
  locally observed rate of other Hints (`core/src/mailbox/hint_release.rs`).
  Large file descriptors also pass through this window, with a minimum of
  one hour for uploads of 8 MiB or more.
  - The node's own measured relay throughput may only *lengthen* the delay.
    Anyone can route traffic through a relay to inflate the measurement,
    and noise they generated themselves does not hide anything from them.

### 6. Boards

- **Board identity.** Boards are identified by random 256-bit IDs
  (`client/src/boards.rs`). A few built-in boards ship their IDs and are
  public by design.
- **Board indexes.** A board's index is split into **daily pages**:
  `H("aether_index_page_v1" ‖ board_key ‖ day)`. This removes the
  256-entry ceiling a single index had and spreads load over many holder
  sets (`core/src/mailbox/index.rs`, `client/src/index_pages.rs`).
  - Readers query the last 7 days in parallel, asking 2 of the 5 page holders
    first.
  - Replying re-puts the thread's root record (unchanged, so no new PoW) into
    today's page, which keeps active threads visible — 2ch's "age".
  - Index records stay on relays as small public data. Each carries a PoW
    used for spam resistance and thread ranking.
- **Posting identities.** Per-thread posting IDs are derived from a random
  per-thread secret and the day, and are Ed25519-signed. A seized device
  therefore reveals at most which threads it used recently, not authorship of
  all past posts (`client/src/bbs.rs`).
- **Attachments.** Files can be attached to threads from the GUI.
  - File names supplied by the network are sanitised before being offered
    as a save name. Bidi-override and zero-width characters are removed from
    display, so that an executable cannot be dressed up as an image.
  - Downloaded files are never opened automatically.

## Supporting Components

- **Onion routing** (`core/src/net/onion.rs`): Sphinx-style fixed-length
  headers and per-packet ephemeral keys. Bodies are padded to power-of-two
  buckets up to 256 KiB, then 256 KiB steps.
- **Persistent entry guards** (`core/src/net/guard.rs`): a sample of 3,
  one used, rotated after 60 days. Selection weights locally observed
  tenure, never self-reported uptime.
- **Circuit pool** (`client/src/pull.rs`): two pre-built, round-trip-probed
  circuits wait in a pool. Each is used for one operation and discarded, so
  separate operations do not share an exit.
- **Signed relay descriptors with Argon2id NodeId proof-of-work**
  (`core/src/net/relay_list.rs`), at most 2 relays per IP (or IPv6 /64).
  IPv6 addresses are announced as fully reachable only after an external
  probe confirms it. Nodes reachable only via coordinated hole punching are
  not used for circuits or inlets until the punching initiator is wired up.
- **Protocol version check** (`core/src/protocol/wire.rs`): every frame
  carries a marker and a version. Mismatched frames are dropped and newer
  versions trigger an update notice. The notice can be triggered by anyone,
  so it tells users to verify updates at the official source.
- **Anti-flooding.**
  - **Upload limit at the guard.** A guard knows its clients' IPs anyway, so
    it limits uploads per sender IP (IPv6 per /64) to 1 MB/s with a 4 MB
    burst, for senders that are not listed relays. It applies backpressure
    instead of dropping (`core/src/net/rate_limit.rs`).
  - **Eviction order.** Holders split storage into a small-object slot (20%)
    and a large-object slot (80%) and evict by (times fetched, age). Garbage
    is never fetched, so it goes first.
  - **Self-certifying keys.** v2 shard keys carry a marker bit and must equal
    a hash of the shard. A holder rejects mismatches, so knowing a file in
    advance does not let anyone squat its storage locations with garbage.
- **Seizure hygiene.**
  - **Encryption at rest** (`core/src/storage/at_rest.rs`): Argon2id
    (32 MiB, 3 passes) and ChaCha20-Poly1305 under a passphrase, for
    identity, contacts and ratchet state, storage keys, board and talk data,
    and held shards.
  - **No delivery evidence.** A holder's per-entry fetch count is capped at
    3, so it cannot serve as evidence of how many times something was
    distributed.
  - **Nothing written to disk.** Replies to one's own requests live in
    memory only and are never written to disk. Relay throughput is measured
    as a per-minute moving average of byte counts only.
- **First contact for private messages: one-time invites**
  (`core/src/crypto/x3dh.rs`, `client/src/friends.rs`).
  - **What an invite is.** A "friend code" carries a one-time signed X25519
    prekey, a Kyber768 public key and an expiry (30 days). It is handed
    over out of band and consumed on first use.
  - **Why not prekey bundles.** Earlier versions published prekey bundles on
    the network. A bundle appearing shortly after start-up made the owner's
    online time — and hence IP — observable.
  - **Key agreement.** It is a hybrid X3DH: X25519 plus Kyber768 from
    `pqcrypto-kyber`, which is **round-3 Kyber, not the final ML-KEM /
    FIPS 203**. Only the initial agreement is hybrid. The Double Ratchet that
    follows (HKDF-SHA256 root KDF, HMAC-SHA256 chain KDF, ChaCha20-Poly1305)
    uses classical X25519. This combiner has not been reviewed.
- **Fetch jitter and cover fetches** (`client/src/receive.rs`): message
  fetches wait a uniform 0–60 s, and dummy fetches follow an exponential
  schedule (mean 90 s).
- **Epoch beacon** (`core/src/net/epoch.rs`, opt-in, off by default): ring
  positions can mix in a seed rotated daily from drand. The fetched value is
  hash-chain checked, but the BLS signature is not verified.

## Security Properties (Qualitative)

- No relay, holder or exit learns the IP of the person who puts or fetches
  content, absent controlling that person's guard *and* correlating timing
  at the far end.
- No party learns a holder's IP except that holder's own guard (tested as
  R5). Residents do not appear in any directory (tested as R8).
- A holder learns neither the recipient of a private message nor the
  requester of a shard.
- Seizing a device without its passphrase reveals nothing. With it, past
  private messages remain protected by the Double Ratchet. Holders keep no
  record of who fetched what, nor how often beyond "at least three times".
- Censoring a v2 file requires making a stripe lose more than `m` of its
  `16+m` shards, each on a different holder.

These are design intentions checked by tests on local networks, not
properties established by proof or external review.

### Quantitative analysis

`docs/anonymity/analysis.md` (Japanese) and the design notes compute
anonymity and availability under stated assumptions. Each number is
reproducible from the accompanying Python scripts. Some of those figures
predate hidden holders. In particular, the earlier observation that anyone
could cheaply grind identities to sit next to a public board's index or a
user's prekey bundle has changed shape:

- prekey bundles no longer exist;
- holder slots each require Argon2id proof-of-work;
- board indexes are split across daily pages.

Grinding slots near a *known* position is still possible at the cost of the
slot PoW. It yields a censorship position, not the IP of any user.

## Known Limitations and Open Problems

- **Holder liveness is observable.** Because holders serve content, anyone
  can tell whether a given SID is online by asking it for something it
  holds. Correlating that over weeks with ISP connection records can
  *confirm* that a suspected IP runs a given SID. It is not an efficient way
  to *find* holders, but it is a real confirmation attack. Delaying
  publication would not fix it. Rotating SIDs periodically (planned) limits
  how much can be accumulated.
- **Guard plus far-end correlation.** An uploader's (or downloader's) guard
  colluding with the holders or index holders at the other end can
  correlate time and volume, as in Tor. Release windows dilute this; they do
  not remove it.
- **Private messages are experimental.**
  - Receiving them requires being a listed relay.
  - The time a recipient fetches a body can reveal when it started up; a
    recipient-chosen fetch proxy is planned.
  - A compromised correspondent sees reply timing.
  - There is no cold-contact inbox: an invite must be exchanged out of band.
- **Public boards are readable by anyone with the board key.** For built-in
  boards that means everyone, including descriptors with file names and
  sizes. Attachment names are visible to all readers. Embedded metadata,
  such as EXIF location, is not stripped. On small private boards, fetches
  reveal that *some* member is reading.
- **Storage proof-of-work is not implemented yet.** Flooding is slowed by
  per-IP upload limits and eviction order, but a party with many IPs can
  still push out content that nobody fetches. Fetching one's own garbage
  raises its eviction rank.
- **Sybil and eclipse.** NodeId and slot PoW make identities costly, not
  bounded. There is no mechanism yet to ensure honest nodes converge on the
  same directory, or to detect a node fed a manipulated subset.
- **Scale.**
  - Every node holds the full relay directory and all leaseSets. This is
    fine for thousands of nodes; at Winny scale (hundreds of thousands
    online) it needs a different design.
  - Hints are flooded to every relay.
  - A full eviction scan reads the whole store when a slot fills.
- **Files over ~800 MB are refused.** Fetched files are held in memory.
- **Bootstrap.** Joining requires the address of a running relay, obtained
  out of band. No seed addresses are built into the software.
- **Testing.** Integration tests run on local networks only. Behaviour under
  real home NATs, and at meaningful node counts, is unverified.
- **No external audit.** In particular the hybrid X3DH combiner, the onion
  header construction and the storage formats need independent review.

## Status

AETHER is a beta. The protocol changed incompatibly between versions;
version 3 introduced hidden holders and dropped relay-held content. Expect
the test network to be reset. Do not rely on it where real safety depends on
staying anonymous.

## How to Help

- **Review the design against the code.** Paths are given throughout this
  document. Point out where the implementation diverges from what is
  described here, or where the design itself has a gap.
- **Cryptographic review**, especially of:
  - the X25519 + Kyber768 X3DH combiner;
  - the Double Ratchet implementation;
  - the Sphinx-style onion headers;
  - the at-rest encryption.
- **Attack the hidden-holder layer.** Look for ways to link an SID to an IP,
  to enumerate holders of known content, or to make a holder's guard the
  sender of something it should not send.
- **Run a relay** on a public address (`aether start --relay`) in a test
  network, to help measure real NAT behaviour and throughput.
