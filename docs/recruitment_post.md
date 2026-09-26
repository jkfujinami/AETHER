## Title

Looking for reviewers and test-network volunteers for AETHER, an experimental metadata-private messaging protocol (Rust)

## Body

I've been building AETHER, a peer-to-peer protocol for private messaging
and public bulletin-board-style content that tries to hide *metadata* —
who's talking to whom, from where, and when — not just message content.
It's a research/hobby project, written in Rust, and it is **not**
audited and **not** something anyone should rely on for real safety yet.
I'm posting because I'd like more eyes on the design before it gets any
more serious than that.

The rough approach: addressing happens through small encrypted "hints"
flooded to every node (so recipients find their own messages by local
decryption, never by querying the network for them), message bodies are
erasure-coded and stored at a location only the sender and recipient can
derive, and instead of a DHT lookup, every node holds the relay list
locally and computes the nearest holders itself — so nobody ever asks the
network "who has X." All of that runs over 3-hop onion circuits with
persistent entry guards. There's a longer write-up of the design and its
known gaps (Sybil resistance, eclipse/directory-consistency, bootstrap
trust, and more) if anyone wants the details.

**What would actually help right now:**

- Reading the design/threat model and pointing out where it's wrong,
  incomplete, or where the code doesn't match what it claims to do.
- Cryptographic review, especially of a hybrid classical/post-quantum
  key-agreement step and the forward-secrecy (Double Ratchet) wiring —
  this is exactly the kind of thing that shouldn't ship un-reviewed.
- Running a **test-network seed node**. There are no public seeds yet;
  the design wants several independently operated seeds in different
  networks and jurisdictions, so that no single operator can feed nodes a
  fake view of the network. Please read the note on risks below first.
- General adversarial thinking: if you can find a way to deanonymize a
  sender, holder, or recipient on the test network, I want to know about
  it.

**Please do not use this for anything where your safety depends on it.**
This is pre-audit, early-stage software, and a test network is exactly
that — a test network, not a production service.

**If you run a node:** its IP address is published in the relay list, so
anyone can see that the address runs this software. Use a VPS rather than
your home connection, and check what running an anonymity relay means
legally where you and the server are located.

Design write-up: <LINK TO whitepaper.md>
Code: <LINK TO REPOSITORY>

If you want to poke at the code, ask questions, or just tell me what's
obviously broken about the design, I'd genuinely appreciate it.

---

### Alternative titles

1. "AETHER: an experimental Rust protocol for hiding who's talking to whom, not just what they say — looking for reviewers"
2. "Building a metadata-private P2P messaging protocol in Rust — need cryptography reviewers and test-network volunteers"
3. "Early-stage anonymous messaging protocol (Rust, unaudited) — looking for design/crypto review and seed-node volunteers"

### Candidate subreddits

- **r/crypto** — technical, review-oriented crowd; generally fine with
  "here's my design, please critique it" posts as long as it's
  substantive and not a token/coin pitch. Low self-promotion friction for
  this kind of ask.
- **r/netsec** — welcomes offensive/defensive review requests; uncertain
  about current self-promotion rules (may want a writeup rather than a
  bare project link, and may be stricter about "vendor-y" framing) —
  uncertain, check sidebar/wiki before posting.
- **r/rust** — receptive to "I built X in Rust" posts, but the audience
  there is more about the language/implementation than the anonymity
  design; may draw fewer cryptography reviewers. Self-promotion is
  generally tolerated if the post is technical rather than a launch
  announcement — uncertain on current specifics.
- **r/privacy** — larger, more general audience; likely to be interested
  in the pitch but less likely to produce deep cryptographic review.
  Some general-privacy subs are wary of "new anonymity network" posts
  that read as unvetted claims — worth being extra explicit about the
  unaudited/experimental status. Uncertain on current self-promotion
  norms.
- **r/degoogle** or **r/selfhosted** — uncertain fit; likely low
  relevance and not recommended unless the framing shifts toward
  self-hosting a node specifically.
- **r/darknetplan** or similar mesh/decentralized-network communities —
  plausible fit for seed-node volunteers, but uncertain about current
  activity level and self-promotion norms — verify before posting.

Note: subreddit self-promotion rules change over time and are uncertain
where marked; check each subreddit's current rules/wiki before posting,
and consider leading with substance (the design writeup) rather than a
bare ask, since most of these communities are stricter about the latter.
