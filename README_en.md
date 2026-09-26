# AETHER

**An experimental peer-to-peer protocol that hides metadata — who talks to whom, when, and how much — not just message content.**

Private messaging and public, threaded bulletin boards run on the same anonymity substrate. Written in Rust, with a CLI and a Tauri desktop app.

> ⚠️ **Experimental and unaudited.** This is a solo student project. Do not use it for anything where your safety depends on it. Reviews and attacks are very welcome.

- **Design document:** [`docs/whitepaper.md`](docs/whitepaper.md)
- **Quantitative anonymity analysis:** [`docs/anonymity/analysis_en.md`](docs/anonymity/analysis_en.md) (numbers reproducible with `python3 docs/anonymity/compute.py`)
- The main [README.md](README.md) and code comments are in Japanese.

## Core idea

AETHER combines three mechanisms:

| Mechanism | What it hides | How |
|---|---|---|
| **Broadcast Veil** | who the recipient is | Small encrypted *Hints* (SHA-256 PoW, Dandelion++ for the injection point) are flooded to every relay. Recipients detect their own messages by local trial decryption and never query the network. |
| **Schrödinger Mailbox** | where a message is stored, and what it says, from the storage nodes | Bodies are Reed-Solomon sharded (3-of-5) and each shard is replicated to 5 holders at ring positions only the sender and recipient can compute. Holders see only ciphertext. |
| **Ring+K** | who is looking for what | Every node holds the relay directory and computes the K nearest holders locally — there are no DHT lookup queries to observe. |

These run over:

- 3-hop onion routing with persistent guards and Sphinx-style fixed-length packets (every hop sees the same packet length)
- fixed-length inbound reply tunnels, so holders reply without learning the requester's address
- X3DH with a hybrid X25519 + Kyber768 initial key agreement (round-3 Kyber, not final ML-KEM), followed by a classical Double Ratchet
- signed relay descriptors, fetch jitter and cover fetches, and passphrase-based encryption at rest

## What it does and does not protect (short version)

At an adversarial relay fraction of `f = 0.05` (see the analysis for the assumptions):

- **Private message censored:** ≈ 3 × 10⁻¹⁹ (5 shards × 5 replicas)
- **Receiver anonymity against passive observers:** the whole relay set
- **Sender identified:** 0.0025 per circuit, but ≈ 0.30 over a year as guards rotate
- **Known weaknesses:** holder positions that are public (built-in boards, prekey bundles) can be targeted for about 90 CPU-seconds; a malicious *sender* who can watch a suspect's traffic timing can confirm the recipient in about 16 messages among 1,000 suspects; Sybil and eclipse resistance are open problems.
- **Out of scope:** a global passive adversary.

## Try it locally

Requires Rust 1.93+ (edition 2024). The GUI also needs Node.js.

```bash
# A local test network: 5 reachable relays on 127.0.0.1 (seed: 127.0.0.1:19001)
scripts/local-net.sh
```

**CLI**

```bash
cargo build --release
alias aether='target/release/aether-cli'

aether init                    # create your messaging identity (prints your NodeId)
aether id                      # show it again

# Stay online as a relay and receive messages / subscribe to a board
aether start --connect 127.0.0.1:19001 --subscribe 雑談

# Send a private message (no pre-shared secret needed; X3DH on first contact)
aether send --to <NodeId> --message "hello" --connect 127.0.0.1:19001

# Post to / read a board. "雑談" is the built-in general chat board;
# private boards are addressed as aether-board:<64 hex chars>
aether send   --board 雑談 --message "hi" --name "first thread" --connect 127.0.0.1:19001
aether search --board 雑談 --connect 127.0.0.1:19001
aether get    --board 雑談 --ref <ref> --connect 127.0.0.1:19001
```

Set `AETHER_PASSPHRASE` to encrypt keys, contacts and stored data at rest.

**Desktop app**

```bash
cd gui
npm install
npm run dev
```

Enter the seed address (`127.0.0.1:19001` for the local network) and join. See [`gui/README.md`](gui/README.md).

**Tests**

```bash
cargo test            # unit tests (heavy multi-node tests are #[ignore])
cargo test -p aether-client -- --ignored   # 3-hop end-to-end tests with in-process relays
```

## Repository layout

```
core/     protocol building blocks: onion, tunnels, gossip, Dandelion++, ring, relay directory,
          mailbox (sharding, storage), crypto (X3DH, ratchet, PoW), at-rest encryption
client/   the send / search / fetch / receive procedures shared by the CLI and the GUI
cli/      command-line interface
gui/      Tauri 2 desktop app (plain HTML/JS UI)
docs/     whitepaper, quantitative analysis
scripts/  local-net.sh — spin up a local test network
```

## How to help

- Review the design and the code against it, especially the X3DH + Kyber768 hybrid, the onion packet format, and the Ring+K approach.
- Look for network-level attacks, particularly on the relay directory (Sybil, eclipse) and on timing.
- Run a test-network node in a different network or country (use a VPS, not your home connection — the relay list is public).

Issues and pull requests are welcome.

## License

MIT OR Apache-2.0
