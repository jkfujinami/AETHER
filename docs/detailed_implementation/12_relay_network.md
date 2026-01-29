## Part 12: Relay Network

### 12.1 概要

Relay = 中継ノード。ユーザーは直接通信せず、Relay を経由する。

```
[通常の通信]
Alice (IP: 1.1.1.1) ────────────────→ Bob (IP: 2.2.2.2)
                    → Bobは Aliceの IP を知る

[Relay経由の通信]
Alice ───→ Relay1 ───→ Relay2 ───→ Relay3 ───→ 宛先
      Onion暗号化で各Relayは前後しか分からない
```

### 12.2 Relay Network 構成

```
┌─────────────────────────────────────────────────────────────┐
│              AETHER PUBLIC RELAY NETWORK                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  [ユーザー層]                                               │
│      │                                                      │
│      │ IP見える（入口Relayのみ）                           │
│      ▼                                                      │
│  [入口 Relay]  ←─── ハードコードまたは紹介で取得           │
│      │                                                      │
│      │ Onion暗号化                                          │
│      ▼                                                      │
│  [中間 Relay]                                               │
│      │                                                      │
│      │ Onion暗号化                                          │
│      ▼                                                      │
│  [出口 Relay]                                               │
│      │                                                      │
│      │ 宛先へ転送（E2EE維持）                              │
│      ▼                                                      │
│  [Mailbox / 相手のRelay]                                    │
│                                                             │
│  各Relayが知っていること:                                   │
│    入口: ユーザーのIP、次のRelay                           │
│    中間: 前のRelay、次のRelay                               │
│    出口: 前のRelay、宛先                                    │
│                                                             │
│  → 誰も全体像を知らない                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 12.3 Relay クライアント実装

```rust
// core/src/net/relay.rs

pub struct RelayClient {
    entry_relay: SocketAddr,
    circuit: Option<OnionCircuit>,
    quic_client: QuicClient,
}

impl RelayClient {
    /// 3-Hop回路を構築
    pub async fn build_circuit(&mut self) -> Result<()> {
        // 1. 入口Relayに接続
        let entry_conn = self.quic_client.connect(self.entry_relay).await?;

        // 2. 入口Relayから中間Relayリストを取得
        let middle_relays = self.fetch_relay_list(&entry_conn).await?;

        // 3. ランダムに中間・出口Relayを選択
        let middle = middle_relays.choose(&mut rand::thread_rng())?;
        let exit = middle_relays.choose(&mut rand::thread_rng())?;

        // 4. Onion回路を構築
        self.circuit = Some(OnionCircuit::new(
            self.entry_relay,
            *middle,
            *exit,
        ));

        Ok(())
    }

    /// Mailbox に PUT（Onion経由）
    pub async fn put(&self, key: &[u8; 32], value: &[u8]) -> Result<()> {
        let circuit = self.circuit.as_ref().ok_or(Error::NoCircuit)?;
        let onion_packet = circuit.wrap(b"PUT", key, value)?;
        self.send_onion(onion_packet).await
    }

    /// Mailbox から GET（Onion経由）
    pub async fn get(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        let circuit = self.circuit.as_ref().ok_or(Error::NoCircuit)?;
        let onion_packet = circuit.wrap(b"GET", key, &[])?;
        self.send_onion_and_receive(onion_packet).await
    }
}
```

### 12.4 Gossip Protocol

```rust
// core/src/net/gossip.rs

pub struct GossipClient {
    relay_client: RelayClient,
    seen_hints: LruCache<[u8; 32], ()>,  // 重複排除用
}

impl GossipClient {
    /// Hint をネットワークにブロードキャスト
    pub async fn broadcast(&self, hint: &HintPacket) -> Result<()> {
        // Relay 経由で送信（送信元IP秘匿）
        let packet = GossipPacket {
            ttl: 5,  // 最大5ホップまで伝播
            hint: hint.clone(),
        };
        self.relay_client.gossip_send(&packet).await
    }

    /// Hint を受信（Relay経由）
    pub async fn receive(&mut self) -> Result<HintPacket> {
        loop {
            let packet = self.relay_client.gossip_receive().await?;

            // 重複チェック
            let hint_hash = sha256(&packet.hint.to_bytes());
            if self.seen_hints.contains(&hint_hash) {
                continue;
            }
            self.seen_hints.put(hint_hash, ());

            return Ok(packet.hint);
        }
    }
}
```

### 12.5 Bootstrap（初回接続）

```rust
// 初回起動時のRelay発見

const BOOTSTRAP_RELAYS: &[&str] = &[
    "relay1.aether.network:8443",
    "relay2.aether.network:8443",
    "relay3.aether.network:8443",
];

impl RelayClient {
    pub async fn bootstrap() -> Result<Self> {
        // 1. ハードコードされたRelayに接続を試みる
        for relay_addr in BOOTSTRAP_RELAYS {
            if let Ok(client) = Self::connect(relay_addr).await {
                return Ok(client);
            }
        }

        // 2. 全て失敗した場合はエラー
        Err(Error::BootstrapFailed)
    }
}
```

---

