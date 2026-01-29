# Project AETHER 実装メモ

**最終更新**: 2026-01-28 18:30

---

## 現在の実装状況

### ✅ 完了済み

| モジュール | ファイル | 状態 | 備考 |
|:---|:---|:---|:---|
| **Crypto** | `crypto/identity.rs` | ✅ | Ed25519 ID生成・署名 |
| | `crypto/cipher.rs` | ✅ | ChaCha20Poly1305 暗号化/復号 |
| | `crypto/key_exchange.rs` | ✅ | X25519 鍵交換 |
| **Net** | `net/quic.rs` | ✅ | QUIC Client/Server (quinn) |
| | `net/stun.rs` | ✅ | STUN NAT越え |
| | `net/onion.rs` | ✅ | Onion Routing (3-Hop) |
| | `net/relay.rs` | ✅ | Relay Client (送信側) |
| | `net/gossip.rs` | ✅ | Gossip Client (Hint拡散) |
| | `net/shaper.rs` | ✅ | Traffic Shaping (WebRTC偽装) |
| **Mailbox** | `mailbox/schrodinger.rs` | ✅ | シュレーディンガーMailbox |
| **Protocol** | `protocol/hint.rs` | ✅ | Hint パケット構造 |
| | `protocol/wire.rs` | ✅ | ワイヤーフォーマット |
| **Node** | `node/server.rs` | ✅ | QUIC Server 起動・接続受付 |
| | `node/router.rs` | 🔧 | Onion Packet 転送 (スケルトン) |
| **CLI** | `cli/src/main.rs` | ✅ | init, start, send コマンド |

### 🔧 実装中 / 残タスク

| タスク | 優先度 | 詳細 |
|:---|:---|:---|
| `Router` 実装 | **高** | Onion Packet の復号・転送ロジック |
| Gossip Server | **高** | 受信した Hint を他ノードへ拡散 |
| Mailbox PUT/GET | **中** | DHT or Local Storage へのメッセージ保存 |
| ピア接続 | **中** | `--connect` オプションの実装 |
| テスト拡充 | **低** | E2E テスト (Alice→Bob) |

---

## テスト結果

### Schrodinger Mailbox (`test_hint_exchange`)
```
test mailbox::schrodinger::tests::test_hint_exchange ... ok
```
- Alice がメッセージを暗号化し Hint 生成 → 成功
- Bob が Hint を復号して Mailbox Key 取得 → 成功
- Charlie (第三者) が復号失敗 → 正常動作

### Onion Routing (`test_onion_wrap_unwrap`)
```
test net::onion::tests::test_onion_wrap_unwrap ... ok
```
- 3層暗号化 → 各ホップで1層ずつ復号 → 最終ペイロード取得 → 成功

### Node Server 起動
```
$ cargo run -p aether-cli -- start --port 9000
Starting AETHER node on port 9000...
Node running. Press Ctrl+C to stop.
Node listening on 0.0.0.0:9000
```
- QUIC Server 正常起動 → 接続待機状態 → 成功

---

## アーキテクチャ概要

```
┌─────────────────────────────────────────────────────────────┐
│                    AETHER ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [User]                                                      │
│     │                                                        │
│     │ aether-cli (init / start / send)                      │
│     ▼                                                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  aether-core                                          │   │
│  │  ├── crypto/    暗号基盤 (Ed25519, X25519, ChaCha20) │   │
│  │  ├── net/       ネットワーク (QUIC, Onion, Gossip)   │   │
│  │  ├── mailbox/   シュレーディンガーMailbox            │   │
│  │  ├── node/      サーバーロジック (Router)            │   │
│  │  └── protocol/  ワイヤーフォーマット                 │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  [Network]                                                   │
│     │                                                        │
│     ├── Relay Node A ──┐                                    │
│     ├── Relay Node B ──┼── Gossip Mesh                      │
│     └── Relay Node C ──┘                                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 次回やること

1. **Router 本実装**
   - `node/router.rs` で Onion Packet を復号
   - 次ホップへ転送 or Payload 処理

2. **E2E テスト環境構築**
   - ターミナル1: `aether-cli start --port 9000`
   - ターミナル2: `aether-cli start --port 9001 --connect 127.0.0.1:9000`
   - ターミナル3: `aether-cli send --to <BOB_ID> --message "Hello"`

3. **Unused Warning 整理**
   - `cargo fix --lib -p aether-core` で自動修正

---

## 参考リンク

- [プロトコル仕様書](./doc.md)
- [詳細実装計画](./detailed_implementation.md)
- [Discovery Protocol 設計](./discovery_protocol_design.md)
# Project AETHER 実装メモ

**最終更新**: 2026-01-29

---

## 現在の実装状況

### ✅ 完了済み (Core Complete)

AETHERの中核機能となる `aether-core` は、通信・暗号化・トンネル制御において主要な実装と動作検証が完了しました。

| モジュール | 状態 | 詳細 |
|:---|:---|:---|
| **Crypto** | ✅ | Ed25519, X25519, ChaCha20Poly1305, 鍵交換ロジック |
| **Networking** | ✅ | QUIC (quinn), STUN, Traffic Shaping (VBRモデル) |
| **Tunneling** | ✅ | **Inbound Tunnel (Alice -> Relay -> GW)**, Onion Encryption, Layered Decryption |
| **Mailbox** | ✅ | Schrodinger Mailbox, Hint Packet |
| **Node Server** | ✅ | Packet Dispatcher, Context Management, Router Integration |
| **Code Quality** | ✅ | `cargo clippy` 警告ゼロ (Clean), テストカバレッジ向上 |

### � 実装中 / 未着手

| モジュール | 進捗 | 詳細 |
|:---|:---|:---|
| **CLI App** | 10% | スケルトンのみ。P2P会話デモのためのコマンド実装が必要。 |
| **HCN / DHT** | 0% | `dht/` が空。これから実装開始（最重要課題）。 |

---

## 2026-01-29 の修正・成果報告

### 1. コード品質改善 (Clippy Clean)
- `server.rs`: 引数過多 (`too_many_arguments`) を `PacketContext` 導入で解消。
- `schrodinger.rs`: ネストした `if let` を `let_chains` にリファクタリング。
- その他: 未使用変数・インポートの整理 (`_var` プレフィックス付与など)。

### 2. テストコードのバグ修正と動作検証
- **問題**: `tunnel.rs` の単体テスト (`test_tunnel_build_processing_decrypt`) が、コンパイルエラー（変数未定義）により長らく実行されておらず、修正後にロジックエラー（復号失敗）が発覚。
- **原因**: AETHERの設計では、Inbound TunnelのEndpoint (Alice) も `TunnelRelay` ロジックを経由して「最後の暗号化層」を追加する仕様だが、テストコードがこれを模倣していなかった（Aliceノード処理スキップ）ため、鍵と暗号化層の数が不一致（鍵3つ vs 暗号化2層）となっていた。
- **解決**: テストコードにAliceノード（Endpoint）としての暗号化処理を追加。`e2e_tunnel` と共に **完全な整合性** を確認。

### 3. E2E トンネル動作確認 (`test_inbound_tunnel_e2e`)
`Gateway` -> `Relay` -> `Alice (Endpoint)` の3ノード構成による統合テストに成功。

```
[DEBUG] Tunnel: reached endpoint (self), storing message for ID ...
Alice: Received 1 messages
DEBUG: [Decrypt] Layer 0 Key: ... Success (Size: 75)
DEBUG: [Decrypt] Layer 1 Key: ... Success (Size: 47)
DEBUG: [Decrypt] Layer 2 Key: ... Success (Size: 19)
Test Passed: Message decrypted successfully: "Hello Tunnel World!"
```
- Endpointも暗号化ループに参加し、3層の暗号化が正しく解除されることを実証。
- Relay経由の匿名通信が可能であることが証明された。

---

## 次回のアクション

### 1. CLIアプリの実装 (`cli/src/main.rs`)
- **目的**: 開発者が手元のPCで実際にメッセージを送り合えるようにする。
- **実装内容**:
    - `aether init`: Identityの永続化
    - `aether start --connect <IP>`: リレーへの接続とトンネル構築
    - REPLモード: `send <EndpointHash> <Msg>` で対話的に送信

### 2. DHT (Discovery) の実装 (`core/src/dht`)
- **目的**: IPアドレス直打ちではなく、ネットワークに参加してピアを発見できるようにする。
- **実装**:
    - `hierarchical_cell_network.md` に基づくセル管理とルーティング。
    - Bootstrapノードへの接続。

---

## アーキテクチャ概要 (Confirmed)

```
[Bob / Sender] --> [Tunnel Layer] --> [Gateway] --> [Relay] --> [Alice / Receiver]
                                                                        │
                                                                 (Endpoint Loop)
                                                                        ▼
                                                                 [Decryption]
```

Endpoint (Alice) 自身も Tunnel Relay として振る舞い、自分自身へ転送する際に最後の暗号化・カプセル化を行う特殊な設計（Loopback Tunnel）となっている。
これにより、Relay Nodeの実装を統一化し、トラフィック解析に対する耐性（Endpointでのトラフィックパターン隠蔽）を高めている。
