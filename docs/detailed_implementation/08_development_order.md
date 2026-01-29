## Part 8: 開発順序（ステップバイステップ）

### Phase 1: 基盤構築 (Week 1-2)

```
Day 1-2: プロジェクト初期化
├── [ ] Cargo.toml (workspace)
├── [ ] core/Cargo.toml
├── [ ] cli/Cargo.toml
├── [ ] core/src/lib.rs (空のmod宣言)
└── [ ] core/src/error.rs

Day 3-4: QUIC基盤
├── [ ] core/src/net/mod.rs
├── [ ] core/src/net/quic.rs
│   ├── QuicServer (自己署名証明書生成、accept)
│   └── QuicClient (connect)
└── [ ] cli: `chat` コマンド (localhost同士でテスト)

Day 5-7: NAT越え
├── [ ] core/src/net/stun.rs
│   └── StunResolver (Google STUN使用)
└── [ ] cli: 異なるネットワーク間でchatテスト
```

### Phase 2: 暗号化 (Week 3-4)

```
Day 8-10: 基本暗号
├── [ ] core/src/crypto/mod.rs
├── [ ] core/src/crypto/identity.rs
├── [ ] core/src/crypto/aead.rs
└── [ ] テスト: Ed25519署名、ChaCha20暗号化

Day 11-14: ハイブリッドKEM & Double Ratchet
├── [ ] core/src/crypto/kem.rs
├── [ ] core/src/crypto/ratchet.rs
└── [ ] テスト: 2者間でDouble Ratchetメッセージ交換
```

### Phase 3: Mailbox (Week 5-6)

```
Day 15-17: シャーディング
├── [ ] core/src/mailbox/mod.rs
├── [ ] core/src/mailbox/sharding.rs
└── [ ] テスト: Reed-Solomon encode/decode

Day 18-21: Mailboxサーバー
├── [ ] core/src/mailbox/server.rs
├── [ ] cli: `mailbox` コマンド
└── [ ] テスト: PUT/GET/LIST/DELETE

Day 22-24: Mailboxクライアント
├── [ ] core/src/mailbox/client.rs
├── [ ] cli: `send` / `recv` コマンド
└── [ ] テスト: オフラインメッセージング
```

### Phase 4: 分散ネットワーク (Week 7-8)

```
Day 25-28: DHT
├── [ ] core/src/dht/mod.rs
├── [ ] core/src/dht/kbucket.rs
├── [ ] core/src/dht/rpc.rs
└── [ ] テスト: Bootstrap、FIND_NODE

Day 29-32: Onion Routing
├── [ ] core/src/net/onion.rs
└── [ ] テスト: 3-Hop経由での通信
```

### Phase 5: ステルス化 (Week 9-10)

```
Day 33-35: Traffic Shaping
├── [ ] core/src/net/shaper.rs
└── [ ] Wiresharkで検証

Day 36-38: ローカルストレージ
├── [ ] core/src/storage/local_db.rs
├── [ ] core/src/storage/keystore.rs
└── [ ] テスト: 暗号化DB、PIN管理
```

### Phase 6: 統合 (Week 11-12)

```
Day 39-42: 全コンポーネント統合
├── [ ] cli: 全コマンドの統合テスト
└── [ ] E2Eテスト: Alice → Mailbox → Bob

Day 43-45: ドキュメント & リファクタリング
├── [ ] READMEの整備
├── [ ] rustdocコメント追加
└── [ ] コード整理
```

---

