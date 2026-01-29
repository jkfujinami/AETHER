## Part 14: 更新されたデータフロー

### 14.1 メッセージ送信フロー（シュレーディンガー方式）

```
Alice                           Relay Network              Mailbox/Gossip               Bob
  |                                   |                         |                        |
  |-- (1) 3-Hop回路構築 ------------->|                         |                        |
  |                                   |                         |                        |
  |-- (2) Nonce生成 ------------------|                         |                        |
  |      Mailbox_Key = SHA256(Nonce)  |                         |                        |
  |                                   |                         |                        |
  |-- (3) メッセージ暗号化 ------------|                         |                        |
  |      ChaCha20Poly1305(SharedSecret)|                        |                        |
  |                                   |                         |                        |
  |-- (4) PUT(Mailbox_Key, Encrypted) via Onion --------------->| Mailbox               |
  |                                   |                         | [ランダムKeyとして保存]|
  |                                   |                         |                        |
  |-- (5) Hint生成 -------------------|                         |                        |
  |      Enc(SharedSecret, Nonce||ID) |                         |                        |
  |                                   |                         |                        |
  |-- (6) Gossip broadcast(Hint) via Onion -------------------->| Gossip Network        |
  |                                   |                         |      ↓                |
  |                                   |                         | [全ノードに拡散]       |
  |                                   |                         |      ↓                |
  |                                   |                         |<----- Hint到着 ------>|
```

### 14.2 メッセージ受信フロー（シュレーディンガー方式）

```
Bob                             Relay Network              Mailbox/Gossip
  |                                   |                         |
  |<-- (1) Gossip経由でHint受信 ------|-------------------------|
  |                                   |                         |
  |-- (2) Blind Tagでフィルタリング --|                         |
  |      → 自分のコンタクトと一致？   |                         |
  |                                   |                         |
  |-- (3) Hint復号 -------------------|                         |
  |      → Nonce取得                  |                         |
  |                                   |                         |
  |-- (4) Mailbox_Key = SHA256(Nonce) |                         |
  |                                   |                         |
  |-- (5) GET(Mailbox_Key) via Onion ----------------------->| Mailbox
  |                                   |                      | [ランダムKeyで検索]
  |<-- (6) Encrypted Message --------|<-------------------------|
  |                                   |                         |
  |-- (7) メッセージ復号 -------------|                         |
  |      ChaCha20Poly1305(SharedSecret)|                        |
  |                                   |                         |
  |-- (8) DELETE(Mailbox_Key) via Onion -------------------->| Mailbox
  |                                   |                      | [Burn-on-Read]
```

---

