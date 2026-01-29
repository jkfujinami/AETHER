## Part 13: 遅延分析

### 13.1 3-Hop Onion の遅延見積もり

```
各Hop の遅延（片道）:
  - 同一国内: 10-30ms
  - 近い大陸間: 50-80ms
  - 遠い大陸間: 100-150ms

3-Hop 片道:
  最良（国内）: 3 × 20ms = 60ms
  平均:         3 × 40ms = 120ms
  最悪（世界中）: 3 × 100ms = 300ms
```

### 13.2 パターン別遅延

| パターン | 構成 | 遅延 |
|:---|:---|:---|
| 直接配信 | 送信Onion(120ms) + Mailbox(10ms) + 受信Onion(120ms) | **約250ms** |
| Gossip配信 | 送信Onion(120ms) + Gossip(100ms) + 受信Onion(120ms) | **約340ms** |
| 最適化版 | 双方向Onion(240ms) | **約240ms** |

### 13.3 既存技術との比較

| 技術 | 遅延 | 備考 |
|:---|:---|:---|
| Telegram | 50-100ms | 中央サーバー経由 |
| Signal | 100-200ms | 中央サーバー経由 |
| Tor Hidden Service | 500-2000ms | 6-Hop (3+3) |
| I2P | 500-3000ms | Garlic Routing |
| **AETHER** | **200-350ms** | 3-Hop Onion |

---

