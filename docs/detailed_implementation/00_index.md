# Project AETHER 超詳細実装計画書

このドキュメントは参照しやすくするため、以下のファイルに分割されています。

## 目次

| # | ファイル | 内容 |
|:--|:--|:--|
| 1 | [01_project_structure.md](./01_project_structure.md) | プロジェクト構造と初期セットアップ |
| 2 | [02_core_base.md](./02_core_base.md) | core/src 基盤ファイル |
| 3 | [03_net_module.md](./03_net_module.md) | net/ モジュール（ネットワーク層） |
| 4 | [04_crypto_module.md](./04_crypto_module.md) | crypto/ モジュール（暗号層） |
| 5 | [05_mailbox_module.md](./05_mailbox_module.md) | mailbox/ モジュール（分散ストレージ層） |
| 6 | [06_dht_storage_protocol.md](./06_dht_storage_protocol.md) | dht/, storage/, protocol/ モジュール |
| 7 | [07_cli.md](./07_cli.md) | cli/ 実装 |
| 8 | [08_development_order.md](./08_development_order.md) | 開発順序（ステップバイステップ） |
| 9 | [09_dataflow.md](./09_dataflow.md) | データフロー図 |
| 10 | [10_architecture_revision.md](./10_architecture_revision.md) | アーキテクチャ改訂 (2026-01-28) |
| 11 | [11_schrodinger_mailbox.md](./11_schrodinger_mailbox.md) | シュレーディンガーMailbox |
| 12 | [12_relay_network.md](./12_relay_network.md) | Relay Network |
| 13 | [13_latency_analysis.md](./13_latency_analysis.md) | 遅延分析 |
| 14 | [14_updated_dataflow.md](./14_updated_dataflow.md) | 更新されたデータフロー |
| 15 | [15_remaining_issues.md](./15_remaining_issues.md) | 残課題 |
| 16 | [16_next_actions.md](./16_next_actions.md) | 次のアクション |
| **17** | [17_server_side.md](./17_server_side.md) | **サーバーサイド実装（Router/Mailbox/Gossip）** |

---

元の統合ファイル: [../detailed_implementation.md](../detailed_implementation.md)
