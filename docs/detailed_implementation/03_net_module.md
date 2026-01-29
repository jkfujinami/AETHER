## Part 3: net/ モジュール（ネットワーク層）

### 3.1 `core/src/net/mod.rs`

**役割**: netモジュール配下のサブモジュールを公開

```rust
pub mod quic;
pub mod stun;
pub mod onion;
pub mod shaper;

pub use quic::{QuicClient, QuicServer};
pub use stun::StunResolver;
pub use onion::OnionRouter;
pub use shaper::TrafficShaper;
```

---

### 3.2 `core/src/net/quic.rs` - QUIC接続管理

**役割**: `quinn` を使ったQUIC通信の基盤

**主要な構造体・関数**:

#### `QuicServer`
- `new(config: &Config) -> Result<Self>`: サーバーインスタンス生成
- `start(&self) -> Result<()>`: 指定ポートでリッスン開始
- `accept(&self) -> Result<QuicConnection>`: 新規接続を受け入れ
- 内部で自己署名証明書を `rcgen` で生成

#### `QuicClient`
- `connect(addr: SocketAddr, server_name: &str) -> Result<QuicConnection>`: 接続確立
- 証明書検証をスキップする設定（P2Pなので自己署名OK）

#### `QuicConnection` (共通)
- `send(&self, data: &[u8]) -> Result<()>`: データ送信
- `recv(&self) -> Result<Vec<u8>>`: データ受信
- `open_bi_stream() -> Result<(SendStream, RecvStream)>`: 双方向ストリーム開設
- `close(&self)`: 接続クローズ

**処理フロー**:
1. サーバー/クライアント双方で `rustls` の設定を構築
2. `quinn::Endpoint` を作成
3. ハンドシェイク完了後、双方向ストリームでデータ送受信

---

### 3.3 `core/src/net/stun.rs` - NAT越え (STUN)

**役割**: STUNプロトコルで自分のグローバルIP/ポートを特定

**主要な構造体・関数**:

#### `StunResolver`
- `new(stun_servers: Vec<String>) -> Self`
- `resolve() -> Result<SocketAddr>`: 自分の外部アドレスを取得

**処理フロー**:
1. 複数のSTUNサーバー（Google, Cloudflare等）にBindingリクエストを送信
2. レスポンスから `XOR-MAPPED-ADDRESS` を抽出
3. 複数サーバーの結果を比較し、一致すれば信頼できる外部アドレスとして返す

**補足**:
- UDP Hole Punchingの前提条件として使用
- Symmetric NAT環境では機能しない可能性あり（将来的にTURNフォールバックを検討）

---

### 3.4 `core/src/net/onion.rs` - 3-Hop Onion Routing

**役割**: Tor風の多層暗号化で送信元IPを隠蔽

**主要な構造体**:

#### `OnionCircuit`
- 3つのHopノード情報と、各Hopとの共有秘密を保持

#### `OnionRouter`
- `build_circuit(dht: &Dht) -> Result<OnionCircuit>`:
  - DHTから3ノードを選択（異なるAS、高Node Age優先）
  - 各Hopと一時的なX25519鍵交換を実行
  - 共有秘密 `SS_1`, `SS_2`, `SS_3` を導出

- `send_through_circuit(circuit: &OnionCircuit, payload: &[u8], dest: SocketAddr) -> Result<()>`:
  1. Layer 3: `Enc(SS_3, payload)`
  2. Layer 2: `Enc(SS_2, [Hop3_addr | Layer3])`
  3. Layer 1: `Enc(SS_1, [Hop2_addr | Layer2])`
  4. Hop1に送信

#### `RelayNode` (リレーノード用)
- `handle_relay_packet(packet: &[u8]) -> Result<()>`:
  1. 自分の秘密鍵で最外層を復号
  2. 次のHopアドレスを取得
  3. 残りを次のHopに転送

---

### 3.5 `core/src/net/shaper.rs` - Traffic Shaping

**役割**: パケットをWebRTC/Zoomのビデオ通話に偽装

**主要な構造体**:

#### `TrafficShaper`
- `real_queue: mpsc::Sender<Vec<u8>>`: 実際に送りたいデータのキュー
- `conn: QuicConnection`: 送信先接続

#### `ShapingConfig`
```rust
struct ShapingConfig {
    fps: u32,                    // 30 or 60
    i_frame_interval_secs: f32,  // 2.0
    p_frame_avg_size: usize,     // 500 bytes
    p_frame_std_dev: usize,      // 200 bytes
    jitter_ms: u32,              // ±5ms
}
```

**処理フロー (`run()` ループ)**:
```
毎 33ms (30fps) ごとに:
  1. ジッター計算: 実際の待機時間 = 33ms ± rand(-5, +5)ms
  2. Iフレームタイミングか判定 (2秒ごと)
  3. if Iフレームタイミング:
       大きなパケット(5-15KB)を送信
     else if real_queueにデータあり:
       実データを送信（サイズがPフレームモデルより小さければパディング追加）
     else:
       ダミーパケット(Pフレームサイズ)を送信
```

**パケット構造**:
```
+--------+---------------+
| Flags  | Payload       |
| 1 byte | Variable      |
+--------+---------------+
Flags: 0x00=ダミー, 0x01=実データ
```
受信側はFlags=0x00のパケットを破棄

---

