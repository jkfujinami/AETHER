# Project AETHER 実装計画書 (Implementation Plan)

## 1. システム構成・技術スタック

コアロジックは全てRustで記述し、メモリ安全性とパフォーマンスを確保する。

| コンポーネント | 採用技術 / クレート | 選定理由 |
| :--- | :--- | :--- |
| **非同期ランタイム** | `tokio` | I/Oバウンド処理のデファクトスタンダード。 |
| **通信プロトコル** | `quinn` (QUIC) | 純正Rust実装。通信パラメータ（パケットサイズ等）の微調整が可能で、偽装工作に向いている。 |
| **耐量子暗号** | `kyberlib` (ML-KEM) | NIST標準化されたPQC。`no_std`対応で将来的な移植性が高い。 |
| **署名** | `ed25519-dalek` | 高速な署名検証。ID管理に使用。 |
| **データ分割** | `reed-solomon-erasure` | Erasure Codingの高速実装(SIMD対応)。Mailboxへのデータ分散に必須。 |
| **ローカルDB** | `sled` | Rust製の組み込みKVS。バイナリデータの保存に最適。 |
| **GUI (将来)** | `Tauri v2` | フロントエンドにWeb技術を使いつつ、バックエンドはRustでセキュアに構築。モバイル対応も強化済み。 |

---

## 2. 段階的実装ロードマップ (Iterative Development)

「まずは動くCLI」を作り、そこへ徐々に機能を追加していくアプローチをとる。

### **Step 1: CLI Direct Talk & NAT Traversal (基盤)**
まずは暗号化や分散はおいておき、**「AとBが繋がり、会話できる」**ことを目指す。
*   **1-1. Local QUIC Chat**:
    *   CLIツールを作成。`localhost`同士で `quinn` を使って文字列を送受信する。
    *   自己署名証明書によるTLS 1.3通信の確立。
*   **1-2. UDP Hole Punching (NAT越え)**:
    *   STUNサーバー（Googleの公開STUN等）を使用し、お互いのグローバルIP/ポートを特定。
    *   ポート開放設定なしで、異なるネットワーク(家のWi-Fiとテザリング等)間のP2P接続を成功させる。

### **Step 2: Stealth Layer PoC (隠蔽)**
通信の中身を「WebRTC（Zoom）」に見せかけるための実験。
*   **2-1. Traffic Shaping**:
    *   パケット送信ロジックに「ダミーパケット注入機能」を追加。
    *   H.264ビデオ通信のような「可変ビットレート(VBR)」の統計モデル（Iフレーム/Pフレームの波）に合わせてパケットを流す。
*   **2-2. 検証**:
    *   Wiresharkでパケットをキャプチャし、Zoomの通信と比較して見分けがつかないか確認する。

### **Step 3: Cryptography & Mailbox (分散)**
ここで初めて「AETHERらしさ（非同期・匿名）」を実装する。
*   **3-1. End-to-End Encryption**:
    *   Kyber-768 + X25519 による鍵交換の実装。
    *   Double Ratchet アルゴリズムによるメッセージ暗号化。
*   **3-2. Dead Drop (Mailbox)**:
    *   メッセージを `reed-solomon` で5つの断片(3 data + 2 parity)に分割する処理の実装。
    *   Mailbox役のノード（CLI）を立ち上げ、そこへ断片をPUT/GETするロジックの実装。

### **Step 4: Platform Expansion (アプリ化)**
コアロジック(`core`)が固まったら、UIを乗せる。
*   **4-1. Web Frontend (Tauri)**:
    *   React等でチャットUIを作成し、Tauri経由でRustのコアロジックを叩く。
    *   まずは**Desktopアプリ**（Windows/Mac/Linux）として完成させる。
*   **4-2. Mobile Adaptation**:
    *   Tauri v2 のモバイルビルドを試し、Android/iOS実機で動作確認。
    *   バックグラウンド動作の制約など、モバイル特有の問題を解決する。

---

## 3. 詳細内部ロジック (Internal Logic Details)

ここは仕様書(`doc.md`)には記載しない、実装レベルの具体的なアルゴリズムとデータフロー定義である。

### **3.1 クライアントロジック (Sender / Receiver)**

ステートレスに見えるが、内部では複雑なステートマシンを持つ。

*   **送信フロー (Sender Phase):**
    1.  **Packetization**: メッセージを圧縮(Zstd) -> 暗号化(Double Ratchet)し、固定長またはVBRモデルに合わせたパディングを行う。
    2.  **Sharding**: 暗号化ペイロードを `reed-solomon-erasure` で $N$ 個（例: 5）の断片に分割。閾値 $K$（例: 3）を設定。
    3.  **Mailbox Discovery**: DHTを検索し、受信者($R$)が現在使用しているMailboxノードリスト $[M_1, M_2, ...]$ を取得。
    4.  **Parallel PUT**:
        *   3-Hop Onionサーキットを介して、各断片を対応するMailboxへ並列アップロード。
        *   **Retry Strategy**: タイムアウトやエラーが発生しても、$K$ 個以上のアップロード成功が確認できれば「送信完了」とみなす。残りは破棄してよい（冗長性が担保するため）。

*   **受信フロー (Receiver Phase):**
    1.  **Ghost Polling**:
        *   設定された間隔（Active時は数秒、Bg時は数分）で、自分のMailboxリストを巡回。
        *   `LIST` コマンドで「新規メッセージID一覧」を取得。
    2.  **Selective Fetch**:
        *   未取得のIDに対し `GET` を発行。
        *   $K$ 個の断片が集まった時点でダウンロードを打ち切り、残りの通信を節約する。
    3.  **Reconstruction & Verify**: 断片を結合し、AEADタグ（認証タグ）を検証。改竄があれば破棄。
    4.  **Atomic Burn**:
        *   正常に復号できた場合のみ、各Mailboxに対して署名付きの `DELETE` リクエスト（Receipt）を送信。
        *   「読んだら消す」をプロトコルレベルで徹底する。

### **3.2 Mailboxサーバーロジック**

Mailboxは「中身を知らない」「責任を持たない」単なる高性能なKVSとして実装する。

*   **Storage Schema (Sled DB構造)**:
    *   単一のSledインスタンスで全データを管理するが、Key設計で論理的に分離する。
    *   **Key**: `[Receiver_PubKey_Hash (32B)]` + `[Message_ID (16B)]` + `[Shard_Index (1B)]`
    *   **Value**: `[Timestamp (8B)]` + `[Encrypted_Shard_Blob]`
*   **Garbage Collection (自律浄化)**:
    *   別スレッド(`tokio::spawn`)で `Expiration Worker` が常駐。
    *   **TTL Check**: タイムスタンプが「48時間以上前」のレコードをスキャンして削除。
    *   **Capacity Check**: 特定の `Receiver_ID` プレフィックスを持つデータの総量が上限（例: 50MB）を超えた場合、タイムスタンプが古い順に削除 (FIFO)。
*   **Anti-Spam (PoW verifier)**:
    *   `PUT` リクエストには、リクエスト内容のハッシュに対する `Argon2` のソリューション添付を必須とする。
    *   難易度（Difficulty）は動的に調整しない（シンプルさ優先）。スマホで1秒程度かかる計算量を要求し、スパム攻撃のコストを高める。

### **3.3 Onion Routing (3-Hop Circuit)**

Tor風の多層暗号化を用いて、送信元IPを隠蔽する。

#### **サーキット構築の手順 (Circuit Building)**
1.  **Hop Selection**:
    *   DHTから、Senderとは異なるAS（自律システム）に属するノードを3つ選択する。
    *   選択基準: `Node Age` (稼働実績) が高いノード、かつ過去24時間の応答成功率が90%以上のノードを優先。
2.  **Ephemeral Key Exchange**:
    *   各Hopに対し、Senderは一時的なX25519キーペア $(ek_i, epk_i)$ を生成。
    *   Sender -> Hop1: `epk_1` を送信し、Hop1の公開鍵 $PK_1$ とDHを行い、共有秘密 $SS_1 = DH(ek_1, PK_1)$ を導出。
    *   同様に Sender -> Hop2 (Hop1経由), Sender -> Hop3 (Hop1, Hop2経由) で $SS_2$, $SS_3$ を確立。
3.  **Layered Encryption (玉ねぎ暗号化)**:
    *   Senderはペイロードを以下の順で暗号化する:
        *   Layer 3 (最内層): $Enc(SS_3, Payload)$ -> これがHop3で復号され、Mailboxへ到達。
        *   Layer 2: $Enc(SS_2, [Hop3_Address | Layer3_Ciphertext])$
        *   Layer 1 (最外層): $Enc(SS_1, [Hop2_Address | Layer2_Ciphertext])$
    *   各Hopは自分のLayerを剥がし、次のHopへ転送する。どのHopも最終的な宛先（Mailbox）を知らない。

#### **リレーノードの責務**
*   受け取ったパケットを復号し、`Next_Hop_Address` を確認して転送するのみ。
*   ログは一切取らない（ステートレス）。

### **3.4 Double Ratchet Protocol (E2EE)**

SignalプロトコルをベースにPQCハイブリッド化したDouble Ratchetの実装詳細。

#### **初期鍵交換 (X3DH-like Handshake with PQC)**
AliceがBobに初めてメッセージを送る場合:
1.  **Prekey Bundle (Bobが事前にDHTに公開)**:
    *   `IK_B` (Bob's Identity Key, Ed25519公開鍵)
    *   `SPK_B` (Bob's Signed Prekey, X25519公開鍵 + 署名)
    *   `OPK_B` (Bob's One-Time Prekey, X25519公開鍵, 任意数)
    *   `KEM_PK_B` (Bob's Kyber公開鍵)
2.  **Aliceの計算**:
    *   `DH1 = DH(IK_A_priv, SPK_B)`
    *   `DH2 = DH(EK_A_priv, IK_B)` (EK_A = Ephemeral Key)
    *   `DH3 = DH(EK_A_priv, SPK_B)`
    *   `DH4 = DH(EK_A_priv, OPK_B)` (あれば)
    *   `KEM_SS = Kyber.Encaps(KEM_PK_B)` -> `(ciphertext, shared_secret_kyber)`
    *   **Master Secret** = `HKDF(DH1 || DH2 || DH3 || DH4 || shared_secret_kyber)`
3.  **Initial Message**:
    *   AliceはBobに `IK_A`, `EK_A`, `KEM_ciphertext`, そして暗号化されたメッセージを送信。

#### **Symmetric Ratchet (メッセージ毎の鍵更新)**
*   各メッセージ送信毎に、Chain Key ($CK_n$) からMessage Key ($MK_n$) を導出し、送信後に $CK_{n+1}$ へ更新。
*   `MK_n = HMAC-SHA256(CK_n, 0x01)`
*   `CK_{n+1} = HMAC-SHA256(CK_n, 0x02)`

#### **DH Ratchet (相手からの返信時)**
*   相手から新しいDH公開鍵を受け取るたびに、Root Key ($RK$) を更新し、新しいChain Keyを導出。
*   これにより、過去の鍵が漏洩しても将来のメッセージは安全 (Forward Secrecy)。

#### **Out-of-Order Message Handling (順序逆転対策)**
*   受信者は、まだ使っていない古いChain Keyを一時的にキャッシュする（`skipped_keys` マップ）。
*   規定回数（例: 1000メッセージ）を超えたスキップ鍵は破棄し、復号不能にする（DoS対策）。

### **3.5 Traffic Shaping & Cover Traffic**

DPIによる「Zoomらしくない」判定を回避するためのパケット偽装。

#### **VBRモデルパラメータ (H.264/VP9 ビデオ通話模倣)**
| パラメータ | 値 (目安) | 備考 |
| :--- | :--- | :--- |
| **Iフレーム間隔** | 2秒 (60フレームごと) | 大きなパケット (5-15KB) がバースト的に発生。 |
| **Pフレームサイズ** | 平均500B, 標準偏差200B | 動きが少ないと小さく、多いと大きくなる。 |
| **パケット送信間隔** | 平均33ms (30fps相当), ジッター ±5ms | 一定すぎると検知されるため揺らぎを入れる。 |

#### **Traffic Shaper (送信スケジューラ)**
*   実装: `tokio::time::interval` と `rand` を組み合わせたステートマシン。
*   **Real Packet Queue**: 実際に送りたいデータが溜まるキュー。
*   **Dummy Packet Generator**: VBRモデルに基づき、ダミーパケット（ランダムバイト列）を生成。
*   **Scheduler Loop**:
    1.  33ms (±ジッター) ごとにティック。
    2.  Real Queueに送信待ちデータがあれば、それを送信。サイズがPフレームモデルより小さければパディングを追加。
    3.  Real Queueが空の場合、ダミーパケットを送信 (Cover Traffic)。
    4.  2秒ごとに「Iフレーム」として大きなダミーパケット (5KB程度) を注入。

### **3.6 Local Security (ローカルストレージ保護)**

端末からデータを「正しく」抜き出すための、複数PIN機構。

#### **鍵管理アーキテクチャ**
```
+---------------------+       +-------------------------+
|   User Input (PIN)  | ----> |   Key Derivation Logic  |
+---------------------+       +-------------------------+
                                      |
             +------------------------+------------------------+
             |                        |                        |
             v                        v                        v
      [ Normal PIN ]           [ Decoy PIN ]            [ Panic PIN ]
             |                        |                        |
             v                        v                        v
   Unlock Master Key (MK)     Unlock Decoy Key (DK)     Destroy MK!
             |                        |                        |
             v                        v                        v
   Decrypt Real DB             Decrypt Dummy DB          App Crash / Wipe
```

#### **Secure Enclave / StrongBox 連携 (Tier 1 デバイス)**
*   Master Key (MK) は Secure Enclave 内で生成され、外部に**絶対に出ない**。
*   アプリはPINを Enclave に渡し、Enclave 内部で「このPINはValidか？」を判定してもらう。
*   Enclave は「PINが5回連続で間違い」を検知したら、MKを内部的に破棄するよう設定可能。

#### **Argon2id フォールバック (Tier 2 デバイス)**
*   TPM/Enclave がない場合、Master Key はファイルに保存されるが、PINからArgon2idで派生した鍵 (PIN-DEK) でラップされる。
*   `Encrypted_MK = AES-GCM(Argon2id(PIN, salt, t=3, m=64MB, p=4), MK)`
*   この場合、PINの強度が重要なため、**8文字以上のパスフレーズを強制**する。

### **3.7 DHT & Peer Discovery (ノード発見)**

中央サーバーなしで他のノードを見つけるための分散ハッシュテーブル。

#### **Kademliaベースのルーティングテーブル**
*   各ノードは256ビットのNode ID (Ed25519公開鍵のSHA256ハッシュ) を持つ。
*   ルーティングテーブルは256個の「k-bucket」で構成される。
*   k-bucket $i$ には、自分のNode IDと「XOR距離」が $[2^i, 2^{i+1})$ の範囲にあるノードが格納される。

#### **Bootstrap問題 (最初の接続)**
*   ハードコードされた「Bootstrap Node」リスト（複数の公開ボランティアノード）を持つ。
*   初回起動時、これらのノードに接続し、自分のNode IDに近いノードを紹介してもらう（`FIND_NODE` RPC）。

#### **DHTに保存されるデータ**
| Key | Value |
| :--- | :--- |
| `Hash(UserPubKey)` | `[Mailbox_Node_ID_1, Mailbox_Node_ID_2, ...]` (このユーザーの現在のMailboxリスト) |
| `Hash(UserPubKey + "prekey")` | `Prekey Bundle` (Double Ratchet用の公開鍵バンドル) |

---

## 4. ワイヤープロトコル (Wire Protocol)

QUIC上でやり取りされるメッセージのバイナリフォーマット定義。

### **4.1 基本パケット構造**
全てのパケットは以下のヘッダを持つ:
```
+--------+--------+------------------+
| Type   |  Flags |  Payload Length  |  Payload (Variable)
| 1 byte | 1 byte |     4 bytes      |
+--------+--------+------------------+
```

### **4.2 メッセージタイプ一覧**
| Type (hex) | Name | Description |
| :--- | :--- | :--- |
| `0x01` | `ONION_RELAY` | 3-Hop Onion経由の転送パケット。Payloadは暗号化されたレイヤー。 |
| `0x10` | `MAILBOX_PUT` | Mailboxへの断片書き込みリクエスト。PoWソリューション含む。 |
| `0x11` | `MAILBOX_GET` | Mailboxからの断片読み出しリクエスト。 |
| `0x12` | `MAILBOX_LIST` | 特定Receiver宛ての新規メッセージID一覧取得。 |
| `0x13` | `MAILBOX_DELETE` | 署名付き削除命令 (Burn-on-Read)。 |
| `0x20` | `DHT_FIND_NODE` | Kademlia FIND_NODE RPC。 |
| `0x21` | `DHT_FIND_VALUE` | Kademlia FIND_VALUE RPC。 |
| `0x22` | `DHT_STORE` | Kademlia STORE RPC。 |
| `0x30` | `RATCHET_MSG` | Double Ratchetで暗号化されたエンドツーエンドメッセージ。 |

### **4.3 `MAILBOX_PUT` 詳細**
```
+---------------+----------------+---------------+----------------+----------------+
| Receiver_Hash | Message_ID     | Shard_Index   | PoW_Solution   | Shard_Data     |
| 32 bytes      | 16 bytes       | 1 byte        | 32 bytes       | Variable       |
+---------------+----------------+---------------+----------------+----------------+
```
*   `PoW_Solution`: `Argon2id(SHA256(Receiver_Hash || Message_ID || Shard_Index || Shard_Data), salt)` の出力の先頭32バイト。Mailboxはこれを検証し、難易度閾値を満たしているか確認する。

---

## 5. ディレクトリ構成案 (Monorepo)

```
AETHER/
├── Cargo.toml              # ワークスペース定義
├── core/                   # 全プラットフォーム共通のコアロジック (ライブラリ)
│   ├── src/
│   │   ├── lib.rs
│   │   ├── net/
│   │   │   ├── mod.rs
│   │   │   ├── quic.rs         # quinn wrapper, 接続管理
│   │   │   ├── stun.rs         # NAT越え (UDP Hole Punching)
│   │   │   ├── onion.rs        # 3-Hop Onion Routing ロジック
│   │   │   └── shaper.rs       # Traffic Shaping (VBRモデル)
│   │   ├── crypto/
│   │   │   ├── mod.rs
│   │   │   ├── identity.rs     # Ed25519 鍵ペア管理
│   │   │   ├── kem.rs          # Kyber-768 + X25519 ハイブリッドKEM
│   │   │   ├── ratchet.rs      # Double Ratchet ステートマシン
│   │   │   └── aead.rs         # ChaCha20-Poly1305 wrapper
│   │   ├── mailbox/
│   │   │   ├── mod.rs
│   │   │   ├── sharding.rs     # Reed-Solomon 分割/復元
│   │   │   ├── client.rs       # PUT/GET/LIST/DELETE クライアント
│   │   │   └── server.rs       # Mailboxサーバーロジック (Sled DB)
│   │   ├── dht/
│   │   │   ├── mod.rs
│   │   │   ├── kbucket.rs      # Kademlia k-bucket 実装
│   │   │   └── rpc.rs          # FIND_NODE, FIND_VALUE, STORE
│   │   ├── storage/
│   │   │   ├── mod.rs
│   │   │   ├── local_db.rs     # ローカル暗号化DB (sled + AEAD)
│   │   │   └── keystore.rs     # Secure Enclave / Argon2 Key管理
│   │   └── protocol/
│   │       ├── mod.rs
│   │       └── wire.rs         # パケットシリアライズ/デシリアライズ
├── cli/
│   └── src/main.rs             # 開発・検証用CUIツール
└── app/
    ├── src-tauri/              # Tauri Rustバックエンド
    └── src/                    # React/TypeScript フロントエンド
```

---

## 6. 次の手順 (Next Actions)

1.  **プロジェクト初期化**:
    ```bash
    mkdir AETHER && cd AETHER
    cargo new --lib core
    cargo new --bin cli
    # Cargo.toml を編集して [workspace] を設定
    ```
2.  **依存関係の追加 (`core/Cargo.toml`)**:
    ```toml
    [dependencies]
    tokio = { version = "1", features = ["full"] }
    quinn = "0.11"
    rustls = { version = "0.23", features = ["ring"] }
    ed25519-dalek = "2"
    x25519-dalek = "2"
    kyberlib = "0.8"
    reed-solomon-erasure = { version = "6", features = ["simd-accel"] }
    sled = "0.34"
    chacha20poly1305 = "0.10"
    argon2 = "0.5"
    rand = "0.8"
    sha2 = "0.10"
    hkdf = "0.12"
    zstd = "0.13"
    bincode = "1"
    ```
3.  **Step 1-1 (Local QUIC Chat) の実装を開始**:
    *   `core/src/net/quic.rs` を作成し、`quinn` を使った基本的なサーバー/クライアント接続を実装。
