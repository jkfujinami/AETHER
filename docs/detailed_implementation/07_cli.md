## Part 7: cli/ 実装

### 7.1 `cli/src/main.rs` - CLIエントリポイント

**役割**: 開発・検証用のコマンドラインツール

**CLIコマンド構成 (clap)**:

```rust
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 新しいIDを生成
    Init,

    /// ピアに直接接続してチャット (Step 1検証用)
    Chat {
        #[arg(short, long)]
        peer: String,  // "IP:PORT" or "PEER_ID"
    },

    /// Mailboxサーバーを起動
    Mailbox {
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },

    /// メッセージ送信
    Send {
        #[arg(short, long)]
        to: String,     // 受信者のUser ID (hex)
        #[arg(short, long)]
        message: String,
    },

    /// 新着メッセージを確認
    Recv,

    /// ネットワーク情報を表示
    Info,
}
```

**各コマンドの処理**:

#### `init`
1. `Identity::generate()` で新しいEd25519鍵ペアを生成
2. `~/.aether/identity.key` に秘密鍵を保存（Argon2で暗号化）
3. User ID（公開鍵ハッシュ）を表示

#### `chat`
1. STUNで自分の外部アドレスを取得
2. 指定されたピアにQUIC接続
3. REPLモードで入出力をやり取り
4. Traffic Shaping有効ならダミーパケットも送信

#### `mailbox`
1. `MailboxServer::new()` でサーバーインスタンス作成
2. 指定ポートでリッスン開始
3. PUT/GET/LIST/DELETEリクエストを処理

#### `send`
1. ローカルDBから受信者のPrekey Bundleを取得（なければDHTから）
2. X3DHハンドシェイク（初回のみ）
3. Double Ratchetでメッセージを暗号化
4. Reed-Solomonで5シャードに分割
5. 各シャードを受信者のMailboxにPUT

#### `recv`
1. 自分のMailboxリストを取得
2. 各MailboxにLIST→GETを実行
3. シャードを復元、Double Ratchetで復号
4. 成功したらDELETE（Burn-on-Read）

---

