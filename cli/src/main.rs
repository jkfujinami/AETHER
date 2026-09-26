//! AETHER ノードの CLI
//!
//! ```text
//! aether init                        鍵を生成して保存する
//! aether start --connect <種ノード>   ネットワークに参加して常駐する
//! aether id                          保存済みの Node ID を表示する
//! ```

use aether_client::{
    AetherClient, Board, ClientConfig, ClientEvent, Contact, KeyFiles, MessageSource, NodeMode,
    PublicPost, RelayOptions, event_channel, parse_hex32,
};
use clap::{Parser, Subcommand};
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "aether", version)]
#[command(
    about = "AETHER ── 匿名 P2P（Winny 後継）",
    long_about = "AETHER 匿名 P2P ネットワークの CLI。\n\
私信（事前共有秘密）と公開共有（キーワード）を同じ匿名基盤に載せる。\n\
\n\
使用例:\n  \
aether init                                       鍵を生成\n  \
aether start --connect <種>:<port>                常駐（リレー / 受信）\n  \
aether start --subscribe 雑談                     板を購読して受信\n  \
\n  \
# 私信（相手と秘密を事前共有）\n  \
aether send --to <NodeId> --secret <hex> --message \"やあ\" --connect <種>\n  \
\n  \
# 公開：投稿・ファイル共有・掲示板\n  \
aether send --board 雑談 --message \"本文\" --connect <種>\n  \
aether send --board aether-board:<ID> --file movie.mkv --connect <種>\n  \
aether send --board 雑談 --message \"レス\" --reply-to <ref> --connect <種>\n  \
\n  \
# 発見・取得\n  \
aether search --board 雑談 --connect <種>\n  \
aether get --board 雑談 --ref <ref> --out movie.mkv --connect <種>"
)]
struct Cli {
    /// データディレクトリ（鍵・Mailbox・ガード情報）
    #[arg(long, default_value = "./aether-data", global = true)]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 鍵を生成して保存する
    Init {
        /// 既存の鍵を上書きする
        #[arg(long)]
        force: bool,
    },
    /// ネットワークに参加して常駐する
    Start {
        /// 待ち受けポート
        #[arg(short, long, default_value_t = 9000)]
        port: u16,

        /// 種ノードのアドレス（例: 203.0.113.1:9000）
        #[arg(short, long)]
        connect: Option<String>,

        /// 到達可能と宣言するアドレス
        ///
        /// 公開 IP や手動ポート開放で到達性が分かっている場合に指定する。
        /// 省略すると STUN で自動判定する。
        #[arg(long)]
        advertise: Option<String>,

        /// ルータへのポートマッピングを許可する
        ///
        /// **ルータのリース表に痕跡が残る**（既定は無効）。
        #[arg(long)]
        allow_port_mapping: bool,

        /// NodeId の PoW 難易度
        ///
        /// 高いほど Sybil 耐性が上がるが、起動時に1回だけその時間がかかる。
        #[arg(long, default_value_t = 16)]
        pow_difficulty: u32,

        /// 受信したい相手 `<NodeId hex>:<共有秘密 hex>`（複数指定可）
        ///
        /// **共有秘密は事前共有が前提。** X3DH は未実装。
        /// 1つでも指定すると受信用の Inbound Tunnel を張り、
        /// 自分宛ての Hint を手元で拾って本文を表示する。
        #[arg(long = "contact")]
        contacts: Vec<String>,

        /// 購読する板（公式の板の名前か aether-board:…、複数指定可）
        ///
        /// 指定すると、その板に書かれた投稿を拾って表示する。
        #[arg(long = "subscribe")]
        subscribe: Vec<String>,

        /// エポックビーコン（drand 由来の日次シード）を有効にする (3-4)
        ///
        /// 位置グラインディング対策。**網全体で揃える必要がある**（一部だけ有効にすると
        /// 保持者計算がずれて分裂する）。有効時は日次で drand へ HTTPS 取得する
        /// （弱いフィンガープリント）。
        #[arg(long)]
        epoch_beacon: bool,
    },
    /// メッセージを送る（私信 or 公開）
    ///
    /// 私信は `--to`＋`--secret`（事前共有）、板への書き込みは `--board`。
    Send {
        /// 宛先の Node ID (hex 64文字)。私信のとき指定
        ///
        /// `--secret` を省くと、相手の NodeId から**自動で鍵合意**する（3-1 ③）。
        #[arg(long)]
        to: Option<String>,

        /// 事前共有秘密 (hex 64文字)。私信で明示したいときだけ指定（省略時は自動鍵合意）
        #[arg(long)]
        secret: Option<String>,

        /// 書き込む板（公式の板の名前か aether-board:…）
        ///
        /// 板の ID を知る全員が読める（`--to`/`--secret` とは排他）。
        #[arg(long, conflicts_with_all = ["to", "secret"])]
        board: Option<String>,

        /// 本文（テキスト送信）。`--file` と排他
        #[arg(long, conflicts_with = "file")]
        message: Option<String>,

        /// 送信するファイルのパス（公開モードの大容量共有 / 2-4）。`--message` と排他
        ///
        /// 大きいファイルは自動でチャンク化され content-address で配置される
        /// （重複排除・並列取得）。公開モード専用。
        #[arg(long, requires = "board")]
        file: Option<String>,

        /// 表示名（公開モードで索引に載せるときの見出し。省略時は本文の先頭 or ファイル名）
        #[arg(long)]
        name: Option<String>,

        /// 返信先の投稿 ref (hex 64文字)。掲示板のスレッド返信（2-5）。省略で新規スレッド
        #[arg(long = "reply-to", requires = "board")]
        reply_to: Option<String>,

        /// 種ノード
        #[arg(short, long)]
        connect: String,

        /// 待ち受けポート（0 = OS 任せ）
        #[arg(short, long, default_value_t = 0)]
        port: u16,

        /// リレーが何台見つかるまで待つか
        #[arg(long, default_value_t = 3)]
        min_relays: usize,
    },
    /// 板の索引を引いて、スレッドを一覧する
    Search {
        /// 板（公式の板の名前か aether-board:…）
        #[arg(long)]
        board: String,

        /// 種ノード
        #[arg(short, long)]
        connect: String,

        /// 待ち受けポート（0 = OS 任せ）
        #[arg(short, long, default_value_t = 0)]
        port: u16,

        /// リレーが何台見つかるまで待つか
        #[arg(long, default_value_t = 3)]
        min_relays: usize,
    },
    /// 索引で見つけた投稿・ファイルの本体を取得する（板 + content ref）
    Get {
        /// 板（公式の板の名前か aether-board:…）
        #[arg(long)]
        board: String,

        /// 取得する content ref (hex 64文字、search の出力に対応)
        #[arg(long)]
        r#ref: String,

        /// 取得したファイルの保存先パス（省略時は本文をテキスト表示）
        #[arg(long)]
        out: Option<String>,

        /// 種ノード
        #[arg(short, long)]
        connect: String,

        /// 待ち受けポート（0 = OS 任せ）
        #[arg(short, long, default_value_t = 0)]
        port: u16,

        /// リレーが何台見つかるまで待つか
        #[arg(long, default_value_t = 3)]
        min_relays: usize,
    },
    /// 保存済みの Node ID を表示する
    Id,
}

/// `<NodeId hex>[:<共有秘密 hex>]` を分解する（秘密を省くと NodeId から自動鍵合意）
fn parse_contact(spec: &str) -> Result<Contact, Box<dyn Error>> {
    use aether_core::crypto::identity::NodeId;
    Ok(match spec.split_once(':') {
        Some((id, secret)) => Contact {
            node_id: NodeId(parse_hex32(id, "--contact の NodeId")?),
            secret: Some(parse_hex32(secret, "--contact の共有秘密")?),
        },
        None => Contact {
            node_id: NodeId(parse_hex32(spec, "--contact の NodeId")?),
            secret: None,
        },
    })
}

/// 保存時暗号化のパスフレーズ（環境変数 `AETHER_PASSPHRASE`）。空・未設定なら `None`
///
/// これ 1 つで identity.key・relay.key・KeyStore・mailbox.db をまとめて解錠する。
fn env_passphrase() -> Option<String> {
    std::env::var("AETHER_PASSPHRASE").ok().filter(|p| !p.is_empty())
}

/// 一回限りのクライアントとして網に参加する（送信・検索・取得）
async fn join_ephemeral(
    data_dir: PathBuf,
    port: u16,
    connect: &str,
    min_relays: usize,
) -> Result<Arc<AetherClient>, Box<dyn Error>> {
    println!("種ノード {} へ参加します。リレーを探しています...", connect);
    let events = event_channel();
    spawn_event_printer(events.subscribe());
    let client = AetherClient::start(
        ClientConfig {
            data_dir,
            passphrase: env_passphrase(),
            port,
            seed: Some(connect.parse()?),
            min_relays,
            mode: NodeMode::Ephemeral,
            network: Default::default(),
        },
        events,
    )
    .await?;
    client.wait_for_relays().await?;
    Ok(client)
}

/// クライアントのイベントを端末へ流す
fn spawn_event_printer(mut rx: tokio::sync::broadcast::Receiver<ClientEvent>) {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ClientEvent::Progress { message }) => println!("{}", message),
                Ok(ClientEvent::Warning { message }) => eprintln!("警告: {}", message),
                Ok(ClientEvent::SendStatus { .. }) => {}
                Ok(ClientEvent::Received { source, text }) => {
                    let from = match source {
                        MessageSource::Contact { node_id } => format!("contact {}", node_id),
                        MessageSource::Board { label } => format!("板「{}」", label),
                    };
                    println!("\n--- 受信 ({}) ---\n{}\n", from, text);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    eprintln!("表示が追いつかず {} 件のイベントを落としました", n)
                }
                Err(_) => return,
            }
        }
    });
}

/// 掲示板をスレッドごとに字下げして表示する（2-5 / 2-7）
///
/// 各行の `ref` はそのまま `get --ref` / `send --reply-to` に渡せる。
fn print_board(label: &str, board: &Board) {
    println!(
        "\n=== 「{}」: {} スレッド / {} 投稿（PoW ランク順）===",
        label.trim(),
        board.threads.len(),
        board.post_count()
    );
    for thread in &board.threads {
        for post in &thread.posts {
            let indent = "  ".repeat(post.depth);
            let marker = if post.depth == 0 { "●" } else { "└─" };
            let tag = if post.chunked { "  [ファイル]" } else { "" };
            let weight = if post.depth == 0 {
                format!("  [熱量 {}]", thread.heat)
            } else {
                String::new()
            };
            println!("{}{} {}  ({} バイト){}{}", indent, marker, post.name, post.size, tag, weight);
            println!("{}   ref: {}", indent, post.content_ref);
        }
        println!();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let keys = KeyFiles::new(&cli.data_dir, env_passphrase());

    match &cli.command {
        Commands::Init { force } => {
            if let Some(w) = keys.plaintext_warning() {
                eprintln!("警告: {}", w);
            }
            let identity = keys.create_identity(*force)?;
            println!("鍵を生成しました");
            println!("  Node ID : {}", identity.public_id());
            println!("  保存先  : {}", keys.identity_path().display());
            println!();
            println!("この鍵を失うと同じ ID には戻れません。");
        }

        Commands::Id => {
            println!("{}", keys.load_identity()?.public_id());
        }

        Commands::Send {
            to,
            secret,
            board,
            message,
            file,
            name,
            reply_to,
            connect,
            port,
            min_relays,
        } => {
            use aether_core::crypto::identity::NodeId;

            // 送る中身：--message（テキスト）か --file（ファイル）
            let (content, default_name): (Vec<u8>, String) = match (message, file) {
                (Some(m), None) => (m.as_bytes().to_vec(), m.chars().take(40).collect()),
                (None, Some(path)) => {
                    let bytes = std::fs::read(path)
                        .map_err(|e| format!("ファイルを読めません {}: {}", path, e))?;
                    let base = std::path::Path::new(path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("file")
                        .to_string();
                    (bytes, base)
                }
                _ => return Err("--message か --file のどちらか一方を指定してください".into()),
            };

            let report = match (to, board) {
                (Some(to), None) => {
                    let target = NodeId(parse_hex32(to, "--to")?);
                    let secret = secret.as_deref().map(|s| parse_hex32(s, "--secret")).transpose()?;
                    if secret.is_none() {
                        println!("相手の NodeId から鍵を自動合意します（--secret 不要）");
                    }
                    let client = join_ephemeral(cli.data_dir.clone(), *port, connect, *min_relays).await?;
                    let r = client.send_private(target, secret, &content).await?;
                    // 書き出し終える前に終了すると、置いたはずのシャードが失われる
                    client.flush().await;
                    r
                }
                (None, Some(board)) => {
                    let board_id = aether_client::resolve_board(board)?;
                    // 掲示板の親投稿（2-5）。カンマ区切りで複数指定でき DAG を成す
                    let parents = match reply_to {
                        Some(s) => s
                            .split(',')
                            .map(|r| parse_hex32(r, "--reply-to"))
                            .collect::<Result<Vec<_>, _>>()?,
                        None => Vec::new(),
                    };
                    println!("板 #{} に書き込みます", board_id.fingerprint());
                    let client = join_ephemeral(cli.data_dir.clone(), *port, connect, *min_relays).await?;
                    let r = client
                        .publish(PublicPost {
                            board: board_id,
                            content,
                            name: name.clone().unwrap_or(default_name),
                            parents,
                        })
                        .await?;
                    client.flush().await;
                    r
                }
                _ => return Err("私信は --to（--secret は任意）、板への書き込みは --board を指定してください".into()),
            };

            if let Some(r) = &report.content_ref {
                println!("ref: {}", r);
            }
            println!("送信完了");
        }

        Commands::Search {
            board,
            connect,
            port,
            min_relays,
        } => {
            let client = join_ephemeral(cli.data_dir.clone(), *port, connect, *min_relays).await?;
            let found = client.search(&aether_client::resolve_board(board)?).await?;
            if found.is_empty() {
                println!("該当なし（まだ公開されていないか、保持者に届いていません）");
            } else {
                print_board(board, &found);
            }
        }

        Commands::Get {
            board,
            r#ref,
            out,
            connect,
            port,
            min_relays,
        } => {
            let content_ref = parse_hex32(r#ref, "--ref")?;
            let client = join_ephemeral(cli.data_dir.clone(), *port, connect, *min_relays).await?;
            match client.get(&aether_client::resolve_board(board)?, content_ref).await? {
                Some(fetched) => match out {
                    Some(path) => {
                        std::fs::write(path, &fetched.bytes)
                            .map_err(|e| format!("保存に失敗 {}: {}", path, e))?;
                        println!("\n--- 取得成功 ---\n{} バイトを {} に保存しました\n", fetched.bytes.len(), path);
                    }
                    None => println!("\n--- 取得成功 ---\n{}\n", String::from_utf8_lossy(&fetched.bytes)),
                },
                None => println!("取得できませんでした（保持者が居ないか、期限切れ）"),
            }
        }

        Commands::Start {
            port,
            connect,
            advertise,
            allow_port_mapping,
            pow_difficulty,
            contacts,
            subscribe,
            epoch_beacon,
        } => {
            println!("Node ID: {}", keys.load_identity()?.public_id());
            let contacts = contacts
                .iter()
                .map(|c| parse_contact(c))
                .collect::<Result<Vec<_>, _>>()?;

            let events = event_channel();
            spawn_event_printer(events.subscribe());
            let client = AetherClient::start(
                ClientConfig {
                    data_dir: cli.data_dir.clone(),
                    passphrase: env_passphrase(),
                    port: *port,
                    seed: connect.as_deref().map(str::parse::<SocketAddr>).transpose()?,
                    min_relays: 2,
                    mode: NodeMode::Relay(RelayOptions {
                        advertise: advertise.as_deref().map(str::parse).transpose()?,
                        allow_port_mapping: *allow_port_mapping,
                        pow_difficulty: *pow_difficulty,
                        epoch_beacon: *epoch_beacon,
                    }),
                    network: Default::default(),
                },
                events,
            )
            .await?;
            if connect.is_none() {
                println!("種ノードが未指定です (--connect)。単独で待ち受けます");
            }
            println!("待ち受け開始。Ctrl+C で停止します");

            if !contacts.is_empty() || !subscribe.is_empty() {
                let boards = subscribe
                    .iter()
                    .map(|b| Ok((aether_client::resolve_board(b)?, b.clone())))
                    .collect::<aether_client::Result<Vec<_>>>()?;
                client.start_receiving(contacts, boards).await?;
            }
            // 誰からでも初回接触を受けられるよう、プレキー束を網へ公開しておく
            client.start_prekey_publisher()?;

            let status = client.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    let s = status.status().await;
                    println!("既知リレー: {} 台 / 保持エントリ: {} 件", s.known_relays, s.stored_entries);
                }
            });

            tokio::signal::ctrl_c().await?;
            println!("\n停止します");
        }
    }

    Ok(())
}
