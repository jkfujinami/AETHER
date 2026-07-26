//! AETHER ノードの CLI
//!
//! ```text
//! aether init                        鍵を生成して保存する
//! aether start --connect <種ノード>   ネットワークに参加して常駐する
//! aether id                          保存済みの Node ID を表示する
//! ```

use aether_core::crypto::identity::Identity;
use aether_core::node::server::NodeServer;
use aether_core::Config;
use clap::{Parser, Subcommand};
use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
aether start --subscribe <キーワード>              公開キーワードを購読して受信\n  \
\n  \
# 私信（相手と秘密を事前共有）\n  \
aether send --to <NodeId> --secret <hex> --message \"やあ\" --connect <種>\n  \
\n  \
# 公開：投稿・ファイル共有・掲示板\n  \
aether send --keyword <語> --message \"本文\" --connect <種>\n  \
aether send --keyword <語> --file movie.mkv --connect <種>\n  \
aether send --keyword <板> --message \"レス\" --reply-to <ref> --connect <種>\n  \
\n  \
# 発見・取得\n  \
aether search --keyword <語> --connect <種>\n  \
aether get --keyword <語> --ref <ref> --out movie.mkv --connect <種>"
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

        /// 購読する公開キーワード（複数指定可）
        ///
        /// キーワードを知る全員が同じ鍵に到達する（公開モード / 19.3.1）。
        /// 指定すると、そのキーワードで公開された投稿を拾って表示する。
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
    /// 私信は `--to`＋`--secret`（事前共有）、公開は `--keyword`。
    Send {
        /// 宛先の Node ID (hex 64文字)。私信のとき指定
        ///
        /// `--secret` を省くと、相手の NodeId から**自動で鍵合意**する（3-1 ③）。
        #[arg(long)]
        to: Option<String>,

        /// 事前共有秘密 (hex 64文字)。私信で明示したいときだけ指定（省略時は自動鍵合意）
        #[arg(long)]
        secret: Option<String>,

        /// 公開キーワード。指定すると公開モードで投稿する
        ///
        /// キーワードを知る全員が受け取れる（`--to`/`--secret` とは排他）。
        #[arg(long, conflicts_with_all = ["to", "secret"])]
        keyword: Option<String>,

        /// 本文（テキスト送信）。`--file` と排他
        #[arg(long, conflicts_with = "file")]
        message: Option<String>,

        /// 送信するファイルのパス（公開モードの大容量共有 / 2-4）。`--message` と排他
        ///
        /// 大きいファイルは自動でチャンク化され content-address で配置される
        /// （重複排除・並列取得）。公開モード専用。
        #[arg(long, requires = "keyword")]
        file: Option<String>,

        /// 表示名（公開モードで索引に載せるときの見出し。省略時は本文の先頭 or ファイル名）
        #[arg(long)]
        name: Option<String>,

        /// 返信先の投稿 ref (hex 64文字)。掲示板のスレッド返信（2-5）。省略で新規スレッド
        #[arg(long = "reply-to", requires = "keyword")]
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
    /// 公開キーワードの索引を引いて、公開されている記述子を一覧する
    ///
    /// 購読して待たなくても、キーワードの索引を pull して発見できる（19.7）。
    Search {
        /// 検索する公開キーワード
        #[arg(long)]
        keyword: String,

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
    /// 索引で見つけた記述子の本体を取得する（keyword + content ref）
    Get {
        /// 公開キーワード
        #[arg(long)]
        keyword: String,

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

/// 連絡先の解決結果: (NodeId, 明示された秘密 or None＝自動鍵合意)
type ContactSpec = (aether_core::crypto::identity::NodeId, Option<[u8; 32]>);

/// `<NodeId hex>[:<共有秘密 hex>]` を分解する
///
/// 秘密を省略できる。省略時は `None`（呼び出し側が NodeId から自動鍵合意する / 3-1 ③）。
fn parse_contact(spec: &str) -> Result<ContactSpec, Box<dyn Error>> {
    use aether_core::crypto::identity::NodeId;
    match spec.split_once(':') {
        Some((id, secret)) => Ok((
            NodeId(parse_hex32(id, "--contact の NodeId")?),
            Some(parse_hex32(secret, "--contact の共有秘密")?),
        )),
        None => Ok((NodeId(parse_hex32(spec, "--contact の NodeId")?), None)),
    }
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let bytes = hex::decode(s).map_err(|e| format!("{} が hex ではありません: {}", what, e))?;

    bytes
        .try_into()
        .map_err(|_| format!("{} は 32 バイト (hex 64文字) である必要があります", what).into())
}

/// 公開鍵から contacts マップ用の合成 NodeId を作る
///
/// 公開モードには特定の宛先が無い。K_pub をローカルの contacts マップに
/// 収めるための安定した鍵として、鍵のハッシュを NodeId 代わりに使う。
/// （送信側・受信側で一致する必要はない。各自のマップの鍵にすぎない）
fn keyword_target(k_pub: &[u8; 32]) -> aether_core::crypto::identity::NodeId {
    aether_core::crypto::identity::NodeId(aether_core::crypto::keyword::subscription_id(k_pub))
}

/// 死んだ relay を引いた時に共通で使う定数：1 試行の頭打ち時間
const ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);

/// エラーの箱（`tokio::spawn` の中でも使えるよう Send + Sync）
type BoxErr = Box<dyn Error + Send + Sync>;

/// `BoxErr` を main の `Box<dyn Error>` に落とす。
/// `?` の `From` 解決は Send+Sync 付きだと通らないので明示変換する。
fn box_err(e: BoxErr) -> Box<dyn Error> {
    e
}

/// Pull セッション一式（返信用 Inbound Tunnel ＋ 索引/本体を引く出口回路つき Mailbox）
struct PullSession {
    mailbox: aether_core::mailbox::schrodinger::SchrodingerMailbox,
    receive_tunnel_id: [u8; 32],
    reply_to: aether_core::net::tunnel::TunnelEndpoint,
    gateway_addr: SocketAddr,
}

/// gateway を選んで返信トンネルと出口回路を張り、`PullSession` を用意する。
///
/// ディレクトリは **liveness を持たない**（PEX で既に落ちたノードも載る。
/// bootstrap した一発クライアントすら relay として登録される）。gateway に死んだ
/// relay を引くと TunnelBuild / connect_entry が QUIC で timeout する。1 台死んだ
/// だけで検索・取得・受信が落ちるのは不可なので、失敗した gateway を除外して別候補で
/// 最大 `max_attempts` 回まで試す。各試行は `ATTEMPT_TIMEOUT` で頭打ちにし、死んだと
/// 分かった相手は **ディレクトリから `remove`（eviction）** して二度と引かない。
///
/// `contacts` は Mailbox に載せる共有秘密。検索/取得は空、受信は購読中の秘密を渡す。
async fn establish_pull_session(
    node: &Arc<NodeServer>,
    contacts: std::collections::HashMap<aether_core::crypto::identity::NodeId, [u8; 32]>,
    max_attempts: usize,
) -> Result<PullSession, BoxErr> {
    use aether_core::mailbox::schrodinger::SchrodingerMailbox;
    use aether_core::net::gossip::GossipClient;
    use aether_core::net::onion::OnionCircuit;
    use aether_core::net::relay::RelayClient;
    use aether_core::net::tunnel::InboundTunnel;
    use aether_core::protocol::wire::PacketType;
    use std::sync::Mutex;

    let directory = node.directory();
    // 自ノードと、既に失敗した gateway は再抽選しない
    let mut excluded = vec![node.descriptor.node_id];
    let mut last_err: Option<BoxErr> = None;

    for _ in 0..max_attempts {
        let gateway = {
            let dir = directory.read().await;
            dir.random_path(1, &excluded).into_iter().next()
        };
        let Some(gateway) = gateway else { break };
        excluded.push(gateway.node_id);

        // gateway が生きているかは、実際に張ってみるまで分からない。
        // 一連のネットワーク確立をまとめて timeout で括る。
        let attempt = async {
            let (tunnel, instructions) = InboundTunnel::build(
                vec![gateway.addr, node.descriptor.addr],
                vec![gateway.x25519_pub, node.descriptor.x25519_pub],
            )?;
            let receive_tunnel_id = tunnel.receive_tunnel_id;
            let reply_to = tunnel.endpoint.clone();

            // 返信トンネルの各ホップへ TunnelBuild を送る（死んだ gateway はここで落ちる）
            let builder = RelayClient::new()?;
            for (addr, payload) in &instructions {
                builder
                    .send_direct_packet(*addr, PacketType::TunnelBuild, payload)
                    .await?;
            }

            // 索引/本体を引くための出口回路
            let mut fetch_client = RelayClient::new()?;
            fetch_client.connect_entry(gateway.addr).await?;
            let mut circuit = OnionCircuit::new(1);
            circuit.add_hop(
                gateway.addr,
                gateway.x25519_pub,
                aether_core::crypto::key_exchange::EphemeralKey::generate(),
            )?;
            fetch_client.set_circuit(circuit);

            let mailbox = SchrodingerMailbox::with_directory(
                Arc::new(fetch_client),
                Arc::new(GossipClient::new(RelayClient::new()?)),
                Arc::new(Mutex::new(contacts.clone())),
                directory.clone(),
            );
            mailbox.register_inbound_tunnel(tunnel);

            Ok::<PullSession, BoxErr>(PullSession {
                mailbox,
                receive_tunnel_id,
                reply_to,
                gateway_addr: gateway.addr,
            })
        };

        match tokio::time::timeout(ATTEMPT_TIMEOUT, attempt).await {
            Ok(Ok(session)) => return Ok(session),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => last_err = Some("gateway への接続が timeout しました".into()),
        }

        // ここまで来た＝この gateway は死んでいた。接続に失敗した相手はここで初めて
        // 「死んでいる」と分かるので、ディレクトリから外す。次の抽選（と後続の操作）で
        // 二度と引かない。
        directory.write().await.remove(&gateway.node_id);
    }

    Err(last_err.unwrap_or_else(|| "gateway になれる生存 relay が見つかりません".into()))
}

/// 生きている出口リレーを 1 台選んで接続する（送信の出口用）。
///
/// `random_path` はディレクトリから無作為に選ぶだけで liveness を見ない。死んだ相手に
/// あたったら [`establish_pull_session`] と同じくディレクトリから `remove` して別候補を
/// 試す。`exclude` に渡した NodeId は選ばない（本体と Hint の出口を別々にするため / 19.2.4）。
async fn connect_live_exit(
    node: &Arc<NodeServer>,
    exclude: &[aether_core::crypto::identity::NodeId],
    max_attempts: usize,
) -> Result<
    (
        aether_core::net::relay_list::RelayDescriptor,
        aether_core::net::relay::RelayClient,
    ),
    BoxErr,
> {
    use aether_core::net::relay::RelayClient;

    let directory = node.directory();
    let mut excluded = exclude.to_vec();
    excluded.push(node.descriptor.node_id);
    let mut last_err: Option<BoxErr> = None;

    for _ in 0..max_attempts {
        let hop = {
            let dir = directory.read().await;
            dir.random_path(1, &excluded).into_iter().next()
        };
        let Some(hop) = hop else { break };
        excluded.push(hop.node_id);

        let mut client = RelayClient::new()?;
        match tokio::time::timeout(ATTEMPT_TIMEOUT, client.connect_entry(hop.addr)).await {
            Ok(Ok(())) => return Ok((hop, client)),
            Ok(Err(e)) => last_err = Some(e.into()),
            Err(_) => last_err = Some("出口リレーへの接続が timeout しました".into()),
        }

        // 死んでいると分かった出口をディレクトリから外す
        directory.write().await.remove(&hop.node_id);
    }

    Err(last_err.unwrap_or_else(|| "生存している出口リレーが見つかりません".into()))
}

/// ネットワークに参加する ── ノードを起動し、種へ bootstrap し、リレーが集まるまで待つ
///
/// 送信・検索・取得の共通の起点。`node_id_pow_difficulty = 0`（一発クライアントは
/// リレーとして振る舞わない）。リレーが `min_relays` を超えるまで最大 30 秒待つ。
async fn join_network(
    data_dir: &Path,
    port: u16,
    connect: &str,
    min_relays: usize,
) -> Result<Arc<NodeServer>, Box<dyn Error>> {
    let identity = load_identity(data_dir)?;
    let config = Config {
        listen_port: port,
        node_id_pow_difficulty: 0,
        ..Default::default()
    };
    let db_path = data_dir.join("mailbox.db");
    let node = Arc::new(NodeServer::with_config_passphrase(
        port,
        identity,
        &db_path,
        &config,
        env_passphrase().as_deref(),
    )?);

    // run() が受信を回してから参加する（Connection Reversal の応答を取りこぼさない）
    let running = node.clone();
    tokio::spawn(async move { running.run().await });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    node.bootstrap(connect.parse()?).await?;

    // 回路を張るにはリレーが要る。収束を最大 30 秒待つ
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while node.directory_size().await <= min_relays {
        if std::time::Instant::now() > deadline {
            return Err(format!(
                "リレーが {} 台見つかりませんでした（現在 {} 台）",
                min_relays,
                node.directory_size().await
            )
            .into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Ok(node)
}

/// content-addressed（または単一 body）オブジェクトを1つ取りに行き、復元して返す
///
/// 取得要求を出し、Inbound Tunnel に返ってくるシャードを `timeout` まで集めて復元する。
/// 3 シャード揃えば復元でき、遅い・落ちた保持者は待たない。揃わなければ `None`。
async fn fetch_object(
    node: &Arc<NodeServer>,
    mailbox: &aether_core::mailbox::schrodinger::SchrodingerMailbox,
    receive_tunnel_id: &[u8; 32],
    mailbox_key: &[u8; 32],
    secret: &[u8; 32],
    timeout: std::time::Duration,
) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    mailbox.request_object(mailbox_key, secret).await?;

    let mut collected: Vec<Vec<u8>> = Vec::new();
    let until = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < until {
        let raw = node.mailbox().fetch_tunnel_messages(receive_tunnel_id).await?;
        if !raw.is_empty() {
            collected.extend(mailbox.decrypt_replies(&raw));
            if let Ok(Some(obj)) = mailbox.reassemble(&collected, mailbox_key, secret) {
                return Ok(Some(obj));
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    Ok(None)
}

/// 相手のプレキー束を網から取得する（X3DH 初回接触 / 3-1）
///
/// Pull セッションを張り、`H("aether_prekey_v1"‖NodeId)` の担当保持者から束を集めて復元する。
/// 相手が束を公開していない／オフラインなら timeout でエラー。
async fn fetch_prekey_bundle(
    node: &Arc<NodeServer>,
    target: &aether_core::crypto::identity::NodeId,
) -> Result<aether_core::crypto::x3dh::PreKeyBundle, BoxErr> {
    let session = establish_pull_session(node, std::collections::HashMap::new(), 4).await?;
    session.mailbox.request_prekey_bundle(target).await?;

    let mut collected: Vec<Vec<u8>> = Vec::new();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < until {
        let raw = node
            .mailbox()
            .fetch_tunnel_messages(&session.receive_tunnel_id)
            .await?;
        if !raw.is_empty() {
            collected.extend(session.mailbox.decrypt_replies(&raw));
            if let Some(bundle) = session.mailbox.reassemble_prekey_bundle(&collected, target)? {
                return Ok(bundle);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    Err(format!("プレキー束を取得できません（相手 {} が公開していない/オフライン）", target).into())
}

/// 受信した私信フレームを開く（X3DH 初回接触 or 継続ラチェット / 3-1）
///
/// フレーム tag を見て、初回接触なら Bob のプレキー秘密で respond して `SK` を復元し
/// [`Session::bootstrap`] で立てる。継続なら保存済み Session を読む。開けたら Session を
/// 保存（ラチェット前進）して平文を返す。
///
/// [`Session::bootstrap`]: aether_core::crypto::session::Session::bootstrap
fn open_private_body(
    keystore: &aether_core::storage::keystore::KeyStore,
    bob_identity: &Identity,
    prekeys: Option<&aether_core::crypto::x3dh::PreKeySecrets>,
    me: &aether_core::crypto::identity::NodeId,
    contact: &aether_core::crypto::identity::NodeId,
    body: &[u8],
) -> Result<Option<Vec<u8>>, BoxErr> {
    use aether_core::crypto::session::Session;
    use aether_core::crypto::x3dh;

    let (initial, sealed) = match x3dh::parse_frame(body) {
        Ok(v) => v,
        Err(_) => return Ok(None), // 壊れたフレームは黙って捨てる
    };

    let mut session = match initial {
        Some(init) => {
            // 初回接触：認識で特定した contact と init_msg の差出人が一致すること
            if init.initiator_node_id != *contact {
                return Ok(None);
            }
            let Some(secrets) = prekeys else { return Ok(None) }; // 束未生成なら開けない
            match x3dh::respond(bob_identity, secrets, &init) {
                Ok(sk) => Session::bootstrap(&sk, me, contact),
                Err(_) => return Ok(None),
            }
        }
        None => match keystore.load(contact)? {
            Some(s) => s,
            None => return Ok(None), // 継続だが Session 未確立（初回を取りこぼした）
        },
    };

    match session.open(sealed, &[]) {
        Ok(pt) => {
            keystore.save(contact, &session)?; // 受信ラチェットを前進
            Ok(Some(pt))
        }
        Err(_) => Ok(None),
    }
}

/// 自分のプレキー束を網へ公開し続ける（X3DH の受信側 / 3-1）
///
/// 初回接触を受けるには束を網へ置いておく必要がある。束と秘密を KeyStore に永続化して
/// 再起動を跨いで再利用し（Kyber 公開鍵は秘密から再導出できないため束も持つ）、
/// 保持者 churn / TTL に抗って定期再公開する。
fn spawn_prekey_publisher(
    node: Arc<NodeServer>,
    keystore: Arc<aether_core::storage::keystore::KeyStore>,
    data_dir: PathBuf,
) {
    /// 束の再公開間隔
    const REPUBLISH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

    tokio::spawn(async move {
        if let Err(e) = run(node, keystore, data_dir).await {
            eprintln!("プレキー公開を継続できません: {}", e);
        }
    });

    async fn run(
        node: Arc<NodeServer>,
        ks: Arc<aether_core::storage::keystore::KeyStore>,
        data_dir: PathBuf,
    ) -> Result<(), BoxErr> {
        use aether_core::crypto::x3dh;

        // 束＋秘密を用意（無ければ生成して永続化・以後再利用）
        let bundle = match ks.load_prekeys()? {
            Some((b, _s)) => b,
            None => {
                let identity = load_identity_shared(&data_dir)?;
                let (b, s) = x3dh::generate_prekeys(&identity, false);
                ks.save_prekeys(&b, &s)?;
                b
            }
        };

        // ディレクトリ収束を待つ（公開には出口リレーが要る）
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while node.directory_size().await < 2 {
            if std::time::Instant::now() > deadline {
                return Err("プレキー公開に足るリレーが見つかりません".into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        loop {
            match publish_once(&node, &bundle).await {
                Ok(()) => println!("プレキー束を公開しました（初回接触を受信できます）"),
                Err(e) => eprintln!("プレキー公開に失敗: {}", e),
            }
            tokio::time::sleep(REPUBLISH_INTERVAL).await;
        }
    }

    async fn publish_once(
        node: &Arc<NodeServer>,
        bundle: &aether_core::crypto::x3dh::PreKeyBundle,
    ) -> Result<(), BoxErr> {
        use aether_core::crypto::key_exchange::EphemeralKey;
        use aether_core::mailbox::schrodinger::SchrodingerMailbox;
        use aether_core::net::gossip::GossipClient;
        use aether_core::net::onion::OnionCircuit;
        use aether_core::net::relay::RelayClient;
        use std::collections::HashMap;
        use std::sync::Mutex;

        // 本体配置と同じく、生きた出口リレーを1台引いて onion 回路を張る
        let (hop, mut client) = connect_live_exit(node, &[], 4).await?;
        let mut circuit = OnionCircuit::new(1);
        circuit.add_hop(hop.addr, hop.x25519_pub, EphemeralKey::generate())?;
        client.set_circuit(circuit);

        let mailbox = SchrodingerMailbox::with_directory(
            Arc::new(client),
            Arc::new(GossipClient::new(RelayClient::new()?)),
            Arc::new(Mutex::new(HashMap::new())),
            node.directory(),
        );
        mailbox.publish_prekey_bundle(bundle).await?;

        // **接続を即閉じない。** onion パケットは entry へ書いた直後で、QUIC がまだ
        // 送出しきっていない。ここで mailbox（＝RelayClient）を drop すると接続が閉じて
        // 書いたシャードが失われる。少し待ってフラッシュさせる（送信コマンドと同じ）。
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Ok(())
    }
}

/// 掲示板の索引結果をスレッド DAG として表示する（2-5 / 2-7）
///
/// 決定論的トポロジカル順に並べ、スレッド（根）ごとにまとめ、深さで字下げして
/// 木のように見せる。スレッドの並びは**累積 PoW（熱量）の HN 式ランク順** ──
/// PoW を積んだ議論が上に、スパムの単発投稿は下に沈む（2-7）。
/// 各行の `ref` はそのまま `get --ref` / `send --reply-to` に渡せる。
fn print_board(
    keyword: &str,
    found: &[aether_core::mailbox::index::IndexDescriptor],
    pow: &[u32],
) {
    use aether_core::mailbox::board;
    use std::collections::HashMap;

    let order = board::topological_order(found);
    let depth = board::depths(found, &order);
    let cum = board::cumulative_pow(found, &order, pow);
    let now = aether_core::protocol::hint::current_timestamp();

    // content_ref → index
    let idx: HashMap<[u8; 32], usize> =
        found.iter().enumerate().map(|(i, d)| (d.content_ref, i)).collect();

    // 各投稿が属するスレッド（根）を、トポロジカル順に親から伝播して決める
    let mut thread_of: HashMap<usize, usize> = HashMap::new();
    for &i in &order {
        let root = found[i]
            .parents
            .iter()
            .filter_map(|p| idx.get(p))
            .filter_map(|pi| thread_of.get(pi).copied())
            .next()
            .unwrap_or(i);
        thread_of.insert(i, root);
    }

    // スレッドごとに投稿を集める（トポロジカル順を保つ）
    let mut threads: HashMap<usize, Vec<usize>> = HashMap::new();
    for &i in &order {
        threads.entry(thread_of[&i]).or_default().push(i);
    }

    // スレッド内の最大累積 PoW ＝「熱量」
    let heat = |r: usize| -> u32 { threads[&r].iter().map(|&i| cum[i]).max().unwrap_or(0) };

    // スレッドは HN 式スコア（熱量 ÷ 時間の重力）で降順に
    let mut roots: Vec<usize> = threads.keys().copied().collect();
    roots.sort_by(|&a, &b| {
        let sa = board::hn_score(heat(a) as f64, found[a].timestamp, now);
        let sb = board::hn_score(heat(b) as f64, found[b].timestamp, now);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });

    println!(
        "\n=== 「{}」: {} スレッド / {} 投稿（PoW ランク順）===",
        keyword.trim(),
        roots.len(),
        found.len()
    );
    for r in roots {
        for &i in &threads[&r] {
            let d = &found[i];
            let indent = "  ".repeat(depth[&i]);
            let marker = if depth[&i] == 0 { "●" } else { "└─" };
            let tag = if d.chunked { "  [ファイル]" } else { "" };
            let weight = if depth[&i] == 0 {
                format!("  [熱量 {}]", heat(r))
            } else {
                String::new()
            };
            println!("{}{} {}  ({} バイト){}{}", indent, marker, d.name, d.size, tag, weight);
            println!("{}   ref: {}", indent, hex::encode(d.content_ref));
        }
        println!();
    }
}

/// 保存時暗号化のパスフレーズ（環境変数 `AETHER_PASSPHRASE`）。空・未設定なら `None`
///
/// これ 1 つで identity.key・KeyStore・mailbox.db をまとめて解錠する（押収対策 / 3-1）。
fn env_passphrase() -> Option<String> {
    match std::env::var("AETHER_PASSPHRASE") {
        Ok(p) if !p.is_empty() => Some(p),
        _ => None,
    }
}

/// 私信の前方秘匿セッションを保存する KeyStore を開く
///
/// 環境変数 `AETHER_PASSPHRASE` があれば**保存時暗号化**する（押収対策 / 3-1）。
/// 無ければ平文で開き、警告する。
fn open_keystore(data_dir: &Path) -> aether_core::Result<aether_core::storage::keystore::KeyStore> {
    use aether_core::storage::keystore::KeyStore;
    let path = data_dir.join("keystore.db");
    match env_passphrase() {
        Some(pass) => KeyStore::open_encrypted(&path, &pass),
        None => {
            eprintln!(
                "警告: AETHER_PASSPHRASE 未設定 ── KeyStore を平文で保存します（押収対策には設定推奨）"
            );
            KeyStore::open(&path)
        }
    }
}

fn identity_path(data_dir: &Path) -> PathBuf {
    data_dir.join("identity.key")
}

/// `Send + Sync` なエラーで返す版（`tokio::spawn` の中でも使える / 受信・公開タスク用）
fn load_identity_shared(data_dir: &Path) -> Result<Identity, BoxErr> {
    let path = identity_path(data_dir);

    let bytes = std::fs::read(&path).map_err(|e| -> BoxErr {
        format!(
            "鍵を読み込めません ({}): {}\n先に `aether init` を実行してください",
            path.display(),
            e
        )
        .into()
    })?;

    // 暗号化された identity.key（マジック付き）はパスフレーズが要る。平文はそのまま。
    if Identity::is_encrypted_bytes(&bytes) {
        let pass = env_passphrase().ok_or_else(|| -> BoxErr {
            "identity.key は暗号化されています。AETHER_PASSPHRASE を設定してください".into()
        })?;
        Ok(Identity::from_encrypted_bytes(&bytes, &pass)?)
    } else {
        Ok(Identity::from_bytes(&bytes)?)
    }
}

fn load_identity(data_dir: &Path) -> Result<Identity, Box<dyn Error>> {
    load_identity_shared(data_dir).map_err(box_err)
}

/// 鍵を保存する
///
/// **所有者以外が読めないようにする。** 同じマシンの他ユーザからも守る。
/// `AETHER_PASSPHRASE` があれば**保存時暗号化**する（押収されても成りすませない / 3-1）。
fn save_identity(data_dir: &Path, identity: &Identity, force: bool) -> Result<(), Box<dyn Error>> {
    let path = identity_path(data_dir);

    if path.exists() && !force {
        return Err(format!(
            "鍵が既に存在します: {}\n上書きするには --force を指定してください。\
             \n上書きすると NodeId が変わり、ガードも PoW もやり直しになります",
            path.display()
        )
        .into());
    }

    std::fs::create_dir_all(data_dir)?;

    match env_passphrase() {
        Some(pass) => {
            std::fs::write(&path, identity.to_encrypted_bytes(&pass)?)?;
            println!("  暗号化: AETHER_PASSPHRASE で保存時暗号化しました（押収対策）");
        }
        None => {
            std::fs::write(&path, identity.to_bytes())?;
            eprintln!(
                "警告: AETHER_PASSPHRASE 未設定 ── identity.key を平文で保存します（押収対策には設定推奨）"
            );
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Init { force } => {
            let identity = Identity::generate();
            save_identity(&cli.data_dir, &identity, *force)?;

            println!("鍵を生成しました");
            println!("  Node ID : {}", identity.public_id());
            println!("  保存先  : {}", identity_path(&cli.data_dir).display());
            println!();
            println!("この鍵を失うと同じ ID には戻れません。");
        }

        Commands::Send {
            to,
            secret,
            keyword,
            message,
            file,
            name,
            reply_to,
            connect,
            port,
            min_relays,
        } => {
            use aether_core::crypto::identity::NodeId;
            use aether_core::crypto::key_exchange::EphemeralKey;
            use aether_core::crypto::keyword as kw;
            use aether_core::mailbox::schrodinger::SchrodingerMailbox;
            use aether_core::net::gossip::GossipClient;
            use aether_core::net::onion::OnionCircuit;
            use aether_core::net::relay::RelayClient;
            use std::collections::HashMap;
            use std::sync::Mutex;

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
                (Some(_), Some(_)) => {
                    return Err("--message と --file は同時に指定できません".into())
                }
                (None, None) => {
                    return Err("--message か --file のどちらかを指定してください".into())
                }
            };
            let display_name = name.clone().unwrap_or(default_name);

            // 掲示板の親投稿（2-5）。カンマ区切りで複数指定でき DAG を成す。空なら新規スレッド
            let post_parents: Vec<[u8; 32]> = match reply_to {
                Some(s) => s
                    .split(',')
                    .map(|r| parse_hex32(r.trim(), "--reply-to"))
                    .collect::<Result<Vec<_>, _>>()?,
                None => Vec::new(),
            };

            // 宛先と鍵を決める：私信(--to、--secret は任意) か 公開(--keyword)
            let (target, shared_secret, is_public): (NodeId, [u8; 32], bool) =
                match (to, keyword) {
                    (Some(to), None) => {
                        let target = NodeId(parse_hex32(to, "--to")?);
                        let sec = match secret {
                            // 明示された事前共有秘密を使う
                            Some(s) => parse_hex32(s, "--secret")?,
                            // 省略時は相手の NodeId から自動鍵合意（3-1 ③）
                            None => {
                                let identity = load_identity(&cli.data_dir)?;
                                println!("相手の NodeId から鍵を自動合意します（--secret 不要）");
                                identity.agree(&target)?
                            }
                        };
                        (target, sec, false)
                    }
                    (None, Some(keyword)) => {
                        let k_pub = kw::derive_public_key(keyword)?;
                        println!("公開モード: キーワード「{}」で投稿します", keyword.trim());
                        (keyword_target(&k_pub), k_pub, true)
                    }
                    _ => {
                        return Err(
                            "私信は --to（--secret は任意）、公開は --keyword を指定してください".into(),
                        )
                    }
                };

            println!("種ノード {} へ参加します。リレーを探しています...", connect);
            let node = join_network(&cli.data_dir, *port, connect, *min_relays).await?;

            // --- Onion 回路を張る ---
            //
            // 出口は生きているものを引く。死んだ relay に当たったらディレクトリから
            // 外して別候補へ（connect_live_exit）。
            let (body_hop, mut body_client) = connect_live_exit(&node, &[], 4).await.map_err(box_err)?;
            let mut body_circuit = OnionCircuit::new(1);
            body_circuit.add_hop(body_hop.addr, body_hop.x25519_pub, EphemeralKey::generate())?;
            body_client.set_circuit(body_circuit);

            // **本体 PUT と Hint 放流は別の出口を通す（回路分離 / 19.2.4）。**
            // 同じ出口だと、その出口を取られた時点で「本体を置いた者と
            // Hint を流した者は同一」が確定し、時間分離の意味が相殺される。
            let (hint_hop, mut hint_client) =
                match connect_live_exit(&node, &[body_hop.node_id], 4).await {
                    Ok(pair) => pair,
                    Err(_) => {
                        eprintln!(
                            "警告: 他に生存リレーが無いため本体と Hint が同じ出口を通ります（相関リスク）"
                        );
                        let mut c = RelayClient::new()?;
                        c.connect_entry(body_hop.addr).await?;
                        (body_hop.clone(), c)
                    }
                };
            let mut hint_circuit = OnionCircuit::new(1);
            hint_circuit.add_hop(hint_hop.addr, hint_hop.x25519_pub, EphemeralKey::generate())?;
            hint_client.set_circuit(hint_circuit);

            println!("本体の出口: {} ／ Hint の出口: {}", body_hop.addr, hint_hop.addr);

            let contacts = Arc::new(Mutex::new(HashMap::new()));
            contacts.lock().unwrap().insert(target, shared_secret);

            let mailbox = SchrodingerMailbox::with_directory(
                Arc::new(body_client),
                Arc::new(GossipClient::new(hint_client)),
                contacts,
                node.directory(),
            )
            // 放流網が要求する PoW を Hint に解かせる（受信側の検証と一致させる）
            .with_pow_difficulty(node.gossip().pow_difficulty());

            // 大容量の公開コンテンツはチャンク化して content-addressed に配置する（2-4）。
            // 私信・小容量は従来どおり単一 body + Hint。
            let chunked = is_public && aether_core::mailbox::chunk::needs_chunking(content.len());

            if chunked {
                // --- チャンク化して配置（Hint は流さない＝pull 専用の大容量共有）---
                let content_ref = mailbox
                    .place_chunked(&shared_secret, &display_name, &content)
                    .await?;

                let num_chunks = content.len().div_ceil(aether_core::mailbox::chunk::CHUNK_SIZE);
                println!(
                    "ファイルを {} チャンクに分割して配置しました ({} バイト、content-addressed)",
                    num_chunks,
                    content.len()
                );

                let descriptor = aether_core::mailbox::index::IndexDescriptor {
                    content_ref,
                    name: display_name.clone(),
                    size: content.len() as u64,
                    timestamp: aether_core::protocol::hint::current_timestamp(),
                    chunked: true,
                    parents: post_parents.clone(),
                };
                mailbox.publish_descriptor(&shared_secret, &descriptor).await?;
                println!("索引に記述子を公開しました（キーワードで検索可能・チャンク化）");
            } else {
                // --- 単一 body を配置 ---
                // 私信は**前方秘匿**（Session でラチェット封じ）。公開は静的（K_pub）。
                let (hint, mailbox_key, profile) = if is_public {
                    mailbox.place_body_profiled(&target, &content).await?
                } else {
                    use aether_core::crypto::session::Session;
                    use aether_core::crypto::x3dh;

                    let ks = open_keystore(&cli.data_dir)?;
                    let me = node.descriptor.node_id;

                    // 既存 Session があれば継続。無ければ **X3DH で初回接触**：相手の署名付き
                    // プレキー束を取得し、ephemeral＋耐量子KEM を含む初期秘密 SK を立てる
                    // （静的 agree より初回の前方秘匿が強い）。SK をラチェットの種にする。
                    // 認識（blind_tag / mailbox 位置）は従来どおり agree 秘密のまま（分離）。
                    let (mut session, initial): (Session, Option<x3dh::InitialMessage>) =
                        match ks.load(&target)? {
                            Some(s) => (s, None),
                            None => {
                                println!("初回接触: {} のプレキー束を取得して X3DH 鍵合意します", target);
                                let bundle = fetch_prekey_bundle(&node, &target).await.map_err(box_err)?;
                                let identity = load_identity(&cli.data_dir)?;
                                let (sk, init) = x3dh::initiate(&identity, &target, &bundle)?;
                                println!("X3DH 成立（前方秘匿＋耐量子ハイブリッド）。ラチェットを開始します");
                                (Session::bootstrap(&sk, &me, &target), Some(init))
                            }
                        };

                    let sealed = session.seal(&content, &[])?;

                    // フレーム: 初回は [0x01][InitialMessage][sealed]、継続は [0x00][sealed]
                    let body = match &initial {
                        Some(init) => x3dh::frame_initial(init, &sealed)?,
                        None => x3dh::frame_continuation(&sealed),
                    };

                    let placed = mailbox.place_ratchet_body(&target, &body).await?;
                    ks.save(&target, &session)?; // ラチェットを前進させて永続化
                    println!("前方秘匿でラチェット封じしました（Session を更新）");
                    placed
                };

                println!(
                    "本体を配置しました (mailbox_key {}..., {} バイト送出)",
                    hex::encode(&mailbox_key[..8]),
                    profile.bytes
                );

                // --- Hint 放流（遅延は網の活動量から決まる）---
                let policy = mailbox.release_policy(
                    node.gossip().observed_hint_rate().await,
                    aether_core::mailbox::hint_release::DEFAULT_RELAY_THROUGHPUT_BPS,
                );

                match policy.status(&profile) {
                    aether_core::mailbox::hint_release::ReleaseStatus::BuriedInNoise { .. } => {
                        println!("Hint を即時放流します（中継トラフィックに埋もれる大きさ）");
                    }
                    other => println!("Hint 放流: {:?}", other),
                }

                let delay = policy.delay_for(&profile);
                if !delay.is_zero() {
                    println!("{:?} 待機してから放流します", delay);
                    tokio::time::sleep(delay).await;
                }

                mailbox.broadcast_hint(&hint).await?;
                println!("Hint を放流しました");

                // --- 公開モードなら索引にも記述子を載せる（pull で発見できるように / 19.7）---
                if is_public
                    && let Some((content_ref, _)) = mailbox.decrypt_hint(&hint)
                {
                    let descriptor = aether_core::mailbox::index::IndexDescriptor {
                        content_ref,
                        name: display_name.clone(),
                        size: profile.bytes,
                        timestamp: aether_core::protocol::hint::current_timestamp(),
                        chunked: false,
                        parents: post_parents.clone(),
                    };
                    mailbox.publish_descriptor(&shared_secret, &descriptor).await?;
                    println!("索引に記述子を公開しました（キーワードで検索可能）");
                }
            }

            println!("送信完了");

            // 拡散が回るまで少し待つ
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }

        Commands::Search {
            keyword,
            connect,
            port,
            min_relays,
        } => {
            use aether_core::crypto::keyword as kw;

            let k_pub = kw::derive_public_key(keyword)?;
            println!("キーワード「{}」の索引を引きます", keyword.trim());

            let node = join_network(&cli.data_dir, *port, connect, *min_relays).await?;

            // Gateway を選び、返信トンネルと出口回路を張る（死んだ relay は自動でスキップ）
            let PullSession {
                mailbox,
                receive_tunnel_id,
                reply_to,
                ..
            } = establish_pull_session(&node, std::collections::HashMap::new(), 4).await.map_err(box_err)?;

            // 索引を引いて、返ってくる記述子を集める
            mailbox.query_index(&k_pub, &reply_to).await?;

            let mut seen = std::collections::HashSet::new();
            let mut found: Vec<aether_core::mailbox::index::IndexDescriptor> = Vec::new();
            let mut pow: Vec<u32> = Vec::new();
            let until = std::time::Instant::now() + std::time::Duration::from_secs(8);
            while std::time::Instant::now() < until {
                let raw = node.mailbox().fetch_tunnel_messages(&receive_tunnel_id).await?;
                if !raw.is_empty() {
                    let decrypted = mailbox.decrypt_replies(&raw);
                    for (d, bits) in mailbox.decode_index_replies(&decrypted, &k_pub) {
                        if seen.insert(d.content_ref) {
                            found.push(d);
                            pow.push(bits);
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }

            if found.is_empty() {
                println!("該当なし（まだ公開されていないか、保持者に届いていません）");
            } else {
                // スレッド DAG として表示する（2-5）。並びは累積 PoW ランク（2-7）
                print_board(keyword, &found, &pow);
            }
        }

        Commands::Get {
            keyword,
            r#ref,
            out,
            connect,
            port,
            min_relays,
        } => {
            use aether_core::crypto::keyword as kw;
            use aether_core::mailbox::chunk::Manifest;
            use aether_core::mailbox::schrodinger::SchrodingerMailbox;

            let k_pub = kw::derive_public_key(keyword)?;
            let content_ref = parse_hex32(r#ref, "--ref")?;

            let node = join_network(&cli.data_dir, *port, connect, *min_relays).await?;

            // Gateway を選び、返信トンネルと出口回路を張る（死んだ relay は自動でスキップ）
            let PullSession {
                mailbox,
                receive_tunnel_id,
                ..
            } = establish_pull_session(&node, std::collections::HashMap::new(), 4).await.map_err(box_err)?;

            println!("取得中 (ref {}...)", hex::encode(&content_ref[..8]));

            // まず content_ref を Manifest（チャンク化）として引く。
            // 単一 body は content_ref の位置に何も無いので None になり、下でフォールバックする。
            let probe = fetch_object(
                &node,
                &mailbox,
                &receive_tunnel_id,
                &content_ref,
                &k_pub,
                std::time::Duration::from_secs(6),
            )
            .await?;
            let manifest = probe.as_deref().and_then(|b| Manifest::decode(b).ok());

            let body: Option<Vec<u8>> = if let Some(manifest) = manifest {
                // --- チャンク化コンテンツ：各チャンクを content-address で取り集めて連結 ---
                println!(
                    "チャンク化コンテンツを取得します: {} ({} チャンク / {} バイト)",
                    manifest.name,
                    manifest.chunk_refs.len(),
                    manifest.size
                );

                let mut file = Vec::with_capacity(manifest.size as usize);
                let mut complete = true;
                for (i, cref) in manifest.chunk_refs.iter().enumerate() {
                    match fetch_object(
                        &node,
                        &mailbox,
                        &receive_tunnel_id,
                        cref,
                        &k_pub,
                        std::time::Duration::from_secs(15),
                    )
                    .await?
                    {
                        Some(chunk) => {
                            file.extend_from_slice(&chunk);
                            println!("  チャンク {}/{} 取得", i + 1, manifest.chunk_refs.len());
                        }
                        None => {
                            eprintln!(
                                "  チャンク {}/{} を取得できませんでした（保持者が居ない）",
                                i + 1,
                                manifest.chunk_refs.len()
                            );
                            complete = false;
                            break;
                        }
                    }
                }
                if complete {
                    Some(file)
                } else {
                    None
                }
            } else {
                // --- 単一 body：mailbox_key = SHA256(content_ref) ---
                let mailbox_key = SchrodingerMailbox::body_mailbox_key(&content_ref);
                fetch_object(
                    &node,
                    &mailbox,
                    &receive_tunnel_id,
                    &mailbox_key,
                    &k_pub,
                    std::time::Duration::from_secs(15),
                )
                .await?
            };

            match body {
                Some(bytes) => match out {
                    Some(path) => {
                        std::fs::write(path, &bytes)
                            .map_err(|e| format!("保存に失敗 {}: {}", path, e))?;
                        println!("\n--- 取得成功 ---\n{} バイトを {} に保存しました\n", bytes.len(), path);
                    }
                    None => {
                        println!("\n--- 取得成功 ---\n{}\n", String::from_utf8_lossy(&bytes))
                    }
                },
                None => println!("取得できませんでした（保持者が居ないか、期限切れ）"),
            }
        }

        Commands::Id => {
            let identity = load_identity(&cli.data_dir)?;
            println!("{}", identity.public_id());
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
            let identity = load_identity(&cli.data_dir)?;
            println!("Node ID: {}", identity.public_id());

            // 連絡先を解決する。秘密を省いた `--contact <NodeId>` は
            // 相手の NodeId から自動鍵合意する（3-1 ③・`--secret` 手渡し不要）。
            let mut contacts: Vec<(aether_core::crypto::identity::NodeId, [u8; 32])> = {
                let mut resolved = Vec::new();
                for spec in contacts {
                    let (nid, sec_opt) = parse_contact(spec)?;
                    let secret = match sec_opt {
                        Some(s) => s,
                        None => {
                            println!("連絡先 {} と鍵を自動合意します（--secret 不要）", nid);
                            identity.agree(&nid)?
                        }
                    };
                    resolved.push((nid, secret));
                }
                resolved
            };

            // 公開キーワードの購読も同じ contacts マップに載せる（K_pub を秘密として扱う）。
            // どれが公開かは覚えておく（公開だけ再シード＋再放流する / 18.3-A,C）。
            let mut public_secrets = std::collections::HashSet::new();
            for keyword in subscribe {
                let k_pub = aether_core::crypto::keyword::derive_public_key(keyword)?;
                println!("公開キーワード「{}」を購読します", keyword.trim());
                contacts.push((keyword_target(&k_pub), k_pub));
                public_secrets.insert(k_pub);
            }

            let config = Config {
                listen_port: *port,
                node_id_pow_difficulty: *pow_difficulty,
                enable_port_mapping: *allow_port_mapping,
                epoch_beacon: *epoch_beacon,
                ..Default::default()
            };

            if *epoch_beacon {
                println!("エポックビーコン: 有効（drand から日次シードを取得します）");
            }

            if *pow_difficulty > 0 {
                println!(
                    "NodeId PoW (難易度 {}) を計算中... 起動時に1回だけかかります",
                    pow_difficulty
                );
            }

            let db_path = cli.data_dir.join("mailbox.db");
            let mut node = NodeServer::with_config_passphrase(
                *port,
                identity,
                &db_path,
                &config,
                env_passphrase().as_deref(),
            )?;

            // --- 到達性を確定させる ---
            //
            // これをやらないと 127.0.0.1 を広告し続け、
            // 実網では誰も繋げないアドレスがディレクトリに載る
            match advertise {
                Some(addr) => {
                    let addr: SocketAddr = addr.parse()?;
                    node.declare_reachable(addr).await;
                    println!("到達性: 宣言済み {} (Tier 0)", addr);
                }
                None => {
                    println!("到達性を判定中 (STUN / ポートマッピング)...");
                    let result = node.discover_reachability(&config).await?;
                    println!(
                        "到達性: {:?} @ {} ({})",
                        result.tier, result.advertised, result.reason
                    );

                    if !result.tier.can_be_guard() {
                        println!(
                            "  → ガードにはなれませんが、Connection Reversal で保持者にはなれます"
                        );
                    }
                }
            }

            let node = Arc::new(node);

            println!("待ち受け開始。Ctrl+C で停止します");

            let running = node.clone();
            let server = tokio::spawn(async move { running.run().await });

            // **run() が受信ループを立ててから参加要求を出す。**
            // 応答はこちらが張った接続の上で返ってくるので、
            // 先に投げると誰も読んでいない接続に届いて捨てられる
            if let Some(seed) = connect {
                let seed: SocketAddr = seed.parse()?;
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                node.bootstrap(seed).await?;
                println!("種ノード {} へ参加要求を送信しました", seed);
            } else {
                println!("種ノードが未指定です (--connect)。単独で待ち受けます");
            }

            // **KeyStore は1プロセスに1ハンドルだけ。** sled は DB ディレクトリを排他
            // ロックするので、受信タスクと公開タスクが別々に開くと衝突する。1つ開いて
            // Arc で共有する。
            let keystore = Arc::new(open_keystore(&cli.data_dir)?);

            // **X3DH プレキーを、受信・公開タスクを spawn する前に確定させる。**
            // 両タスクは起動時に prekeys を読む。ここで生成・永続化しておかないと、
            // 受信タスクが「まだ未生成」を掴んで初回接触を respond できない（競合）。
            if keystore.load_prekeys()?.is_none() {
                let id = load_identity(&cli.data_dir)?;
                let (bundle, secrets) = aether_core::crypto::x3dh::generate_prekeys(&id, false);
                keystore.save_prekeys(&bundle, &secrets)?;
                println!("X3DH プレキーを生成しました（初回接触を受信できます）");
            }

            if !contacts.is_empty() {
                spawn_receiver(
                    node.clone(),
                    contacts,
                    public_secrets,
                    keystore.clone(),
                    cli.data_dir.clone(),
                );
            }

            // X3DH の受信側：プレキー束を網へ公開しておく（誰からでも初回接触を受けられる）。
            // 束と秘密は KeyStore に永続化して再起動を跨いで再利用する。
            spawn_prekey_publisher(node.clone(), keystore.clone(), cli.data_dir.clone());

            // フィルタ判定はリレーが2台以上必要なので、収束を待ってから走らせる。
            // EIM + EIF と判明すると punch 不要の Tier 0 に上がる
            {
                let node = node.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    match node.check_filtering_shared().await {
                        aether_core::net::punch::NatFiltering::EndpointIndependent => {
                            println!("フィルタ判定: EIF → Tier 0 へ昇格（punch 不要）");
                        }
                        aether_core::net::punch::NatFiltering::Restricted => {
                            println!("フィルタ判定: 制限あり（punch が必要）");
                        }
                        aether_core::net::punch::NatFiltering::Unknown => {
                            println!("フィルタ判定: 保留（リレーが2台以上必要）");
                        }
                    }
                });
            }

            let status = node.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    println!(
                        "既知リレー: {} 台 / 保持エントリ: {} 件",
                        status.directory_size().await,
                        status.mailbox().len()
                    );
                }
            });

            tokio::select! {
                result = server => { result??; }
                _ = tokio::signal::ctrl_c() => {
                    println!("\n停止します");
                }
            }
        }
    }

    Ok(())
}

/// 自分宛ての Hint を拾って本文を表示し続ける
///
/// # なぜ Inbound Tunnel が要るか
///
/// Mailbox から直接返させると、要求者の IP が Mailbox に割れる。
/// 「誰がどのコンテンツを取りに来たか」は受信者匿名性を直接壊す。
/// 手前に Gateway を1枚挟み、Mailbox には Gateway しか見せない。
fn spawn_receiver(
    node: Arc<NodeServer>,
    contacts: Vec<(aether_core::crypto::identity::NodeId, [u8; 32])>,
    public_secrets: std::collections::HashSet<[u8; 32]>,
    keystore: Arc<aether_core::storage::keystore::KeyStore>,
    data_dir: PathBuf,
) {
    use std::collections::HashMap;

    /// 公開コンテンツを保持者として維持する間隔（18.3-A,C）
    const REPUBLISH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

    tokio::spawn(async move {
        if let Err(e) = receive_loop(node, contacts, public_secrets, keystore, data_dir).await {
            eprintln!("受信を継続できません: {}", e);
        }
    });

    async fn receive_loop(
        node: Arc<NodeServer>,
        contacts: Vec<(aether_core::crypto::identity::NodeId, [u8; 32])>,
        public_secrets: std::collections::HashSet<[u8; 32]>,
        keystore: Arc<aether_core::storage::keystore::KeyStore>,
        data_dir: PathBuf,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Mailbox に載せる購読秘密。復元時に「どの秘密で開いたか」の照合にも使う。
        let secrets: HashMap<_, _> = contacts.iter().copied().collect();
        let me = node.descriptor.node_id;

        // X3DH の受信側：自分の Identity と、公開済みプレキーの秘密。
        // 初回接触（InitialMessage 付き）を respond して SK を復元するのに要る。
        let identity = load_identity_shared(&data_dir)?;
        let prekeys = keystore.load_prekeys()?.map(|(_, s)| s);

        // Gateway を確立する。リレーリストの収束を待ちつつ、死んだ gateway を引いても
        // ディレクトリから外して別候補を試す（establish_pull_session / eviction）。
        // 受信は常駐なので、確立できなければ deadline まで粘る。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let session = loop {
            if node.directory_size().await == 0 {
                if std::time::Instant::now() > deadline {
                    return Err("Gateway になれるリレーが見つかりません".into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            }
            match establish_pull_session(&node, secrets.clone(), 4).await {
                Ok(s) => break s,
                Err(e) => {
                    if std::time::Instant::now() > deadline {
                        return Err(e);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        };
        let receive_tunnel_id = session.receive_tunnel_id;
        let mailbox = Arc::new(session.mailbox);
        println!("受信トンネル確立: Gateway {}", session.gateway_addr);

        let mut hints = node.gossip().subscribe();

        // シャードは順不同かつ重複して届く。3つ **異なる** インデックスが
        // 揃うまで貯め続ける（同じシャードが3枚来ても復元できない）。
        //
        // 複数メッセージが同時に飛んでくるので mailbox_key ごとに束ねる。
        // 封が別メッセージのシャードを弾くため、取り違えは起きない
        //
        // 揃わないまま放置すると、届く応答を全部抱え込んで際限なく太る。
        // 3枚集まらない = 保持者が落ちたということなので、諦めて捨てる
        struct PendingBody {
            secret: [u8; 32],
            /// mailbox_key の素。再放流 (18.3-A) に要る
            nonce: [u8; 32],
            shards: Vec<Vec<u8>>,
            since: std::time::Instant,
        }
        const PENDING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

        let mut pending: HashMap<[u8; 32], PendingBody> = HashMap::new();

        loop {
            tokio::select! {
                hint = hints.recv() => {
                    match hint {
                        Ok(hint) => {
                            // 自分宛てでなければ何も起きない（手元だけで判定）
                            if let Ok(Some(key)) = mailbox.process_hint(&hint).await {
                                println!("自分宛ての Hint を検出 (mailbox_key {}...)",
                                    hex::encode(&key[..8]));

                                // nonce と共有秘密を控える（復元と再放流に要る）
                                if let Some((nonce, secret)) = mailbox.decrypt_hint(&hint) {
                                    pending.entry(key).or_insert_with(|| PendingBody {
                                        secret,
                                        nonce,
                                        shards: Vec::new(),
                                        since: std::time::Instant::now(),
                                    });
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            eprintln!("Hint を {} 件取りこぼしました", n);
                        }
                        Err(_) => return Ok(()),
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {}
            }

            let raw = node
                .mailbox()
                .fetch_tunnel_messages(&receive_tunnel_id)
                .await?;

            pending.retain(|_, p| p.since.elapsed() < PENDING_TIMEOUT);

            if raw.is_empty() {
                continue;
            }
            let decrypted = mailbox.decrypt_replies(&raw);

            let mut done = Vec::new();
            for (mailbox_key, p) in pending.iter_mut() {
                let secret = p.secret;
                // 封が別メッセージ・偽造を弾くので、素通しで足していい
                p.shards.extend(decrypted.iter().cloned());

                let is_public = public_secrets.contains(&secret);
                let msg: Option<Vec<u8>> = if is_public {
                    // 公開コンテンツ：静的 K_pub で復号
                    mailbox.reassemble(&p.shards, mailbox_key, &secret).ok().flatten()
                } else if let Ok(Some(body)) =
                    mailbox.reassemble_raw(&p.shards, mailbox_key, &secret)
                {
                    // 私信：生本体を復元し、フレームを開く（**前方秘匿**）。
                    // 初回接触なら InitialMessage を respond して X3DH SK でラチェットを立て、
                    // 継続なら保存済み Session で開く（[`open_private_body`]）。
                    match secrets.iter().find(|(_, s)| **s == secret).map(|(id, _)| *id) {
                        Some(contact) => open_private_body(
                            &keystore,
                            &identity,
                            prekeys.as_ref(),
                            &me,
                            &contact,
                            &body,
                        )?,
                        None => None,
                    }
                } else {
                    None
                };

                if let Some(msg) = msg {
                    // X3DH が無いので「差出人」は名乗れない。分かるのは「どの秘密で開いたか」だけ
                    let label = secrets
                        .iter()
                        .find(|(_, s)| **s == secret)
                        .map(|(id, _)| id.to_string())
                        .unwrap_or_else(|| "?".into());

                    println!(
                        "\n--- 受信 (contact {}) ---\n{}\n",
                        label,
                        String::from_utf8_lossy(&msg)
                    );

                    // 公開コンテンツなら、ダウンローダが保持者になる (18.3-C) +
                    // Hint を再放流する (18.3-A)。私信はここで役目を終えるので何もしない。
                    if is_public {
                        let mailbox = mailbox.clone();
                        let mailbox_key = *mailbox_key;
                        let nonce = p.nonce;
                        let sealed = p.shards.clone();
                        tokio::spawn(async move {
                            match mailbox.reseed(&mailbox_key, &secret, &sealed).await {
                                Ok(n) => println!(
                                    "公開コンテンツを保持者として再シード ({} shard) + Hint 再放流",
                                    n
                                ),
                                Err(e) => eprintln!("再シードに失敗: {}", e),
                            }
                            let _ = mailbox.republish(&secret, &nonce).await;

                            // 以降は定期的に維持する（人気なほど保持者が多く、頻度が上がる）
                            loop {
                                tokio::time::sleep(REPUBLISH_INTERVAL).await;
                                let _ = mailbox.reseed(&mailbox_key, &secret, &sealed).await;
                                let _ = mailbox.republish(&secret, &nonce).await;
                            }
                        });
                    }

                    done.push(*mailbox_key);
                }
            }
            for key in done {
                pending.remove(&key);
            }
        }
    }
}
