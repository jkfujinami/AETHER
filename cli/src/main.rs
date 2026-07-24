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
#[command(name = "aether")]
#[command(about = "AETHER Protocol CLI", long_about = None)]
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
    },
    /// メッセージを送る
    ///
    /// **共有秘密は事前共有が前提。** X3DH（鍵合意）は未実装なので、
    /// 相手と別経路で取り決めた値を `--secret` で渡す。
    Send {
        /// 宛先の Node ID (hex 64文字)
        #[arg(long)]
        to: String,

        /// 事前共有秘密 (hex 64文字)
        ///
        /// 相手と同じ値を使うこと。異なると相手は Hint を復号できない。
        #[arg(long)]
        secret: String,

        /// 本文
        #[arg(long)]
        message: String,

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

/// `<NodeId hex>:<共有秘密 hex>` を分解する
fn parse_contact(
    spec: &str,
) -> Result<(aether_core::crypto::identity::NodeId, [u8; 32]), Box<dyn Error>> {
    let (id, secret) = spec
        .split_once(':')
        .ok_or("--contact は <NodeId hex>:<共有秘密 hex> の形式です")?;

    Ok((
        aether_core::crypto::identity::NodeId(parse_hex32(id, "--contact の NodeId")?),
        parse_hex32(secret, "--contact の共有秘密")?,
    ))
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let bytes = hex::decode(s).map_err(|e| format!("{} が hex ではありません: {}", what, e))?;

    bytes
        .try_into()
        .map_err(|_| format!("{} は 32 バイト (hex 64文字) である必要があります", what).into())
}

fn identity_path(data_dir: &Path) -> PathBuf {
    data_dir.join("identity.key")
}

fn load_identity(data_dir: &Path) -> Result<Identity, Box<dyn Error>> {
    let path = identity_path(data_dir);

    let bytes = std::fs::read(&path).map_err(|e| {
        format!(
            "鍵を読み込めません ({}): {}\n先に `aether init` を実行してください",
            path.display(),
            e
        )
    })?;

    Ok(Identity::from_bytes(&bytes)?)
}

/// 鍵を保存する
///
/// **所有者以外が読めないようにする。** 同じマシンの他ユーザからも守る。
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
    std::fs::write(&path, identity.to_bytes())?;

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
            message,
            connect,
            port,
            min_relays,
        } => {
            use aether_core::crypto::identity::NodeId;
            use aether_core::crypto::key_exchange::EphemeralKey;
            use aether_core::mailbox::schrodinger::SchrodingerMailbox;
            use aether_core::net::gossip::GossipClient;
            use aether_core::net::onion::OnionCircuit;
            use aether_core::net::relay::RelayClient;
            use std::collections::HashMap;
            use std::sync::Mutex;

            let target = NodeId(parse_hex32(to, "--to")?);
            let shared_secret = parse_hex32(secret, "--secret")?;

            let identity = load_identity(&cli.data_dir)?;
            let config = Config {
                listen_port: *port,
                node_id_pow_difficulty: 0, // 送信だけなのでリレーとしては振る舞わない
                ..Default::default()
            };

            let db_path = cli.data_dir.join("mailbox.db");
            let node = Arc::new(NodeServer::with_config(
                *port,
                identity,
                &db_path,
                &config,
            )?);

            let running = node.clone();
            tokio::spawn(async move { running.run().await });

            // run() が受信を回してから参加する
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            node.bootstrap(connect.parse()?).await?;
            println!("種ノード {} へ参加しました。リレーを探しています...", connect);

            // 回路を張るにはリレーが要る
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                if node.directory_size().await > *min_relays {
                    break;
                }
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

            // --- Onion 回路を張る ---
            //
            // ガードは Tier 0 からしか選べない。punch が要る相手をガードにすると
            // 仲介役にクライアントとガードの対応が漏れる
            let directory = node.directory();
            let hops = {
                let dir = directory.read().await;
                dir.random_path(1, &[node.descriptor.node_id])
            };

            let hop = hops
                .first()
                .ok_or("到達可能なリレーが見つかりません")?
                .clone();

            let mut body_client = RelayClient::new()?;
            body_client.connect_entry(hop.addr).await?;
            let mut circuit = OnionCircuit::new(1);
            circuit.add_hop(hop.addr, hop.x25519_pub, EphemeralKey::generate())?;
            body_client.set_circuit(circuit);

            let mut hint_client = RelayClient::new()?;
            hint_client.connect_entry(hop.addr).await?;
            let mut hint_circuit = OnionCircuit::new(1);
            hint_circuit.add_hop(hop.addr, hop.x25519_pub, EphemeralKey::generate())?;
            hint_client.set_circuit(hint_circuit);

            println!("出口リレー: {}", hop.addr);

            let contacts = Arc::new(Mutex::new(HashMap::new()));
            contacts.lock().unwrap().insert(target, shared_secret);

            let mailbox = SchrodingerMailbox::with_directory(
                Arc::new(body_client),
                Arc::new(GossipClient::new(hint_client)),
                contacts,
                node.directory(),
            );

            // --- 本体を配置 ---
            let (hint, mailbox_key, profile) =
                mailbox.place_body_profiled(&target, message.as_bytes()).await?;

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
            println!("Hint を放流しました。送信完了");

            // 拡散が回るまで少し待つ
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
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
        } => {
            let contacts: Vec<_> = contacts
                .iter()
                .map(|c| parse_contact(c))
                .collect::<Result<_, _>>()?;

            let identity = load_identity(&cli.data_dir)?;
            println!("Node ID: {}", identity.public_id());

            let config = Config {
                listen_port: *port,
                node_id_pow_difficulty: *pow_difficulty,
                enable_port_mapping: *allow_port_mapping,
                ..Default::default()
            };

            if *pow_difficulty > 0 {
                println!(
                    "NodeId PoW (難易度 {}) を計算中... 起動時に1回だけかかります",
                    pow_difficulty
                );
            }

            let db_path = cli.data_dir.join("mailbox.db");
            let mut node = NodeServer::with_config(*port, identity, &db_path, &config)?;

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

            if !contacts.is_empty() {
                spawn_receiver(node.clone(), contacts);
            }

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
) {
    use aether_core::mailbox::schrodinger::SchrodingerMailbox;
    use aether_core::net::gossip::GossipClient;
    use aether_core::net::onion::OnionCircuit;
    use aether_core::net::relay::RelayClient;
    use aether_core::net::tunnel::InboundTunnel;
    use aether_core::protocol::wire::PacketType;
    use std::collections::HashMap;
    use std::sync::Mutex;

    tokio::spawn(async move {
        if let Err(e) = receive_loop(node, contacts).await {
            eprintln!("受信を継続できません: {}", e);
        }
    });

    async fn receive_loop(
        node: Arc<NodeServer>,
        contacts: Vec<(aether_core::crypto::identity::NodeId, [u8; 32])>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Gateway を選ぶにはリレーリストの収束を待つ必要がある
        let directory = node.directory();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let gateway = loop {
            let picked = {
                let dir = directory.read().await;
                dir.random_path(1, &[node.descriptor.node_id]).into_iter().next()
            };

            if let Some(g) = picked {
                break g;
            }
            if std::time::Instant::now() > deadline {
                return Err("Gateway になれるリレーが見つかりません".into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        };

        // Gateway → 自分 の2ホップ。Mailbox からは Gateway しか見えない
        let (tunnel, instructions) = InboundTunnel::build(
            vec![gateway.addr, node.descriptor.addr],
            vec![gateway.x25519_pub, node.descriptor.x25519_pub],
        )?;
        let receive_tunnel_id = tunnel.receive_tunnel_id;

        let builder = RelayClient::new()?;
        for (addr, payload) in instructions {
            builder
                .send_direct_packet(addr, PacketType::TunnelBuild, &payload)
                .await?;
        }
        println!("受信トンネル確立: Gateway {}", gateway.addr);

        // 取得要求を出すための出口回路
        let mut fetch_client = RelayClient::new()?;
        fetch_client.connect_entry(gateway.addr).await?;
        let mut circuit = OnionCircuit::new(1);
        circuit.add_hop(
            gateway.addr,
            gateway.x25519_pub,
            aether_core::crypto::key_exchange::EphemeralKey::generate(),
        )?;
        fetch_client.set_circuit(circuit);

        let secrets: HashMap<_, _> = contacts.iter().copied().collect();
        let mailbox = SchrodingerMailbox::with_directory(
            Arc::new(fetch_client),
            Arc::new(GossipClient::new(RelayClient::new()?)),
            Arc::new(Mutex::new(secrets.clone())),
            directory,
        );
        mailbox.register_inbound_tunnel(tunnel);

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

                                // どの共有秘密で開いたかを控える。復元に要る
                                if let Some((_, secret)) = mailbox.try_decrypt_hint(&hint) {
                                    pending.entry(key).or_insert_with(|| PendingBody {
                                        secret,
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
                let (secret, collected) = (&p.secret, &mut p.shards);
                // 封が別メッセージ・偽造を弾くので、素通しで足していい
                collected.extend(decrypted.iter().cloned());

                if let Ok(Some(msg)) = mailbox.reassemble(collected, mailbox_key, secret) {
                    // X3DH が無いので「差出人」は名乗れない。
                    // 分かるのは「どの共有秘密で開いたか」だけ
                    let label = secrets
                        .iter()
                        .find(|(_, s)| *s == secret)
                        .map(|(id, _)| id.to_string())
                        .unwrap_or_else(|| "?".into());

                    println!(
                        "\n--- 受信 (contact {}) ---\n{}\n",
                        label,
                        String::from_utf8_lossy(&msg)
                    );
                    done.push(*mailbox_key);
                }
            }
            for key in done {
                pending.remove(&key);
            }
        }
    }
}
