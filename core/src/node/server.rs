use crate::error::Result;
use crate::net::quic::QuicServer;
use crate::protocol::wire::{self, PacketType};
use crate::node::router::{Router, RoutingAction};
use crate::mailbox::server::MailboxServer;
use crate::net::gossip_server::{self, GossipServer, HintAction};
use crate::net::hint_batcher::{self, HintBatcher};
use crate::net::hint_log::{HintDigest, HintLog};
use crate::net::dandelion::{DandelionRouter, Route};
use crate::protocol::hint::current_timestamp;
use crate::net::pex::{self, PexRequest, PexResponse};
use crate::net::relay_list::{RelayDescriptor, RelayDirectory};
use crate::net::reachability::{self, Reachability, Tier};
use crate::net::punch::{self, FilterProbeOrder, NatFiltering, PunchNotify, PunchRequest, PunchSession};
use crate::net::shared_socket::SharedSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::crypto::pow;
use crate::protocol::hint::HintPacket;
use crate::net::tunnel::TunnelRelay;
use crate::node::peer::PeerManager;
use crate::crypto::identity::{Identity, NodeId};
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tracing::{info, error, debug};
use crate::Config;
use std::path::Path;
use std::net::SocketAddr;
use std::time::Duration;

/// 1つの Hint を何ピアへ拡散するか
const GOSSIP_FANOUT: usize = 3;

/// Hint backlog の複製数（19.1.3）。本体シャードの K と揃える
const HINT_REPLICAS: usize = 5;

/// Hint backlog の差分同期間隔
const HINT_RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// Dandelion++ の stem フェイルセーフ (3-2)
///
/// stem した Hint がこの時間内に fluff で戻ってこなければ、自分で fluff する。
/// stem 後継が黒穴でも配送を保証する。
const DANDELION_STEM_TIMEOUT: Duration = Duration::from_secs(3);

/// 期限切れデータの掃除間隔
const GC_INTERVAL: Duration = Duration::from_secs(300);

/// PEX の最短間隔（収束中）
///
/// 参加直後はリストが空同然なので、素早く回して網全体を掴む。
const PEX_MIN_INTERVAL: Duration = Duration::from_millis(500);

/// PEX の最長間隔（収束後）
///
/// 新しいリレーが見つからなくなったらここまで落とす。
const PEX_MAX_INTERVAL: Duration = Duration::from_secs(30);

/// 1回の PEX で何台に問い合わせるか
const PEX_FANOUT: usize = 3;

/// 1ピアへの Hint 拡散を諦めるまでの時間
///
/// 到達不能なピア（クライアント専用ノード等）が混ざっていても
/// 拡散全体が止まらないようにする。
const GOSSIP_RELAY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct NodeServer {
    pub server: QuicServer,
    pub router: Arc<Router>,
    pub mailbox: Arc<MailboxServer>,
    pub gossip: Arc<GossipServer>,
    pub tunnel_relay: Arc<RwLock<TunnelRelay>>,
    pub peers: Arc<PeerManager>,
    pub batcher: Arc<HintBatcher>,
    /// 自分の記述子。PEX で配る
    pub descriptor: RelayDescriptor,
    /// ローカルに保持するリレーリスト
    pub directory: Arc<RwLock<RelayDirectory>>,
    /// フィルタ判定の待ち状態
    ///
    /// `true` の間に**一度も話していない相手から**プローブが届けば EIF。
    filter_check_pending: Arc<AtomicBool>,
    /// フィルタ判定の結果
    filtering: Arc<RwLock<NatFiltering>>,
    /// 分散 Hint backlog（19.1.3・オフライン受信）
    hint_log: Arc<Mutex<HintLog>>,
    /// Dandelion++ の経路ポリシー（放流元秘匿 / 3-2）
    dandelion: Arc<Mutex<DandelionRouter>>,
}


/// 各サブシステムへの共有ハンドル
///
/// 中身はすべて `Arc` なので clone は安価。
#[derive(Clone)]
pub struct PacketContext {
    pub router: Arc<Router>,
    pub mailbox: Arc<MailboxServer>,
    pub gossip: Arc<GossipServer>,
    pub tunnel_relay: Arc<RwLock<TunnelRelay>>,
    pub peers: Arc<PeerManager>,
    pub batcher: Arc<HintBatcher>,
    pub descriptor: RelayDescriptor,
    pub directory: Arc<RwLock<RelayDirectory>>,
    pub socket: Arc<SharedSocket>,
    pub local_addr: SocketAddr,
    /// この接続の相手として**観測された**アドレス
    ///
    /// 申告値ではないので、フィルタ判定のプローブ先に使っても
    /// 第三者へ撃たせる踏み台にならない。
    pub remote_addr: Option<SocketAddr>,
    /// 分散 Hint backlog（19.1.3）
    pub hint_log: Arc<Mutex<HintLog>>,
    /// Dandelion++ の経路ポリシー（3-2）
    pub dandelion: Arc<Mutex<DandelionRouter>>,
}

impl NodeServer {
    pub fn new(port: u16, identity: Identity, db_path: &Path) -> Result<Self> {
        Self::with_config(port, identity, db_path, &Config { listen_port: port, ..Default::default() })
    }

    /// 設定を指定して起動する
    ///
    /// `config.node_id_pow_difficulty` が高いと、起動時の PoW 探索に
    /// その時間がかかる（1回だけ）。テストでは 0 を指定すること。
    pub fn with_config(
        port: u16,
        identity: Identity,
        db_path: &Path,
        config: &Config,
    ) -> Result<Self> {
        let config = Config { listen_port: port, ..config.clone() };
        let server = QuicServer::new(&config)?;

        // Modules init
        let identity = Arc::new(identity);
        // 待ち受けと同じソケットから発信する（NAT マッピングを共有）
        let router = Arc::new(Router::with_endpoint(identity.clone(), server.endpoint())?);
        let mailbox = Arc::new(MailboxServer::new(db_path, &config)?);
        let gossip = Arc::new(GossipServer::new(&config));
        let tunnel_relay = Arc::new(RwLock::new(TunnelRelay::new()));
        let peers = Arc::new(PeerManager::new());
        let batcher = Arc::new(HintBatcher::new());

        // 自分の記述子を組み立てる。NodeId PoW はここで1回だけ解く
        let node_id = identity.public_id();
        let x25519_pub = x25519_dalek::PublicKey::from(&identity.x25519_secret()).to_bytes();
        let pow_nonce = pow::node_id::solve(
            node_id.as_bytes(),
            config.node_id_pow_difficulty,
            1 << 24,
        )?;

        // **引数の port ではなく実際にバインドされたポートを使う。**
        // port=0 を渡した場合、引数は 0 のままなので広告が壊れる。
        let bound_port = server.local_addr()?.port();

        let descriptor = RelayDescriptor {
            node_id,
            addr: format!("127.0.0.1:{}", bound_port).parse()
                .map_err(|e| crate::AetherError::Config(format!("Invalid advertise address: {}", e)))?,
            x25519_pub,
            pow_nonce,
            uptime_secs: 0,
            // 到達性は起動後に調べる。判明するまでは最も控えめな等級。
            // 楽観的に Open と広告すると、届かないノードが
            // Mailbox やガードに選ばれて配送が落ちる
            tier: Tier::Reversed,
        };

        // 自分自身もリレーとしてリストに入れる。
        //
        // **これを入れないと、自分のリストだけが1件欠けた状態になり、
        // K最近接が他ノードと食い違う。** 自分が担当に選ばれていることに
        // 気づけず、置かれたはずのシャードを取りに来た相手に応答できない。
        // MailboxForward は既に「宛先が自分」の場合をローカル保存で処理している。
        let mut initial = RelayDirectory::new(
            crate::net::ring::EPOCH_SEED_PLACEHOLDER,
            config.node_id_pow_difficulty,
        );
        initial.insert(descriptor.clone())?;
        let directory = Arc::new(RwLock::new(initial));

        Ok(Self {
            server,
            router,
            mailbox,
            gossip,
            tunnel_relay,
            peers,
            batcher,
            descriptor,
            directory,
            filter_check_pending: Arc::new(AtomicBool::new(false)),
            filtering: Arc::new(RwLock::new(NatFiltering::Unknown)),
            hint_log: Arc::new(Mutex::new(HintLog::default())),
            dandelion: Arc::new(Mutex::new(DandelionRouter::new())),
        })
    }

    /// 広告するアドレスを差し替える（STUN で外部アドレスが判明した場合など）
    pub fn set_advertised_addr(&mut self, addr: SocketAddr) {
        self.descriptor.addr = addr;
    }

    /// 到達性が既知の場合に宣言する
    ///
    /// 公開 IP、手動ポート開放、コンテナの明示的な公開など、
    /// **STUN を待たずに到達可能と分かっている場合**に使う。
    /// 種ノードは通常こちら。
    ///
    /// 誤って宣言すると、届かないノードがガードや Mailbox に選ばれて
    /// 配送が落ちる。確信がある場合だけ使うこと。
    pub async fn declare_reachable(&mut self, addr: SocketAddr) {
        self.descriptor.addr = addr;
        self.descriptor.tier = Tier::Open;

        let mut dir = self.directory.write().await;
        dir.insert_unchecked(self.descriptor.clone());
    }

    /// 到達性を調べて記述子へ反映する
    ///
    /// **これを呼ばないと `127.0.0.1` を広告し続ける。**
    /// 実網では誰も繋げないアドレスがディレクトリに載ることになる。
    ///
    /// `run()` より前に呼ぶこと（PEX で配る前に確定させたい）。
    pub async fn discover_reachability(&mut self, config: &Config) -> Result<Reachability> {
        let Some(mut side_rx) = self.server.take_side_channel() else {
            return Err(crate::AetherError::Config(
                "Side channel already taken; reachability can only be probed once".into(),
            ));
        };

        let socket = self.server.shared_socket();
        let local = self.server.local_addr()?;

        let result = reachability::probe(
            &socket,
            &mut side_rx,
            local,
            &config.stun_servers,
            config.enable_port_mapping,
        )
        .await;

        // **必ず返す。** 返さないと punch の応答もフィルタ判定もできなくなる
        self.server.restore_side_channel(side_rx);

        self.descriptor.addr = result.advertised;
        self.descriptor.tier = result.tier;

        // 自分の記述子はディレクトリにも入っているので更新する。
        // ここを忘れると自分だけ古い Tier を見続ける
        {
            let mut dir = self.directory.write().await;
            dir.insert_unchecked(self.descriptor.clone());
        }

        // リースが切れると到達性を失うので更新を回し続ける
        if let Some(mapping) = result.port_mapping.clone() {
            reachability::spawn_renewal(mapping, local.port())?;
        }

        info!(
            "Reachability: {:?} at {} ({})",
            result.tier, result.advertised, result.reason
        );

        Ok(result)
    }

    /// 種ノードへ PEX を仕掛けてネットワークに参加する
    ///
    /// **これが MVP の起点。** 1台さえ知っていれば、そこから網全体へ収束する。
    ///
    /// # `run()` を先に開始しておくこと
    ///
    /// 応答は「こちらが張った接続」の上で返ってくる（Connection Reversal）。
    /// その受信を回すのは `run()` が立てるタスクなので、
    /// **`run()` より前に呼ぶと応答が黙って捨てられる。**
    pub async fn bootstrap(&self, seed: SocketAddr) -> Result<()> {
        let request = PexRequest::new(self.descriptor.clone()).encode()?;
        self.router
            .send_packet(seed, PacketType::PexRequest, &request)
            .await
    }

    /// 既知のリレー数
    pub async fn directory_size(&self) -> usize {
        self.directory.read().await.len()
    }

    pub async fn run(&self) -> Result<()> {
        let local_addr = self.server.local_addr()?;
        info!("AETHER Node running on {}", local_addr);

        self.spawn_gc();
        self.spawn_batch_flusher();
        self.spawn_pex();
        self.spawn_side_channel();
        self.spawn_hint_reconcile();

        // **自分がダイヤルした接続も受信を回す。**
        // Connection Reversal では相手がこの接続の上で押し返してくるので、
        // 読まないと応答が全て捨てられる
        {
            let mut opened = self.router.subscribe_opened();
            let ctx_template = PacketContext {
                router: self.router.clone(),
                mailbox: self.mailbox.clone(),
                gossip: self.gossip.clone(),
                tunnel_relay: self.tunnel_relay.clone(),
                peers: self.peers.clone(),
                batcher: self.batcher.clone(),
                descriptor: self.descriptor.clone(),
                directory: self.directory.clone(),
                socket: self.server.shared_socket(),
                local_addr,
                remote_addr: None,
                hint_log: self.hint_log.clone(),
                dandelion: self.dandelion.clone(),
            };

            tokio::spawn(async move {
                while let Some(connection) = opened.recv().await {
                    let ctx = ctx_template.clone();
                    tokio::spawn(async move {
                        Self::pump_streams(connection, ctx).await;
                    });
                }
            });
        }

        let ctx = PacketContext {
            router: self.router.clone(),
            mailbox: self.mailbox.clone(),
            gossip: self.gossip.clone(),
            tunnel_relay: self.tunnel_relay.clone(),
            peers: self.peers.clone(),
            batcher: self.batcher.clone(),
            descriptor: self.descriptor.clone(),
            directory: self.directory.clone(),
            socket: self.server.shared_socket(),
            local_addr,
            remote_addr: None,
            hint_log: self.hint_log.clone(),
            dandelion: self.dandelion.clone(),
        };

        while let Some(conn) = self.server.accept().await {
            let ctx = ctx.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(conn, ctx).await {
                    error!("Connection error: {}", e);
                }
            });
        }
        Ok(())
    }

    /// 接続の受信ストリームを読み続ける
    ///
    /// inbound / outbound を問わず、接続が生きている限り回す。
    async fn pump_streams(connection: quinn::Connection, ctx: PacketContext) {
        let remote = crate::net::addr::normalize(connection.remote_address());

        while let Ok(mut recv_stream) = connection.accept_uni().await {
            let mut ctx = ctx.clone();
            ctx.remote_addr = Some(remote);

            tokio::spawn(async move {
                match wire::read_packet(&mut recv_stream).await {
                    Ok((packet_type, payload)) => {
                        debug!("Received packet: {:?} ({} bytes)", packet_type, payload.len());
                        if let Err(e) = Self::process_packet(packet_type, payload, ctx).await {
                            error!("Error processing packet: {}", e);
                        }
                    }
                    Err(e) => debug!("Failed to read packet: {}", e),
                }
            });
        }
    }

    async fn handle_connection(conn: quinn::Incoming, ctx: PacketContext) -> Result<()> {
        let connection = conn.await.map_err(|e| crate::AetherError::Quic(e.to_string()))?;
        let remote_addr = connection.remote_address();
        debug!("New connection from {}", remote_addr);

        // ピアリストに追加
        ctx.peers.add_peer(remote_addr).await;

        // **接続をプールに登録する（Connection Reversal）**
        //
        // 相手が NAT の内側にいる場合、こちらからダイヤルしても届かない。
        // 相手が張ったこの接続だけが唯一の到達経路になる。
        // 登録しないと NAT 内ノードは保持者になれず、
        // キャッシュが「自分が取りに行ったものだけ」になって
        // 否認可能性が構造的に消える (18.3-C)。
        ctx.router.register_inbound(connection.clone()).await;

        Self::pump_streams(connection, ctx).await;
        Ok(())
    }

    async fn process_packet(
        packet_type: PacketType,
        payload: Vec<u8>,
        ctx: PacketContext,
    ) -> Result<()> {
        match packet_type {
            PacketType::OnionPacket => {

                match ctx.router.handle_packet(&payload).await? {
                    RoutingAction::Forwarded => {
                        // 転送完了
                        debug!("Onion packet forwarded");
                    },
                    RoutingAction::LocalProcessing(inner_payload) => {
                        // 出口リレーとして最終層を剥いた。中身の種別を見て振り分ける。
                        let (inner_type, body) = wire::parse_inner_packet(&inner_payload)?;
                        debug!("Onion packet reached exit. Inner type: {:?}", inner_type);

                        match inner_type {
                            wire::InnerPacketType::MailboxPut => {
                                ctx.mailbox.handle_put(body).await?;
                            }
                            wire::InnerPacketType::MailboxForward => {
                                // 出口リレーは中身を保存せず、指定された Mailbox へ渡すだけ。
                                // Mailbox 側から見える送信元は「出口リレーの IP」であり、
                                // Sybil で Mailbox の座を取っても発信者には近づけない。
                                let (dest, payload) = wire::parse_mailbox_forward(body)?;
                                debug!("Forwarding mailbox payload to {}", dest);

                                if dest.port() == ctx.local_addr.port() {
                                    // 自分自身が Mailbox に選ばれている場合は素直に保存する
                                    ctx.mailbox.handle_put(payload).await?;
                                } else {
                                    ctx.router
                                        .send_packet(dest, PacketType::MailboxPut, payload)
                                        .await?;
                                }
                            }
                            wire::InnerPacketType::TypedForward => {
                                // 出口リレーは中身を解釈せず、指定ノードへそのまま渡す。
                                let (dest, packet_type, inner) = wire::parse_typed_forward(body)?;
                                debug!("Forwarding {:?} to {}", packet_type, dest);

                                if dest.port() == ctx.local_addr.port() {
                                    Box::pin(Self::process_packet(packet_type, inner.to_vec(), ctx.clone())).await?;
                                } else {
                                    ctx.router.send_packet(dest, packet_type, inner).await?;
                                }
                            }
                            wire::InnerPacketType::GossipHint => {
                                // 出口リレーが Gossip ネットワークへの投入点になる。
                                // 送信者の IP はここまで届かない。**ここで Dandelion++ に入れる**：
                                // すぐ全放流せず、まず stem（1本道）で数ホップ運んでから fluff する。
                                Self::inject_hint(body, None, &ctx).await;
                            }
                        }
                    }
                }
            },
            PacketType::GossipHint => {
                Self::relay_hint(&payload, &ctx).await?;
            },
            PacketType::StemHint => {
                // Dandelion++ の stem 相。送り主を除外して次の判断（forward / fluff）へ。
                let sender = match ctx.remote_addr {
                    Some(addr) => {
                        let want = crate::net::addr::normalize(addr);
                        let dir = ctx.directory.read().await;
                        dir.all()
                            .into_iter()
                            .find(|d| crate::net::addr::normalize(d.addr) == want)
                            .map(|d| d.node_id)
                    }
                    None => None,
                };
                Self::inject_hint(&payload, sender, &ctx).await;
            },
            PacketType::GossipHintBatch => {
                Self::relay_hint_batch(&payload, &ctx).await?;
            },
            PacketType::HintDigest => {
                // 差分同期の要求。相手が持つ id 集合に無い自分の Hint を返す（19.1.3）。
                // id しか受け取らないので、どの Hint が誰宛てかは漏れない。
                let digest = HintDigest::decode(&payload)?;
                let response = {
                    let log = ctx.hint_log.lock().unwrap();
                    log.diff(&digest)
                };
                if let Some(dest) = ctx.remote_addr
                    && !response.is_empty()
                {
                    let bytes = bincode::serialize(&response)
                        .map_err(|e| crate::AetherError::Serialization(e.to_string()))?;
                    ctx.router
                        .send_packet(dest, PacketType::HintBacklog, &bytes)
                        .await?;
                }
            },
            PacketType::HintBacklog => {
                // 追いつき応答。**再拡散しない** ── 手元へ配って、担当なら保存するだけ。
                let packets: Vec<HintPacket> = bincode::deserialize(&payload)
                    .map_err(|e| crate::AetherError::Protocol(format!("Invalid HintBacklog: {}", e)))?;
                if packets.len() > gossip_server::MAX_HINTS_PER_BATCH {
                    debug!("Oversized HintBacklog discarded: {}", packets.len());
                    return Ok(());
                }
                for packet in packets {
                    Self::persist_if_responsible(&ctx, &packet).await;
                    ctx.gossip.deliver_local(packet).await;
                }
            },
            PacketType::PexRequest => {
                let request = PexRequest::decode(&payload)?;
                let requester_addr = request.requester.addr;

                // 要求者自身を取り込む。これで一方向の要求だけで相互に知り合える
                {
                    let mut dir = ctx.directory.write().await;
                    if let Err(e) = dir.insert(request.requester.clone()) {
                        debug!("Rejected requester descriptor: {}", e);
                    }
                }

                let response = {
                    let dir = ctx.directory.read().await;
                    pex::select_response(&dir, &request, Some(&ctx.descriptor))
                };

                debug!("PEX: returning {} relay(s) to {}", response.relays.len(), requester_addr);

                ctx.router
                    .send_packet(requester_addr, PacketType::PexResponse, &response.encode()?)
                    .await?;
            },
            PacketType::PunchRequest => {
                // 仲介役として双方へ相手の候補を伝える。
                //
                // ここで学ぶのは「どのリレーがどのリレーに繋ごうとしているか」で、
                // その接続グラフはディレクトリで既に公開されている。
                // **クライアント→ガードの punch を仲介してはならない**
                // （守ろうとしているペアそのものが漏れる）。
                let request = PunchRequest::decode(&payload)?;

                let (target, requester) = {
                    let dir = ctx.directory.read().await;
                    (
                        dir.get(&request.target).cloned(),
                        dir.get(&request.requester).cloned(),
                    )
                };

                let Some(target) = target else {
                    debug!("Punch target {} is unknown", request.target);
                    return Ok(());
                };

                // 相手へ: 要求者の候補
                let notify = PunchNotify {
                    peer: request.requester,
                    candidates: request.candidates.clone(),
                };
                let _ = ctx.router
                    .send_packet(target.addr, PacketType::PunchNotify, &notify.encode()?)
                    .await;

                // 要求者へ: 相手の候補
                if let Some(requester) = requester {
                    let back = PunchNotify {
                        peer: request.target,
                        candidates: vec![target.addr],
                    };
                    let _ = ctx.router
                        .send_packet(requester.addr, PacketType::PunchNotify, &back.encode()?)
                        .await;
                }
            },
            PacketType::PunchNotify => {
                let notify = PunchNotify::decode(&payload)?;
                debug!("Punching towards {} candidate(s)", notify.candidates.len());

                // 通知を受けたら一定時間プローブし続ける。
                // 双方が同じことをするので、時計を合わせなくても窓が重なる
                let socket = ctx.socket.clone();
                tokio::spawn(async move {
                    let mut session = PunchSession::new();
                    let deadline = tokio::time::Instant::now() + punch::PROBE_WINDOW;

                    while tokio::time::Instant::now() < deadline {
                        let _ = session.probe_round(&socket, &notify.candidates).await;
                        tokio::time::sleep(punch::PROBE_INTERVAL).await;
                    }
                });
            },
            PacketType::FilterCheck => {
                // **要求者が申告したアドレスではなく、観測した送信元へ撃たせる。**
                // 申告を信じると、第三者のアドレスを書いて他人にパケットを
                // 撃たせる増幅の踏み台になる。
                let Some(target) = ctx.remote_addr else {
                    debug!("FilterCheck without an observed source");
                    return Ok(());
                };

                // **自分と要求者の両方を除外する。**
                // 自分が撃つと「一度も話していない相手から」にならない。
                // 要求者自身を選ぶと自分宛てに撃つことになり、やはり判定にならない。
                let third_party = {
                    let dir = ctx.directory.read().await;
                    dir.all()
                        .into_iter()
                        .find(|r| {
                            r.node_id != ctx.descriptor.node_id
                                && crate::net::addr::normalize(r.addr).ip() != target.ip()
                        })
                        .cloned()
                };

                if let Some(relay) = third_party {
                    let order = FilterProbeOrder { target };
                    let _ = ctx.router
                        .send_packet(relay.addr, PacketType::FilterProbeOrder, &order.encode()?)
                        .await;
                }
            },
            PacketType::FilterProbeOrder => {
                // 第三者として1発だけ撃つ。
                // 相手のフィルタが EIF ならこれが届く
                let order = FilterProbeOrder::decode(&payload)?;

                let probe = punch::build_probe(stun::agent::TransactionId::new())?;
                let _ = ctx.socket.send_raw(order.target, &probe).await;
            },
            PacketType::PexResponse => {
                let response = PexResponse::decode(&payload)?;
                let count = response.relays.len();

                let added = {
                    let mut dir = ctx.directory.write().await;
                    pex::absorb_response(&mut dir, response)
                };

                debug!("PEX: learned {} new relay(s) out of {}", added, count);
            },
            PacketType::MailboxPut => {
                ctx.mailbox.handle_put(&payload).await?;
            },
            PacketType::IndexPut => {
                // 索引に記述子を1件追加（19.7 / Phase 2-3）
                ctx.mailbox.handle_index_put(&payload).await?;
            },
            PacketType::IndexQuery => {
                // 索引の列挙。返信は Inbound Tunnel 経由（検索者の IP を隠す）。
                let (index_key, reply_to) = wire::parse_mailbox_get(&payload)?;

                let records = ctx.mailbox.handle_index_list(&index_key).await?;
                if !records.is_empty() {
                    // 1メッセージにまとめて返す: [TunnelID(32)][bincode(Vec<record>)]
                    let body = bincode::serialize(&records)
                        .map_err(|e| crate::AetherError::Serialization(e.to_string()))?;
                    let mut tunnel_payload = Vec::with_capacity(32 + body.len());
                    tunnel_payload.extend_from_slice(&reply_to.tunnel_id);
                    tunnel_payload.extend_from_slice(&body);

                    if let Err(e) = ctx
                        .router
                        .send_packet(reply_to.gateway, PacketType::TunnelData, &tunnel_payload)
                        .await
                    {
                        debug!("Failed to reply to index query tunnel: {}", e);
                    }
                }
            },
            PacketType::MailboxGet => {
                // 要求側が返信先の Inbound Tunnel を同梱している。
                // uni-directional stream なので直接は返せず、
                // また直接返せてしまうと要求者の IP が割れる。
                let (key, reply_to) = wire::parse_mailbox_get(&payload)?;

                match ctx.mailbox.handle_get(&key).await? {
                    Some(value) => {
                        debug!("Mailbox GET hit. Replying via tunnel {}", reply_to.gateway);

                        // TunnelData: [TunnelID(32)][Data]
                        let mut tunnel_payload = Vec::with_capacity(32 + value.len());
                        tunnel_payload.extend_from_slice(&reply_to.tunnel_id);
                        tunnel_payload.extend_from_slice(&value);

                        if let Err(e) = ctx
                            .router
                            .send_packet(reply_to.gateway, PacketType::TunnelData, &tunnel_payload)
                            .await
                        {
                            debug!("Failed to reply to tunnel gateway: {}", e);
                        }
                    }
                    None => {
                        // 見つからなかったことは返さない。
                        // 「無い」という応答自体が、要求されたキーの不在を第三者に晒す。
                        debug!("Mailbox GET miss");
                    }
                }
            },
            PacketType::TunnelBuild => {
                match ctx.router.process_tunnel_build(&payload) {
                    Ok((tid, shared_secret, inst)) => {
                        if let Some(next) = inst.next_hop {
                            let mut relay = ctx.tunnel_relay.write().await;
                            relay.register_tunnel(tid, shared_secret, next, inst.next_tunnel_id);
                            debug!("Tunnel registered: ID={:?} -> {}", tid, next);
                        } else {
                            // Inbound Tunnel では自分自身も「次のホップ」として指定されるはず
                             tracing::warn!("TunnelBuild with no next_hop received. Ignoring.");
                        }
                    },
                    Err(e) => {
                        error!("Failed to process TunnelBuild: {}", e);
                    }
                }
            },
            PacketType::TunnelData => {
                // Tunnel Data: [TunnelID(32)][Nonce(12)][EncryptedData]
                if payload.len() < 32 + 12 {
                    error!("TunnelData packet too short");
                    return Ok(());
                }

                let tunnel_id: [u8; 32] = payload[0..32].try_into().unwrap();
                let data = &payload[32..];

                let relay = ctx.tunnel_relay.read().await;
                match relay.process_tunnel_data(&tunnel_id, data) {
                    Ok(Some((next_hop, next_tunnel_id, forwarded_data))) => {
                        // Check if we are the destination (Inbound Tunnel Endpoint)
                        // Compare by port since local_addr might be 0.0.0.0 while next_hop is 127.0.0.1
                        if next_hop.port() == ctx.local_addr.port() {
                             debug!("Tunnel: reached endpoint (self), storing message for ID {:?}", tunnel_id);
                             // Store raw tunnel data. The client will fetch and decrypt it later.
                             // Not using next_tunnel_id, but the original tunnel_id as key.
                             if let Err(e) = ctx.mailbox.store_tunnel_message(&tunnel_id, &forwarded_data).await {
                                 error!("Store tunnel msg failed: {}", e);
                             }
                        } else {
                             // Forwarding
                             debug!("Tunnel: forwarding to {}", next_hop);

                             // New packet: [NextTunnelID][Nonce][EncData]
                             let mut next_payload = Vec::with_capacity(32 + forwarded_data.len());
                             next_payload.extend_from_slice(&next_tunnel_id);
                             next_payload.extend_from_slice(&forwarded_data);

                             // Drop lock before async call
                             drop(relay); // Important: drop lock here, not inside block if possible, but we branch

                             if let Err(e) = ctx.router.send_packet(next_hop, PacketType::TunnelData, &next_payload).await {
                                  error!("Tunnel forwarding failed: {}", e);
                             }
                             return Ok(()); // Lock already dropped or not needed
                        }
                        // If we didn't return, drop lock
                        // drop(relay); // Already dropped above if forwarding. If stored, drop now.
                    },
                    Ok(None) => {
                         // Should not happen with current logic, but just in case
                         debug!("Tunnel: process_tunnel_data returned None");
                    },
                    Err(e) => {
                        error!("Tunnel processing error: {}", e);
                    }
                }
                // Explicit drop if not forwarded (compiler will handle scope drop, but manual drop for clarity)
                // drop(relay);
            },
            _ => {
                info!("Unhandled packet type: {:?}", packet_type);
            }
        }
        Ok(())
    }

    /// Dandelion++ の注入点 ── stem（1本道）で運ぶか fluff（放流）するか決める (3-2)
    ///
    /// onion 出口での投入と、stem 相の中継の両方から呼ぶ。stem なら単一の後継へ
    /// [`StemHint`](PacketType::StemHint) を送る。fluff なら通常の gossip 放流
    /// ([`relay_hint`](Self::relay_hint)) に落とす。
    ///
    /// **フェイルセーフ:** stem した Hint が [`DANDELION_STEM_TIMEOUT`] 内に fluff で
    /// 戻ってこなければ自分で fluff する。stem 後継が黒穴でも配送を保証する。
    async fn inject_hint(hint_bytes: &[u8], sender: Option<NodeId>, ctx: &PacketContext) {
        let packet: HintPacket = match bincode::deserialize(hint_bytes) {
            Ok(p) => p,
            Err(e) => {
                debug!("Invalid Hint for injection discarded: {}", e);
                return;
            }
        };

        // 拡散先候補 = ディレクトリの他ノード
        let neighbors: Vec<NodeId> = {
            let dir = ctx.directory.read().await;
            dir.all()
                .into_iter()
                .map(|d| d.node_id)
                .filter(|id| *id != ctx.descriptor.node_id)
                .collect()
        };

        // 注入点では sender が無いので自分を送り主扱い（自分を除外するだけ）
        let sender_id = sender.unwrap_or(ctx.descriptor.node_id);

        let route = {
            let mut d = ctx.dandelion.lock().unwrap();
            d.route(
                &sender_id,
                &neighbors,
                std::time::Instant::now(),
                &mut rand::thread_rng(),
            )
        };

        match route {
            Route::Forward(target) => {
                let target_addr = {
                    let dir = ctx.directory.read().await;
                    dir.get(&target).map(|d| d.addr)
                };
                let Some(addr) = target_addr else {
                    // 後継が引けない → 即 fluff
                    let _ = Self::relay_hint(hint_bytes, ctx).await;
                    return;
                };

                let _ = ctx
                    .router
                    .send_packet(addr, PacketType::StemHint, hint_bytes)
                    .await;

                // フェイルセーフ: 一定時間 fluff が観測できなければ自分で fluff する
                let id = packet.id();
                let ctx2 = ctx.clone();
                let bytes = hint_bytes.to_vec();
                tokio::spawn(async move {
                    tokio::time::sleep(DANDELION_STEM_TIMEOUT).await;
                    if !ctx2.gossip.has_seen(&id).await {
                        debug!("Dandelion fail-safe: fluffing a stemmed hint");
                        let _ = Self::relay_hint(&bytes, &ctx2).await;
                    }
                });
            }
            Route::Fluff => {
                let _ = Self::relay_hint(hint_bytes, ctx).await;
            }
        }
    }

    /// 単発の Hint を処理して拡散キューに積む（fluff 相）
    async fn relay_hint(hint_bytes: &[u8], ctx: &PacketContext) -> Result<()> {
        let packet: HintPacket = match bincode::deserialize(hint_bytes) {
            Ok(p) => p,
            Err(e) => {
                debug!("Invalid Hint discarded: {}", e);
                return Ok(());
            }
        };

        // 自分が担当なら backlog に保存する（拡散/TTL とは独立、19.1.3）
        Self::persist_if_responsible(ctx, &packet).await;

        match ctx.gossip.handle_hint_packet(packet).await {
            HintAction::Relay(p) => Self::enqueue_for_relay(vec![p], ctx).await,
            HintAction::Drop => debug!("Hint dropped (duplicate / TTL / PoW)"),
        }
        Ok(())
    }

    /// バッチで届いた Hint 群を処理して拡散キューに積む
    async fn relay_hint_batch(payload: &[u8], ctx: &PacketContext) -> Result<()> {
        let packets: Vec<HintPacket> = match bincode::deserialize(payload) {
            Ok(p) => p,
            Err(e) => {
                debug!("Invalid Hint batch discarded: {}", e);
                return Ok(());
            }
        };
        if packets.len() > gossip_server::MAX_HINTS_PER_BATCH {
            debug!("Oversized Hint batch discarded: {}", packets.len());
            return Ok(());
        }

        let mut relay = Vec::new();
        for packet in packets {
            Self::persist_if_responsible(ctx, &packet).await;
            if let HintAction::Relay(p) = ctx.gossip.handle_hint_packet(packet).await {
                relay.push(p);
            }
        }
        if !relay.is_empty() {
            debug!("Relaying {} of the batched Hints", relay.len());
            Self::enqueue_for_relay(relay, ctx).await;
        }
        Ok(())
    }

    /// 自ノードが担当（`H(hint_id)` の K 最近接）なら Hint を backlog に保存する
    ///
    /// PoW を確認してから入れる（backlog にゴミを溜めさせない）。
    /// 拡散するか・TTL が尽きたかとは無関係に、担当なら必ず持つ。
    async fn persist_if_responsible(ctx: &PacketContext, packet: &HintPacket) {
        if !packet.verify_pow(ctx.gossip.pow_difficulty()) {
            return;
        }
        let responsible = {
            let dir = ctx.directory.read().await;
            dir.is_hint_holder(&packet.id(), &ctx.descriptor.node_id, HINT_REPLICAS)
        };
        if responsible
            && let Ok(mut log) = ctx.hint_log.lock()
        {
            log.insert(packet.clone());
        }
    }

    /// 拡散対象の Hint をピアごとの送信キューに積む
    ///
    /// ここでは送信しない。バッチャが [`FLUSH_INTERVAL`] ごと、
    /// あるいはバッチ満杯時にまとめて送る。
    /// Hint 90バイトに対しヘッダが約53バイト乗るため、
    /// 1件ずつ送ると帯域の4割弱がヘッダで消える。
    ///
    /// **拡散先はディレクトリ（既知リレー全体）から無作為抽選する。**
    /// PeerManager（自分が accept した inbound 接続のみ）だと、種のように
    /// Connection Reversal で「相手の接続の上に返信するだけ」の相手が集合から漏れる。
    /// その結果、出口リレー ≠ 購読者 のとき Hint が購読者へ届かず、
    /// Broadcast Veil（全ノードが全 Hint を受け取る）が破れる。既知リレーへ撒けば、
    /// router が生存接続を再利用（無ければダイヤル）して全体に伝播する。
    async fn enqueue_for_relay(packets: Vec<HintPacket>, ctx: &PacketContext) {
        for packet in packets {
            let peers: Vec<SocketAddr> = {
                let dir = ctx.directory.read().await;
                dir.random_path(GOSSIP_FANOUT, std::slice::from_ref(&ctx.descriptor.node_id))
                    .into_iter()
                    .map(|r| r.addr)
                    .collect()
            };

            for peer_addr in peers {
                if peer_addr == ctx.local_addr {
                    continue;
                }

                // 満杯になったバッチだけは待たずに送る
                if let Some(full) = ctx.batcher.enqueue(peer_addr, packet.clone()).await {
                    Self::spawn_batch_send(ctx.router.clone(), peer_addr, full);
                }
            }
        }
    }

    /// バッチを1ピアへ送出する
    ///
    /// 到達不能なピアが1つあるだけで拡散全体が止まらないよう、
    /// 独立タスク + タイムアウトで投げっぱなしにする。
    fn spawn_batch_send(router: Arc<Router>, peer_addr: SocketAddr, hints: Vec<HintPacket>) {
        tokio::spawn(async move {
            let count = hints.len();
            let bytes = match bincode::serialize(&hints) {
                Ok(b) => b,
                Err(e) => {
                    error!("Failed to serialize Hint batch: {}", e);
                    return;
                }
            };

            let send = router.send_packet(peer_addr, PacketType::GossipHintBatch, &bytes);

            match tokio::time::timeout(GOSSIP_RELAY_TIMEOUT, send).await {
                Ok(Ok(())) => debug!("Relayed {} Hint(s) to {}", count, peer_addr),
                Ok(Err(e)) => debug!("Hint relay to {} failed: {}", peer_addr, e),
                Err(_) => debug!("Hint relay to {} timed out", peer_addr),
            }
        });
    }

    /// 溜まった Hint を定期的に送出する
    fn spawn_batch_flusher(&self) {
        let batcher = self.batcher.clone();
        let router = self.router.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(hint_batcher::FLUSH_INTERVAL);

            loop {
                ticker.tick().await;

                for (peer_addr, hints) in batcher.drain().await {
                    Self::spawn_batch_send(router.clone(), peer_addr, hints);
                }
            }
        });
    }

    /// 横取りした STUN を捌き続ける
    ///
    /// これが無いと:
    /// - 相手からの punch プローブに応答できず、punch が片方向で終わる
    /// - フィルタ判定のプローブが届いても気づけない
    fn spawn_side_channel(&self) {
        let Some(mut side_rx) = self.server.take_side_channel() else {
            // discover_reachability が持ったまま返していない
            debug!("Side channel already taken; punch responses will not be handled");
            return;
        };

        let socket = self.server.shared_socket();
        let pending = self.filter_check_pending.clone();
        let filtering = self.filtering.clone();

        tokio::spawn(async move {
            let mut session = PunchSession::new();

            while let Some(datagram) = side_rx.recv().await {
                let Ok(message) = punch::parse_probe(&datagram.data) else {
                    continue;
                };

                let needs_reply = session.handle_incoming(datagram.from, &message);

                // 待ち状態のときに届いた「送っていない相手からのプローブ」は
                // フィルタが EIF である証拠
                if needs_reply && pending.swap(false, Ordering::SeqCst) {
                    info!("Filtering is endpoint-independent (unsolicited probe accepted)");
                    *filtering.write().await = NatFiltering::EndpointIndependent;
                }

                if needs_reply
                    && let punch::ProbeMessage::Request { transaction } = message
                    && let Ok(reply) = punch::build_probe_response(transaction, datagram.from)
                {
                    let _ = socket.send_raw(datagram.from, &reply).await;
                }
            }
        });
    }

    /// フィルタ挙動を判定して Tier を更新する
    ///
    /// **ネットワーク参加後に呼ぶこと。** 一度も話していない相手から
    /// 撃ってもらう必要があるので、リレーが2台以上必要。
    ///
    /// EIM + EIF と判明すると punch すら不要な Tier 0 に上がる。
    /// `Arc<NodeServer>` から呼べる版
    ///
    /// 判定結果は記述子ではなくディレクトリ側に反映する
    /// （`&mut self` を取れないため）。
    pub async fn check_filtering_shared(self: &Arc<Self>) -> NatFiltering {
        *self.filtering.write().await = NatFiltering::Restricted;
        self.filter_check_pending.store(true, Ordering::SeqCst);

        let relays = {
            let dir = self.directory.read().await;
            dir.random_path(2, &[self.descriptor.node_id])
        };

        if relays.len() < 2 {
            self.filter_check_pending.store(false, Ordering::SeqCst);
            return NatFiltering::Unknown;
        }

        let _ = self
            .router
            .send_packet(relays[0].addr, PacketType::FilterCheck, &[])
            .await;

        tokio::time::sleep(punch::PROBE_WINDOW).await;
        self.filter_check_pending.store(false, Ordering::SeqCst);

        let result = *self.filtering.read().await;

        if result.accepts_unsolicited() {
            let mut promoted = self.descriptor.clone();
            promoted.tier = Tier::Open;
            let mut dir = self.directory.write().await;
            dir.insert_unchecked(promoted);
            info!("Promoted to Tier 0: filtering is endpoint-independent");
        }

        result
    }

    pub async fn check_filtering(&mut self) -> NatFiltering {
        // まだ判定できていないうちは「制限あり」を仮置きする。
        // 楽観的に EIF とすると、届かないノードがガードに選ばれる
        *self.filtering.write().await = NatFiltering::Restricted;
        self.filter_check_pending.store(true, Ordering::SeqCst);

        let relays = {
            let dir = self.directory.read().await;
            dir.random_path(2, &[self.descriptor.node_id])
        };

        if relays.len() < 2 {
            debug!("Filtering check needs at least 2 other relays");
            self.filter_check_pending.store(false, Ordering::SeqCst);
            return NatFiltering::Unknown;
        }

        // 1台に頼むと、その1台が別の1台へ撃つよう手配する
        let _ = self
            .router
            .send_packet(relays[0].addr, PacketType::FilterCheck, &[])
            .await;

        // プローブが届くのを待つ
        tokio::time::sleep(punch::PROBE_WINDOW).await;
        self.filter_check_pending.store(false, Ordering::SeqCst);

        let result = *self.filtering.read().await;

        if result.accepts_unsolicited() {
            self.descriptor.tier = Tier::Open;
            let mut dir = self.directory.write().await;
            dir.insert_unchecked(self.descriptor.clone());
            info!("Promoted to Tier 0: filtering is endpoint-independent");
        }

        result
    }

    /// 定期的に PEX を仕掛けてリレーリストを維持する
    ///
    /// これが回っていないと、リストは起動時の種ノードから増えず、
    /// 離脱したノードも残り続ける。
    fn spawn_pex(&self) {
        let router = self.router.clone();
        let directory = self.directory.clone();
        let descriptor = self.descriptor.clone();

        tokio::spawn(async move {
            // 進捗ベースのバックオフ。
            // 新しいリレーが見つかっている間は速く回して収束させ、
            // 見つからなくなったら間隔を伸ばして常時コストを下げる。
            let mut interval = PEX_MIN_INTERVAL;
            let mut last_size = 0usize;

            loop {
                tokio::time::sleep(interval).await;

                let (targets, size) = {
                    let dir = directory.read().await;
                    (dir.random_path(PEX_FANOUT, &[descriptor.node_id]), dir.len())
                };

                // 前回より増えていれば収束中とみなして最短間隔へ戻す
                if size > last_size {
                    interval = PEX_MIN_INTERVAL;
                } else {
                    interval = (interval * 2).min(PEX_MAX_INTERVAL);
                }
                last_size = size;

                if targets.is_empty() {
                    continue;
                }

                let Ok(request) = PexRequest::new(descriptor.clone()).encode() else {
                    continue;
                };

                for target in targets {
                    let _ = router
                        .send_packet(target.addr, PacketType::PexRequest, &request)
                        .await;
                }
            }
        });
    }

    /// 期限切れデータの定期掃除
    ///
    /// これが回っていないと Mailbox と SeenCache が無制限に膨らみ、
    /// 任意の相手からのメモリ／ディスク枯渇 DoS が成立する。
    fn spawn_gc(&self) {
        let mailbox = self.mailbox.clone();
        let gossip = self.gossip.clone();
        let hint_log = self.hint_log.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(GC_INTERVAL);
            // 起動直後の即時発火を捨てる
            ticker.tick().await;

            loop {
                ticker.tick().await;

                match mailbox.cleanup_expired() {
                    Ok(0) => {}
                    Ok(n) => info!("GC: removed {} expired mailbox entries", n),
                    Err(e) => error!("GC: mailbox cleanup failed: {}", e),
                }

                gossip.cleanup().await;

                // backlog の窓外エントリも掃除する
                if let Ok(mut log) = hint_log.lock() {
                    log.prune(current_timestamp());
                }
            }
        });
    }

    /// Hint backlog の差分同期（19.1.3・オフライン受信）
    ///
    /// 定期的に隣（ディレクトリの一人）へ自分の digest を送り、
    /// 取りこぼした Hint を引く。復帰したノードはこれで窓ぶんを埋める。
    /// backlog 応答は再拡散されないので、これ自体が増幅にはならない。
    fn spawn_hint_reconcile(&self) {
        let directory = self.directory.clone();
        let hint_log = self.hint_log.clone();
        let router = self.router.clone();
        let me = self.descriptor.node_id;

        tokio::spawn(async move {
            // 起動直後の追いつきを速めるため、最初だけ短く待つ
            tokio::time::sleep(Duration::from_secs(5)).await;

            loop {
                // 窓外を掃除してから digest を作る
                let digest = {
                    let mut log = hint_log.lock().unwrap();
                    log.prune(current_timestamp());
                    log.digest()
                };

                // 自分以外のノードを1つ選ぶ
                let peer_addr = {
                    let dir = directory.read().await;
                    let mut addrs: Vec<SocketAddr> = dir
                        .all()
                        .into_iter()
                        .filter(|d| d.node_id != me)
                        .map(|d| d.addr)
                        .collect();
                    if addrs.is_empty() {
                        None
                    } else {
                        use rand::seq::SliceRandom;
                        addrs.shuffle(&mut rand::thread_rng());
                        addrs.into_iter().next()
                    }
                };

                if let Some(addr) = peer_addr
                    && let Ok(bytes) = digest.encode()
                {
                    let _ = router
                        .send_packet(addr, PacketType::HintDigest, &bytes)
                        .await;
                }

                tokio::time::sleep(HINT_RECONCILE_INTERVAL).await;
            }
        });
    }

    /// 登録済みトンネル数（テスト・診断用）
    pub async fn tunnel_count(&self) -> usize {
        self.tunnel_relay.read().await.len()
    }

    /// backlog に保持している Hint 数（テスト・診断用）
    pub fn backlog_len(&self) -> usize {
        self.hint_log.lock().unwrap().len()
    }

    /// 指定ピアと backlog を差分同期する（自分の digest を送って引く）
    ///
    /// 通常は [`spawn_hint_reconcile`](Self::spawn_hint_reconcile) が定期実行する。
    /// 復帰直後に明示的に回したい場合のために公開している。
    pub async fn reconcile_backlog_with(&self, peer: SocketAddr) -> Result<()> {
        let digest = {
            let mut log = self.hint_log.lock().unwrap();
            log.prune(current_timestamp());
            log.digest()
        };
        self.router
            .send_packet(peer, PacketType::HintDigest, &digest.encode()?)
            .await
    }

    // Test accessors
    pub fn mailbox(&self) -> Arc<MailboxServer> { self.mailbox.clone() }
    pub fn gossip(&self) -> Arc<GossipServer> { self.gossip.clone() }
    pub fn peers(&self) -> Arc<PeerManager> { self.peers.clone() }
    pub fn directory(&self) -> Arc<RwLock<RelayDirectory>> { self.directory.clone() }
}
