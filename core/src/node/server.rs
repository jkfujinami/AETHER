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
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify, RwLock};
use tracing::{info, error, debug, warn};
use crate::Config;
use std::path::Path;
use std::net::SocketAddr;
use std::time::Duration;

/// Hint backlog の複製数（19.1.3）。本体シャードの K と揃える
const HINT_REPLICAS: usize = 5;

/// Hint backlog の差分同期間隔
const HINT_RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// Dandelion++ の stem フェイルセーフ (3-2)
///
/// stem した Hint がこの時間内に fluff で戻ってこなければ、自分で fluff する。
/// stem 後継が黒穴でも配送を保証する。
const DANDELION_STEM_TIMEOUT: Duration = Duration::from_secs(3);

/// Dandelion++ stem の ACK 待ち時間 (3-2 echo 再送)
///
/// 後継へ [`StemHint`](PacketType::StemHint) を投げてからこの時間内に
/// [`StemAck`](PacketType::StemAck) が返らなければ、その後継は黒穴とみなして
/// **別の後継へ再送する**。[`DANDELION_STEM_TIMEOUT`] より十分短くする
/// （fluff の最終フォールバックより先に代替経路を試したい）。
const DANDELION_STEM_ACK_TIMEOUT: Duration = Duration::from_millis(700);

/// 黒穴を避けて別の後継を試す最大回数 (3-2 echo 再送)
///
/// これを使い切っても ACK が得られなければ、自分で fluff して配送を保証する。
const DANDELION_MAX_STEM_RETRIES: usize = 3;

/// 期限切れデータの掃除間隔
const GC_INTERVAL: Duration = Duration::from_secs(300);

/// 自分の記述子を署名し直す間隔（[`RelayDescriptor::issued_at`] の延命）
///
/// [`crate::net::relay_list::DESCRIPTOR_TTL_SECS`] の 1/3。この余裕が無いと、
/// PEX の伝播や一時的なネットワーク不調で更新が間に合わず、生きているリレーの
/// 記述子が期限切れ扱いで網から消えてしまう。
const DESCRIPTOR_RESIGN_INTERVAL: Duration =
    Duration::from_secs(crate::net::relay_list::DESCRIPTOR_TTL_SECS / 3);

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

/// `addr` がディレクトリに載っているリレーのアドレスか（正規化して比較）
///
/// [`crate::net::addr::normalize`] を通す ── デュアルスタックだと同じノードが
/// IPv4-mapped IPv6 として観測され、素通しで比べると常に不一致になる。
fn is_known_relay_addr(dir: &RelayDirectory, addr: SocketAddr) -> bool {
    let want = crate::net::addr::normalize(addr);
    dir.all()
        .into_iter()
        .any(|d| crate::net::addr::normalize(d.addr) == want)
}

/// `gateway` がディレクトリに載っている、かつ知らない相手を受け入れる Tier のリレーか
///
/// MailboxGet / IndexQuery の返信先はここでしか検証されない。任意のアドレスへ
/// 返信させられると、第三者への増幅攻撃の踏み台になる（FilterCheck と同じ理由）。
fn is_trusted_reply_gateway(dir: &RelayDirectory, gateway: SocketAddr) -> bool {
    let want = crate::net::addr::normalize(gateway);
    dir.all()
        .into_iter()
        .any(|d| crate::net::addr::normalize(d.addr) == want && d.tier.accepts_strangers())
}

/// IPv4/IPv6 のマルチキャスト・ブロードキャストアドレスか
fn is_multicast_or_broadcast(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast(),
        std::net::IpAddr::V6(v6) => v6.is_multicast(),
    }
}

/// PunchNotify の候補アドレスを絞る
///
/// 認証なしで任意の宛先へ UDP を撃たせられる踏み台にしないため:
/// - 未指定・マルチキャスト・ブロードキャストは常に除く
/// - ループバックは**送り主自身もループバックの場合だけ**許す
///   （テストでは 127.0.0.1 を使うため。実網の送り主がループバックのはずはない）
/// - 最大 4 件に切り詰める
fn sanitize_punch_candidates(candidates: &[SocketAddr], sender_is_loopback: bool) -> Vec<SocketAddr> {
    const MAX_PUNCH_CANDIDATES: usize = 4;
    candidates
        .iter()
        .filter(|addr| {
            let ip = addr.ip();
            if ip.is_unspecified() || is_multicast_or_broadcast(ip) {
                return false;
            }
            if ip.is_loopback() && !sender_is_loopback {
                return false;
            }
            true
        })
        .take(MAX_PUNCH_CANDIDATES)
        .copied()
        .collect()
}

pub struct NodeServer {
    pub server: QuicServer,
    pub router: Arc<Router>,
    pub mailbox: Arc<MailboxServer>,
    pub gossip: Arc<GossipServer>,
    pub tunnel_relay: Arc<RwLock<TunnelRelay>>,
    pub peers: Arc<PeerManager>,
    pub batcher: Arc<HintBatcher>,
    /// 自分の記述子。PEX で配る
    ///
    /// **直接書き換えないこと。** 署名が崩れて他ノードに弾かれる。
    /// 変更は [`refresh_descriptor`](Self::refresh_descriptor) 経由で署名し直す。
    pub descriptor: RelayDescriptor,
    /// 記述子に署名する鍵
    identity: Arc<Identity>,
    /// 自分をリレーとして広告するか（一回限りのクライアントは false）
    advertise_self: bool,
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
    /// stem 中の Hint ごとの ACK 待ち通知（3-2 echo 再送）。
    /// key = hint_id。後継から [`StemAck`](PacketType::StemAck) が届いたら notify する。
    stem_acks: Arc<Mutex<HashMap<[u8; 32], Arc<Notify>>>>,
    /// エポックビーコン（drand 由来の日次シード）を回すか (3-4)
    epoch_beacon: bool,
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
    /// stem 中の Hint ごとの ACK 待ち通知（3-2 echo 再送）
    pub stem_acks: Arc<Mutex<HashMap<[u8; 32], Arc<Notify>>>>,
}

impl PacketContext {
    /// `addr` が自ノードを指しているか
    ///
    /// **ポートだけで比べてはいけない。** 実網では皆が既定ポートで待ち受けるので、
    /// 別ホストの同じポートを自分と誤認し、中継すべきパケットを自分で飲み込む
    /// （多段回路・多段トンネルが localhost の試験では通り、実網でだけ壊れる）。
    /// 広告アドレスと一致するか、ループバック宛てでポートが一致する（ローカル試験）
    /// 場合だけ自分とみなす。
    fn is_self(&self, addr: SocketAddr) -> bool {
        addr == self.descriptor.addr
            || (addr.port() == self.local_addr.port()
                && (addr.ip().is_loopback() || addr.ip().is_unspecified()))
    }
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
        Self::with_config_passphrase(port, identity, db_path, config, None)
    }

    /// 設定に加えて Mailbox の**保存時暗号化パスフレーズ**を指定して起動する (3-1)
    ///
    /// `passphrase` が `Some` なら mailbox.db を暗号化する（押収対策）。`None` は平文。
    pub fn with_config_passphrase(
        port: u16,
        identity: Identity,
        db_path: &Path,
        config: &Config,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        let config = Config { listen_port: port, ..config.clone() };
        // 証明書はノードの鍵で作る（接続側がディレクトリの NodeId と照合する）
        let server = QuicServer::with_identity(&config, Some(&identity))?;

        // Modules init
        let identity = Arc::new(identity);
        // 待ち受けと同じソケットから発信する（NAT マッピングを共有）
        let router = Arc::new(Router::with_endpoint(identity.clone(), server.endpoint())?);
        let mailbox = Arc::new(match passphrase {
            Some(p) => MailboxServer::new_encrypted(db_path, &config, p)?,
            None => MailboxServer::new(db_path, &config)?,
        });
        let gossip = Arc::new(GossipServer::new(&config));
        let tunnel_relay = Arc::new(RwLock::new(TunnelRelay::new()));
        let peers = Arc::new(PeerManager::new());
        let batcher = Arc::new(HintBatcher::new());

        // 自分の記述子を組み立てる。NodeId PoW は保存済みの解があれば検証だけで済ませる
        let node_id = identity.public_id();
        let cached = match config.node_id_pow_nonce {
            Some(n) => pow::node_id::verify(node_id.as_bytes(), n, config.node_id_pow_difficulty)?
                .then_some(n),
            None => None,
        };
        let pow_nonce = match cached {
            Some(n) => n,
            None => pow::node_id::solve(node_id.as_bytes(), config.node_id_pow_difficulty, 1 << 24)?,
        };

        // **引数の port ではなく実際にバインドされたポートを使う。**
        // port=0 を渡した場合、引数は 0 のままなので広告が壊れる。
        let bound_port = server.local_addr()?.port();

        let descriptor = RelayDescriptor::new_signed(
            &identity,
            format!("127.0.0.1:{}", bound_port).parse()
                .map_err(|e| crate::AetherError::Config(format!("Invalid advertise address: {}", e)))?,
            pow_nonce,
            // 到達性は起動後に調べる。判明するまでは最も控えめな等級。
            // 楽観的に Open と広告すると、届かないノードが
            // Mailbox やガードに選ばれて配送が落ちる
            Tier::Reversed,
        );

        // 自分自身もリレーとしてリストに入れる。
        //
        // **これを入れないと、自分のリストだけが1件欠けた状態になり、
        // K最近接が他ノードと食い違う。** 自分が担当に選ばれていることに
        // 気づけず、置かれたはずのシャードを取りに来た相手に応答できない。
        // MailboxForward は既に「宛先が自分」の場合をローカル保存で処理している。
        //
        // 検証難易度は網全体の値（directory_pow_difficulty）。自分が解いた難易度とは別。
        // 自分の記述子は自分で作ったものなので検証を通さずに入れる
        // （一回限りのクライアントは PoW を解かないため、検証すると自分を弾く）。
        let mut initial = RelayDirectory::new(
            crate::net::ring::EPOCH_SEED_PLACEHOLDER,
            config.directory_pow_difficulty,
        );
        initial.insert_unchecked(descriptor.clone());
        let directory = Arc::new(RwLock::new(initial));

        // 接続先の証明書を、ディレクトリ上のそのアドレスの NodeId と照合させる
        {
            let dir = directory.clone();
            router.set_key_resolver(Arc::new(move |addr| {
                let dir = dir.clone();
                Box::pin(async move {
                    let want = crate::net::addr::normalize(addr);
                    let dir = dir.read().await;
                    dir.all()
                        .into_iter()
                        .find(|d| crate::net::addr::normalize(d.addr) == want)
                        .map(|d| d.node_id)
                })
            }));
        }

        Ok(Self {
            server,
            router,
            mailbox,
            gossip,
            tunnel_relay,
            peers,
            batcher,
            descriptor,
            identity,
            advertise_self: config.advertise_self,
            directory,
            filter_check_pending: Arc::new(AtomicBool::new(false)),
            filtering: Arc::new(RwLock::new(NatFiltering::Unknown)),
            hint_log: Arc::new(Mutex::new(HintLog::default())),
            dandelion: Arc::new(Mutex::new(DandelionRouter::new())),
            stem_acks: Arc::new(Mutex::new(HashMap::new())),
            epoch_beacon: config.epoch_beacon,
        })
    }

    /// 記述子を署名し直し、自分のディレクトリにも反映する
    ///
    /// 記述子を変えたら必ず呼ぶ。署名が古いままだと他ノードに弾かれ、
    /// 発行時刻が進まないと他ノードが古い記述子を持ち続ける。
    async fn refresh_descriptor(&mut self) {
        self.descriptor.resign(&self.identity);
        self.directory.write().await.insert_unchecked(self.descriptor.clone());
    }

    /// 広告するアドレスを差し替える（STUN で外部アドレスが判明した場合など）
    pub async fn set_advertised_addr(&mut self, addr: SocketAddr) {
        self.descriptor.addr = addr;
        self.refresh_descriptor().await;
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
        self.refresh_descriptor().await;
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
        self.refresh_descriptor().await;

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
        let request = self.pex_request().encode()?;
        self.router
            .send_packet(seed, PacketType::PexRequest, &request)
            .await
    }

    /// 自分宛ての TunnelBuild をネットワークを通さずに登録する
    ///
    /// Inbound Tunnel の終端（＝自分）への構築指示を自分の広告アドレスへ送ると、
    /// 経路上に「このアドレスがトンネルを作った」という足跡が残るだけで得るものが無い。
    pub async fn accept_own_tunnel_build(&self, payload: &[u8]) -> Result<()> {
        // 自分自身の分は next_hop が自分の広告アドレスなので、
        // 転送先の検査（is_allowed_next）を通さなくてよい。
        Self::register_tunnel_build(&self.router, &self.tunnel_relay, payload, None, |_| true).await
    }

    /// TunnelBuild を登録する
    ///
    /// `builder` はこの指示を運んできた接続の相手。`next_hop = None` の指示は
    /// そこへ返す（終端の手前のホップが、NAT 内の構築者へ届けるため）。
    ///
    /// `is_allowed_next` は `builder` が `Some`（＝網経由で届いた指示）かつ
    /// `next_hop` が `Some(addr)` のときだけ効く。**ここを通さないと、網経由の
    /// TunnelBuild で任意の踏み台・内部アドレスへダイヤルさせられる。**
    /// `builder = None`（自分自身の分）や `next_hop = None`（構築者へ返す）は
    /// 従来どおり検査しない。
    async fn register_tunnel_build(
        router: &Router,
        tunnel_relay: &RwLock<TunnelRelay>,
        payload: &[u8],
        builder: Option<SocketAddr>,
        is_allowed_next: impl Fn(SocketAddr) -> bool,
    ) -> Result<()> {
        let (tid, shared_secret, inst) = router.process_tunnel_build(payload)?;

        if builder.is_some()
            && let Some(next_hop) = inst.next_hop
            && !is_allowed_next(next_hop)
        {
            debug!("TunnelBuild next_hop {} is neither self nor a known relay; ignoring", next_hop);
            return Ok(());
        }

        let Some(next) = inst.next_hop.or(builder) else {
            tracing::warn!("TunnelBuild to return to its builder, but the builder is unknown. Ignoring.");
            return Ok(());
        };
        if !tunnel_relay
            .write()
            .await
            .register_tunnel(tid, shared_secret, next, inst.next_tunnel_id)
        {
            debug!("Tunnel registration for ID={:?} -> {} rejected (duplicate ID or full)", tid, next);
            return Ok(());
        }
        debug!("Tunnel registered: ID={:?} -> {}", tid, next);
        Ok(())
    }

    /// PEX 要求。広告しないノードは自分の記述子を載せない
    fn pex_request(&self) -> PexRequest {
        if self.advertise_self {
            PexRequest::new(self.descriptor.clone())
        } else {
            PexRequest::anonymous()
        }
    }

    /// 自分の待ち受けと同じソケットから、`addr` へ keepalive 付き接続を張って保つ
    ///
    /// 返信トンネルの終端に使う。相手はこの接続の上で返信を届ける。
    pub async fn pin_connection(&self, addr: SocketAddr) -> Result<()> {
        self.router.pin_connection(addr).await
    }

    /// 自分の待ち受けと同じソケットから `addr` へ直接送る
    pub async fn send_direct(&self, addr: SocketAddr, packet_type: PacketType, payload: &[u8]) -> Result<()> {
        self.router.send_packet(addr, packet_type, payload).await
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
        if self.epoch_beacon {
            self.spawn_epoch_beacon();
        }
        if self.advertise_self {
            self.spawn_resign();
        }

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
                stem_acks: self.stem_acks.clone(),
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
            stem_acks: self.stem_acks.clone(),
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
                // 中継先は自分か既知リレーに限る。そうでなければ、任意の踏み台・
                // 内部アドレスへ中継がダイヤルさせられてしまう。
                //
                // **ディレクトリのロックを持ったまま転送（await）しない。** 次ホップへの
                // ダイヤルが遅いと、ロック待ちの PEX 書き込みの後ろで全パケット処理が詰まる。
                // 既知リレーのアドレスを先に写し取ってから判定する。
                let known: std::collections::HashSet<SocketAddr> = {
                    let dir = ctx.directory.read().await;
                    dir.all()
                        .into_iter()
                        .map(|d| crate::net::addr::normalize(d.addr))
                        .collect()
                };
                let action = ctx
                    .router
                    .handle_packet(&payload, |next| {
                        ctx.is_self(next) || known.contains(&crate::net::addr::normalize(next))
                    })
                    .await?;

                match action {
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

                                if ctx.is_self(dest) {
                                    // 自分自身が Mailbox に選ばれている場合は素直に保存する
                                    ctx.mailbox.handle_put(payload).await?;
                                } else if is_known_relay_addr(&*ctx.directory.read().await, dest) {
                                    ctx.router
                                        .send_packet(dest, PacketType::MailboxPut, payload)
                                        .await?;
                                } else {
                                    // **転送先は既知リレーに限る。** そうでないと、出口リレーが
                                    // 踏み台や内部アドレスへの任意ダイヤルに使われる。
                                    debug!("MailboxForward dest {} is not a known relay; discarding", dest);
                                }
                            }
                            wire::InnerPacketType::TypedForward => {
                                // 出口リレーは中身を解釈せず、指定ノードへそのまま渡す。
                                let (dest, packet_type, inner) = wire::parse_typed_forward(body)?;
                                debug!("Forwarding {:?} to {}", packet_type, dest);

                                if ctx.is_self(dest) {
                                    Box::pin(Self::process_packet(packet_type, inner.to_vec(), ctx.clone())).await?;
                                } else if is_known_relay_addr(&*ctx.directory.read().await, dest) {
                                    ctx.router.send_packet(dest, packet_type, inner).await?;
                                } else {
                                    // **転送先は既知リレーに限る**（MailboxForward と同じ理由）。
                                    debug!("TypedForward dest {} is not a known relay; discarding", dest);
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
                // Dandelion++ の stem 相。まず送り主へ ACK を返す（黒穴検出 / 3-2 echo 再送）。
                // ACK が返らなければ送り主はこの後継を黒穴とみなし別の後継へ再送する。
                //
                // **投げっぱなしにする（await しない）。** 送り主が到達不能でも ACK の送出で
                // Hint 処理（下の inject_hint）を塞いではならない。ACK は最適化であって、
                // 配送保証は inject_hint 側の fluff フォールバックが担う。
                if let Ok(packet) = bincode::deserialize::<HintPacket>(&payload)
                    && let Some(addr) = ctx.remote_addr
                {
                    let router = ctx.router.clone();
                    let id = packet.id();
                    tokio::spawn(async move {
                        let _ = router.send_packet(addr, PacketType::StemAck, &id).await;
                    });
                }

                // 送り主を除外して次の判断（forward / fluff）へ。
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
            PacketType::StemAck => {
                // 後継が stem を受け取った合図。待っている再送タスクを起こす（3-2）。
                if payload.len() == 32 {
                    let id: [u8; 32] = payload[..32].try_into().expect("長さ確認済み");
                    let waiter = ctx.stem_acks.lock().unwrap().get(&id).cloned();
                    if let Some(notify) = waiter {
                        notify.notify_one();
                    }
                }
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

                // **応答は観測した送信元へ、要求者が乗ってきた接続の上で返す。**
                // 記述子に書かれたアドレスへ返すと、第三者のアドレスを書いた要求で
                // 他人に応答を撃たせる増幅の踏み台になる（FilterCheck と同じ理由）。
                // 一回限りのクライアントの記述子は 127.0.0.1 のままなので、実網では
                // そもそも申告アドレスへは届かない。
                let Some(requester_addr) = ctx.remote_addr else {
                    debug!("PexRequest without an observed source");
                    return Ok(());
                };

                // 要求者自身を取り込む。これで一方向の要求だけで相互に知り合える
                // （一回限りのクライアントは記述子を載せてこない）
                if let Some(requester) = &request.requester {
                    let blockers = {
                        let mut dir = ctx.directory.write().await;
                        match dir.insert(requester.clone()) {
                            Ok(()) => Vec::new(),
                            Err(e) => {
                                debug!("Rejected requester descriptor: {}", e);
                                dir.blocking_claims(requester)
                            }
                        }
                    };
                    if !blockers.is_empty() {
                        Self::spawn_resolve_claim(&ctx, requester.clone(), blockers);
                    }
                }

                let response = {
                    let dir = ctx.directory.read().await;
                    // **`ctx.descriptor` ではなく、ディレクトリ上の自分のエントリを使う。**
                    // `ctx.descriptor` は run() 時点のスナップショットで、
                    // check_filtering_shared 等による Tier 昇格を反映しない
                    // （反映先はディレクトリ側）。古い記述子を配り続けると、
                    // 昇格が他ノードへ広まらない。
                    let self_descriptor = dir.get(&ctx.descriptor.node_id).cloned();
                    pex::select_response(&dir, &request, self_descriptor.as_ref())
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
                //
                // **未認証の PunchRequest を PunchNotify の送り主確認の回避に使わせない。**
                // PunchNotify は「送り主が既知リレーか」しか見ないので、認証なしの
                // PunchRequest を既知リレー A に送りつけ、A に任意候補付きの
                // PunchNotify を既知リレー B へ出させれば、B は「既知リレーから」という
                // だけで受け入れて第三者へプローブを撃ってしまう。ここで:
                // (a) 観測できる送信元が無ければ無視する
                // (b) request.requester がディレクトリに載っていて、その記述子の
                //     アドレスが観測した送信元と一致する場合だけ仲介する（自称を信じない）
                // (c) 相手へ渡す候補は申告の request.candidates ではなく、
                //     観測した送信元アドレスだけにする
                let Some(sender_addr) = ctx.remote_addr else {
                    debug!("PunchRequest without an observed source; ignoring");
                    return Ok(());
                };

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

                let Some(requester) = requester else {
                    debug!("Punch requester {} is unknown", request.requester);
                    return Ok(());
                };

                let observed_ip = crate::net::addr::normalize(sender_addr).ip();
                if crate::net::addr::normalize(requester.addr).ip() != observed_ip {
                    debug!(
                        "PunchRequest claims to be {} but observed source {} does not match its descriptor; ignoring",
                        request.requester, sender_addr
                    );
                    return Ok(());
                }

                // 相手へ: 要求者の候補（観測したアドレスのみ。申告の候補は信じない）
                let notify = PunchNotify {
                    peer: request.requester,
                    candidates: vec![sender_addr],
                };
                let _ = ctx.router
                    .send_packet(target.addr, PacketType::PunchNotify, &notify.encode()?)
                    .await;

                // 要求者へ: 相手の候補
                let back = PunchNotify {
                    peer: request.target,
                    candidates: vec![target.addr],
                };
                let _ = ctx.router
                    .send_packet(requester.addr, PacketType::PunchNotify, &back.encode()?)
                    .await;
            },
            PacketType::PunchNotify => {
                // **送り主がディレクトリ上の既知リレーでなければ無視する。**
                // 認証なしで通れば、任意の第三者が任意の宛先へ UDP を撃たせる
                // 踏み台になる（PunchRequest は本来仲介役のリレーしか出さない）。
                let Some(sender_addr) = ctx.remote_addr else {
                    debug!("PunchNotify without an observed source; ignoring");
                    return Ok(());
                };
                let known_sender = {
                    let dir = ctx.directory.read().await;
                    is_known_relay_addr(&dir, sender_addr)
                };
                if !known_sender {
                    debug!("PunchNotify from {} which is not a known relay; ignoring", sender_addr);
                    return Ok(());
                }

                let notify = PunchNotify::decode(&payload)?;

                // 送り主自身がループバックのときだけ、候補のループバックも許す（試験用）。
                let sender_is_loopback = crate::net::addr::normalize(sender_addr).ip().is_loopback();
                let candidates = sanitize_punch_candidates(&notify.candidates, sender_is_loopback);
                if candidates.is_empty() {
                    debug!("PunchNotify from {} has no usable candidates after filtering", sender_addr);
                    return Ok(());
                }
                debug!("Punching towards {} candidate(s)", candidates.len());

                // 通知を受けたら一定時間プローブし続ける。
                // 双方が同じことをするので、時計を合わせなくても窓が重なる
                let socket = ctx.socket.clone();
                tokio::spawn(async move {
                    let mut session = PunchSession::new();
                    let deadline = tokio::time::Instant::now() + punch::PROBE_WINDOW;

                    while tokio::time::Instant::now() < deadline {
                        let _ = session.probe_round(&socket, &candidates).await;
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
                //
                // **送り主がディレクトリ上の既知リレーでなければ無視する。**
                // 認証なしで通れば、誰でも任意のノードに任意の宛先へ UDP を
                // 撃たせる踏み台になる（本来この指示は FilterCheck の仲介役しか出さない）。
                let Some(sender_addr) = ctx.remote_addr else {
                    debug!("FilterProbeOrder without an observed source; ignoring");
                    return Ok(());
                };
                let known_sender = {
                    let dir = ctx.directory.read().await;
                    is_known_relay_addr(&dir, sender_addr)
                };
                if !known_sender {
                    debug!("FilterProbeOrder from {} which is not a known relay; ignoring", sender_addr);
                    return Ok(());
                }

                let order = FilterProbeOrder::decode(&payload)?;

                // 候補の絞り込みは PunchNotify と同じ基準（未指定・マルチキャスト・
                // ブロードキャスト除外、送り主がループバックでない限りループバック除外）
                let sender_is_loopback = crate::net::addr::normalize(sender_addr).ip().is_loopback();
                let targets = sanitize_punch_candidates(std::slice::from_ref(&order.target), sender_is_loopback);
                let Some(&target) = targets.first() else {
                    debug!("FilterProbeOrder target {} rejected by sanitization", order.target);
                    return Ok(());
                };

                let probe = punch::build_probe(stun::agent::TransactionId::new())?;
                let _ = ctx.socket.send_raw(target, &probe).await;
            },
            PacketType::PexResponse => {
                let response = PexResponse::decode(&payload)?;
                let count = response.relays.len();

                let (added, conflicts) = {
                    let mut dir = ctx.directory.write().await;
                    pex::absorb_response_with_conflicts(&mut dir, response)
                };
                for (descriptor, blockers) in conflicts {
                    Self::spawn_resolve_claim(&ctx, descriptor, blockers);
                }

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

                let trusted = {
                    let dir = ctx.directory.read().await;
                    is_trusted_reply_gateway(&dir, reply_to.gateway)
                };
                if !trusted {
                    debug!(
                        "IndexQuery reply_to.gateway {} is not a known relay accepting strangers; discarding",
                        reply_to.gateway
                    );
                    return Ok(());
                }

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

                let trusted = {
                    let dir = ctx.directory.read().await;
                    is_trusted_reply_gateway(&dir, reply_to.gateway)
                };
                if !trusted {
                    debug!(
                        "MailboxGet reply_to.gateway {} is not a known relay accepting strangers; discarding",
                        reply_to.gateway
                    );
                    return Ok(());
                }

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
                let dir = ctx.directory.read().await;
                let is_allowed_next = |addr: SocketAddr| ctx.is_self(addr) || is_known_relay_addr(&dir, addr);
                if let Err(e) = Self::register_tunnel_build(
                    &ctx.router,
                    &ctx.tunnel_relay,
                    &payload,
                    ctx.remote_addr,
                    is_allowed_next,
                )
                .await
                {
                    error!("Failed to process TunnelBuild: {}", e);
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
                        if ctx.is_self(next_hop) {
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

    /// アドレスの取り合い（同じ IP:port・IP ごとの上限）を到達確認で決着させる
    ///
    /// 登録は先着順なので、攻撃者が他人の IP を書いた記述子を先に配ると本物が締め出される。
    /// 新しい記述子と、それを妨げている既存の記述子の両方へ NodeId を指定して接続し
    /// （証明書が NodeId の鍵なので、接続できる＝鍵の持ち主がそこにいる）、
    /// 応答しなかった既存のものを消してから、新しいものが応答していれば入れ直す。
    ///
    /// 衝突する記述子を作るにも NodeId PoW が要るので、確認の回数は自然に抑えられる。
    /// 同じ NodeId の確認を同時に何本も走らせないようにだけしておく。
    fn spawn_resolve_claim(ctx: &PacketContext, descriptor: RelayDescriptor, blockers: Vec<NodeId>) {
        static IN_FLIGHT: std::sync::OnceLock<Mutex<std::collections::HashSet<NodeId>>> =
            std::sync::OnceLock::new();
        let in_flight = IN_FLIGHT.get_or_init(Default::default);
        if !in_flight.lock().unwrap().insert(descriptor.node_id) {
            return;
        }
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if ctx.router.probe_identity(descriptor.addr, descriptor.node_id).await {
                for id in blockers {
                    let target = ctx.directory.read().await.get(&id).map(|d| (d.addr, d.node_id));
                    let Some((addr, node_id)) = target else { continue };
                    if node_id == ctx.descriptor.node_id {
                        continue; // 自分自身は消さない
                    }
                    if !ctx.router.probe_identity(addr, node_id).await {
                        debug!("Relay {} did not answer at {}; dropping its claim", node_id, addr);
                        ctx.directory.write().await.remove(&node_id);
                    }
                }
                if let Err(e) = ctx.directory.write().await.insert(descriptor.clone()) {
                    debug!("Descriptor for {} still rejected after probing: {}", descriptor.node_id, e);
                }
            }
            in_flight.lock().unwrap().remove(&descriptor.node_id);
        });
    }

    /// Dandelion++ の注入点 ── stem（1本道）で運ぶか fluff（放流）するか決める (3-2)
    ///
    /// onion 出口での投入と、stem 相の中継の両方から呼ぶ。fluff なら通常の gossip 放流
    /// ([`relay_hint`](Self::relay_hint)) に落とす。stem なら
    /// [`stem_forward_with_retry`](Self::stem_forward_with_retry) に委ね、
    /// **ACK が返らない黒穴後継は別の後継へ echo 再送**する。
    async fn inject_hint(hint_bytes: &[u8], sender: Option<NodeId>, ctx: &PacketContext) {
        let packet: HintPacket = match bincode::deserialize(hint_bytes) {
            Ok(p) => p,
            Err(e) => {
                debug!("Invalid Hint for injection discarded: {}", e);
                return;
            }
        };

        // **PoW を確かめてから stem へ流す。** ここを通さないと、PoW を解いていない
        // Hint を大量に StemHint として投げつけるだけで stem 経路（後継への再送・
        // フェイルセーフの fluff）を焚きつけられる（fluff 側の relay_hint は
        // handle_hint_packet 内で確認しているが、stem に乗る間は素通し）。
        if !packet.verify_pow(ctx.gossip.pow_difficulty()) {
            debug!("Hint for injection failed PoW check; discarded");
            return;
        }

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
                // 再送ループは ACK 待ちで時間がかかるので、投入経路を塞がないよう独立タスクへ。
                let id = packet.id();
                let ctx2 = ctx.clone();
                let bytes = hint_bytes.to_vec();
                tokio::spawn(async move {
                    Self::stem_forward_with_retry(bytes, id, target, sender_id, neighbors, ctx2)
                        .await;
                });
            }
            Route::Fluff => {
                let _ = Self::relay_hint(hint_bytes, ctx).await;
            }
        }
    }

    /// stem を後継へ送り、ACK が返らなければ別の後継へ echo 再送する (3-2)
    ///
    /// 後継へ [`StemHint`](PacketType::StemHint) を投げ、[`DANDELION_STEM_ACK_TIMEOUT`]
    /// 内に [`StemAck`](PacketType::StemAck) が返るか待つ。返れば後継は生きているので
    /// stem を託し、悪意ある drop に備えて [`spawn_stem_failsafe`](Self::spawn_stem_failsafe)
    /// だけ残す。返らなければ黒穴とみなし、その後継を除外して別の後継へ再送する
    /// （[`DANDELION_MAX_STEM_RETRIES`] 回まで）。生きた後継が尽きたら自分で fluff して
    /// **配送を必ず保証する**。ACK は最適化であって、配送保証は fluff フォールバックが担う。
    async fn stem_forward_with_retry(
        hint_bytes: Vec<u8>,
        id: [u8; 32],
        first_target: NodeId,
        sender_id: NodeId,
        neighbors: Vec<NodeId>,
        ctx: PacketContext,
    ) {
        // 送り主へは戻さない。ACK が返らなかった後継も順に積んで除外していく。
        let mut excluded: Vec<NodeId> = vec![sender_id];
        let mut target = first_target;

        for _ in 0..DANDELION_MAX_STEM_RETRIES {
            let addr = {
                let dir = ctx.directory.read().await;
                dir.get(&target).map(|d| d.addr)
            };

            let Some(addr) = addr else {
                // 後継の記述子が引けない → 別の後継へ
                excluded.push(target);
                match Self::next_stem_successor(&ctx, &neighbors, &excluded) {
                    Some(t) => {
                        target = t;
                        continue;
                    }
                    None => break,
                }
            };

            // ACK 待ちを登録してから送る（速い ACK を取りこぼさない）
            let notify = Arc::new(Notify::new());
            ctx.stem_acks.lock().unwrap().insert(id, notify.clone());

            // **送信自体も時間で括る。** 後継が黒穴だと QUIC のダイヤルがそこで刺さり、
            // await したままだと再送ループごと止まる（＝黒穴で放流が落ちる）。送信が
            // 時間内に返らなければ、その後継は死んでいるとみなして次へ回す。
            let acked = match tokio::time::timeout(
                DANDELION_STEM_ACK_TIMEOUT,
                ctx.router
                    .send_packet(addr, PacketType::StemHint, &hint_bytes),
            )
            .await
            {
                // 送れた → 残り時間で ACK を待つ
                Ok(_) => tokio::select! {
                    _ = notify.notified() => true,
                    _ = tokio::time::sleep(DANDELION_STEM_ACK_TIMEOUT) => false,
                },
                // 送信が時間内に返らない = 黒穴
                Err(_) => false,
            };
            ctx.stem_acks.lock().unwrap().remove(&id);

            if acked {
                // 後継は生きて受け取った。悪意ある drop に備え gossip タイムアウトの
                // フェイルセーフだけ残す（黒穴でも最終的に配送を保証する）。
                Self::spawn_stem_failsafe(id, hint_bytes, ctx);
                return;
            }

            // ACK が来ない = 黒穴。除外して別の後継へ。
            debug!("Dandelion: stem successor did not ACK; trying another");
            excluded.push(target);
            match Self::next_stem_successor(&ctx, &neighbors, &excluded) {
                Some(t) => target = t,
                None => break,
            }
        }

        // 生きた後継が尽きた → 自分で fluff して配送を保証する
        if !ctx.gossip.has_seen(&id).await {
            debug!("Dandelion: no live stem successor; fluffing");
            let _ = Self::relay_hint(&hint_bytes, &ctx).await;
        }
    }

    /// 除外集合を避けて次のステム後継を引く（3-2 echo 再送）
    fn next_stem_successor(
        ctx: &PacketContext,
        neighbors: &[NodeId],
        excluded: &[NodeId],
    ) -> Option<NodeId> {
        ctx.dandelion.lock().unwrap().choose_successor(
            neighbors,
            excluded,
            std::time::Instant::now(),
            &mut rand::thread_rng(),
        )
    }

    /// stem した Hint が [`DANDELION_STEM_TIMEOUT`] 内に fluff で戻らなければ自分で fluff する
    ///
    /// 後継が ACK を返してから握りつぶす（悪意ある黒穴）ケースの最終フォールバック (3-2)。
    fn spawn_stem_failsafe(id: [u8; 32], hint_bytes: Vec<u8>, ctx: PacketContext) {
        tokio::spawn(async move {
            tokio::time::sleep(DANDELION_STEM_TIMEOUT).await;
            if !ctx.gossip.has_seen(&id).await {
                debug!("Dandelion fail-safe: fluffing a stemmed hint");
                let _ = Self::relay_hint(&hint_bytes, &ctx).await;
            }
        });
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
                dir.random_path(
                    gossip_server::gossip_fanout(dir.len()),
                    std::slice::from_ref(&ctx.descriptor.node_id),
                )
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
            // **署名し直してから入れる。** 署名が古い（Reversed 時点の）ままだと、
            // 他ノードが受け取った際に署名不一致で弾かれ、issued_at も進まない
            // ので、この昇格が網全体に広まらない。
            promoted.resign(&self.identity);
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
            self.refresh_descriptor().await;
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
        let request = self.pex_request();

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

                let Ok(request) = request.encode() else {
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
        let directory = self.directory.clone();
        let node_id = self.descriptor.node_id;

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

                // 期限切れの記述子を掃除する。死んだノードや大昔の記述子が
                // 網に残り続け、PEX でも配られ続けるのを防ぐ。自分の記述子は
                // （たとえ resign タスクが動いていなくても）消さない。
                let removed = directory.write().await.prune_expired(current_timestamp(), &node_id);
                if removed > 0 {
                    info!("GC: removed {} expired relay descriptors", removed);
                }
            }
        });
    }

    /// 自分の記述子を定期的に署名し直してディレクトリへ入れ直す
    ///
    /// [`RelayDescriptor::issued_at`] は起動時に決まったきり進まないと、
    /// [`DESCRIPTOR_TTL_SECS`](crate::net::relay_list::DESCRIPTOR_TTL_SECS) を過ぎて
    /// 期限切れ扱いになり、ディレクトリの GC や PEX から自分が消えてしまう
    /// （常駐リレーのはずが、いつの間にか誰にも配られなくなる）。
    ///
    /// 署名し直す元はディレクトリ上の**最新の**記述子（`dir.get`）を使う。
    /// フィルタ判定で Tier 0 へ昇格した記述子（[`refresh_descriptor`](Self::refresh_descriptor)
    /// を経由せずディレクトリへ直接 `insert_unchecked` されることがある）を
    /// 取りこぼさないため。
    fn spawn_resign(&self) {
        let identity = self.identity.clone();
        let directory = self.directory.clone();
        let node_id = self.descriptor.node_id;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(DESCRIPTOR_RESIGN_INTERVAL);
            // 起動直後は署名したてなので即時発火は捨てる
            ticker.tick().await;

            loop {
                ticker.tick().await;

                let mut dir = directory.write().await;
                let Some(mut latest) = dir.get(&node_id).cloned() else {
                    // 万一自分の記述子が無ければ何もしない（起動時に必ず入れているはず）
                    continue;
                };
                latest.resign(&identity);
                dir.insert_unchecked(latest);
            }
        });
    }

    /// エポックビーコン（drand 由来の日次シード）を回す (3-4)
    ///
    /// 起動時と各エポック境界で drand から seed を取得し、ディレクトリへ反映する。
    /// これでリング座標 `H(NodeId ‖ epoch_seed)` が日次で回転し、位置グラインディングした
    /// NodeId が1日で無効化される。
    ///
    /// **取得に失敗しても placeholder に戻さない。** 戻すと drand を引けた他ノードと
    /// シードが食い違い、保持者計算がずれて網が分裂する。失敗時は現在のシードを据え置き、
    /// 短い間隔で再試行する（drand の一時障害・起動直後のオフラインを吸収する）。
    fn spawn_epoch_beacon(&self) {
        let directory = self.directory.clone();

        tokio::spawn(async move {
            /// 失敗時の再試行間隔
            const RETRY_SECS: u64 = 300;

            loop {
                let epoch = crate::net::epoch::epoch_index(current_timestamp());

                // ブロッキング HTTP なので blocking プールへ逃がす
                let fetched =
                    tokio::task::spawn_blocking(move || crate::net::epoch::fetch_epoch_seed(epoch))
                        .await;

                let succeeded = match fetched {
                    Ok(Ok(seed)) => {
                        directory.write().await.set_epoch_seed(seed);
                        info!(
                            "Epoch beacon: epoch {} seed set ({}...)",
                            epoch,
                            hex::encode(&seed[..8])
                        );
                        true
                    }
                    Ok(Err(e)) => {
                        warn!("Epoch beacon fetch failed ({}); keeping current seed", e);
                        false
                    }
                    Err(e) => {
                        warn!("Epoch beacon task panicked: {}", e);
                        false
                    }
                };

                // 成功したら次のエポック境界（+60s 猶予）まで、失敗したら短く再試行
                let sleep_secs = if succeeded {
                    let into_epoch = current_timestamp() % crate::net::epoch::EPOCH_SECS;
                    (crate::net::epoch::EPOCH_SECS - into_epoch) + 60
                } else {
                    RETRY_SECS
                };
                tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
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

#[cfg(test)]
mod reply_guard_tests {
    use super::*;
    use crate::crypto::identity::Identity;

    fn descriptor(addr: &str, tier: Tier) -> RelayDescriptor {
        let id = Identity::generate();
        RelayDescriptor::new_signed(&id, addr.parse().unwrap(), 0, tier)
    }

    fn dir_with(descriptors: Vec<RelayDescriptor>) -> RelayDirectory {
        let mut dir = RelayDirectory::new([0u8; 32], 0);
        for d in descriptors {
            dir.insert_unchecked(d);
        }
        dir
    }

    #[test]
    fn trusted_reply_gateway_requires_known_and_open() {
        let open = descriptor("127.0.0.1:9001", Tier::Open);
        let reversed = descriptor("127.0.0.1:9002", Tier::Reversed);
        let dir = dir_with(vec![open.clone(), reversed.clone()]);

        assert!(is_trusted_reply_gateway(&dir, open.addr));
        assert!(!is_trusted_reply_gateway(&dir, reversed.addr));
        assert!(!is_trusted_reply_gateway(&dir, "203.0.113.5:1".parse().unwrap()));
    }

    #[test]
    fn trusted_reply_gateway_normalizes_ipv4_mapped_addr() {
        let open = descriptor("127.0.0.1:9001", Tier::Open);
        let dir = dir_with(vec![open.clone()]);
        let mapped: SocketAddr = format!("[::ffff:127.0.0.1]:{}", open.addr.port()).parse().unwrap();
        assert!(is_trusted_reply_gateway(&dir, mapped));
    }

    #[test]
    fn known_relay_addr_ignores_tier() {
        let reversed = descriptor("127.0.0.1:9003", Tier::Reversed);
        let dir = dir_with(vec![reversed.clone()]);
        assert!(is_known_relay_addr(&dir, reversed.addr));
        assert!(!is_known_relay_addr(&dir, "203.0.113.5:1".parse().unwrap()));
    }

    #[test]
    fn sanitize_candidates_drops_dangerous_addresses() {
        let candidates: Vec<SocketAddr> = vec![
            "203.0.113.5:1".parse().unwrap(),
            "0.0.0.0:1".parse().unwrap(),
            "239.255.0.1:1".parse().unwrap(),
            "255.255.255.255:1".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        ];
        // 送り主がループバックでない → ループバック候補も落とす
        let kept = sanitize_punch_candidates(&candidates, false);
        assert_eq!(kept, vec!["203.0.113.5:1".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn sanitize_candidates_allows_loopback_when_sender_is_loopback() {
        let candidates: Vec<SocketAddr> = vec!["127.0.0.1:1".parse().unwrap()];
        let kept = sanitize_punch_candidates(&candidates, true);
        assert_eq!(kept, candidates);
    }

    #[test]
    fn sanitize_candidates_caps_at_four() {
        let candidates: Vec<SocketAddr> = (1u16..=6)
            .map(|p| format!("203.0.113.5:{}", p).parse().unwrap())
            .collect();
        assert_eq!(sanitize_punch_candidates(&candidates, false).len(), 4);
    }
}
