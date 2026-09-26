//! QUIC 接続プール
//!
//! # Connection Reversal
//!
//! NAT の内側にいるノードには、こちらからダイヤルしても届かない。
//! しかし**相手が張った接続の上でなら、こちらからストリームを開ける**
//! （QUIC は双方向）。
//!
//! そこで accept した接続もプールに登録し、送信時にまず再利用を試みる。
//! これが無いと NAT 内ノードは「保持者」になれず、
//! キャッシュが「自分が取りに行ったものだけ」になって
//! 否認可能性 (設計書 18.3-C) が構造的に消える。
//!
//! Winny の Port0 救済、BitTorrent の BEP 55、libp2p の Circuit Relay、
//! Tailscale の DERP が全部この形に収束している。
//!
//! # inbound と outbound で寿命が違う
//!
//! outbound は使い終わったら畳んでよいが、**inbound を TTL で切ると
//! NAT 内ノードへの唯一の経路を自分から捨てることになる。**
//! inbound は相手が閉じるまで保持する。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use quinn::Connection;
use crate::error::Result;
use crate::net::quic::QuicClient;
use crate::net::addr::normalize;
use tokio::sync::mpsc;
use std::sync::Mutex as StdMutex;

/// 接続の由来
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// 自分からダイヤルした
    Outbound,
    /// 相手から来た。**NAT 内ノードへの唯一の経路になりうる**
    Inbound,
    /// 自分からダイヤルし、keepalive で保ち続ける（返信トンネルの戻り道）
    Pinned,
}

struct ConnectionEntry {
    connection: Connection,
    origin: Origin,
    last_used: Instant,
    created_at: Instant,
}

impl ConnectionEntry {
    fn is_alive(&self) -> bool {
        self.connection.close_reason().is_none()
    }
}

/// 発信手段
///
/// 待ち受けと同じエンドポイントを使うのが正しい（NAT マッピングを共有するため）。
/// 独立クライアントは、待ち受けを持たない純クライアント用。
enum Dialer {
    Endpoint(quinn::Endpoint),
    Client(Arc<QuicClient>),
}

impl Dialer {
    async fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<Connection> {
        match self {
            Dialer::Endpoint(ep) => ep
                .connect(addr, server_name)
                .map_err(|e| crate::AetherError::Quic(e.to_string()))?
                .await
                .map_err(|e| crate::AetherError::Quic(e.to_string())),
            Dialer::Client(c) => c.connect(addr, server_name).await,
        }
    }

    async fn connect_keepalive(&self, addr: SocketAddr, server_name: &str) -> Result<Connection> {
        match self {
            Dialer::Endpoint(ep) => ep
                .connect_with(QuicClient::keepalive_config()?, addr, server_name)
                .map_err(|e| crate::AetherError::Quic(e.to_string()))?
                .await
                .map_err(|e| crate::AetherError::Quic(e.to_string())),
            Dialer::Client(c) => c.connect_keepalive(addr, server_name).await,
        }
    }
}

pub struct ConnectionPool {
    dialer: Dialer,
    /// 新しく張った outbound 接続の通知
    ///
    /// **ダイヤルした側も受信ストリームを読む必要がある。**
    /// Connection Reversal では相手がこの接続の上で押し返してくるので、
    /// 読まないと応答が全て捨てられる。
    opened_tx: StdMutex<Option<mpsc::UnboundedSender<Connection>>>,
    connections: Arc<RwLock<HashMap<SocketAddr, ConnectionEntry>>>,
    ttl: Duration,
    idle_timeout: Duration,
    max_connections: usize,
    /// 最後に cleanup を走らせた時刻
    ///
    /// パケット送信ごとに全走査すると、書き込みロックが送信のホットパスを
    /// 直列化する。間隔を空けて償却する。
    last_cleanup: Arc<RwLock<Instant>>,
}

/// cleanup を走らせる最短間隔
const CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

impl ConnectionPool {
    pub fn new(quic_client: Arc<QuicClient>) -> Self {
        Self::with_dialer(Dialer::Client(quic_client))
    }

    /// 待ち受けと同じエンドポイントから発信する
    pub fn from_endpoint(endpoint: quinn::Endpoint) -> Self {
        Self::with_dialer(Dialer::Endpoint(endpoint))
    }

    /// 新規 outbound 接続の通知を受け取る
    ///
    /// 受け取った側は `accept_uni()` を回すこと。
    /// これをしないと、相手が既存接続の上で押し返してきた応答を取りこぼす。
    pub fn subscribe_opened(&self) -> mpsc::UnboundedReceiver<Connection> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.opened_tx.lock().unwrap() = Some(tx);
        rx
    }

    fn with_dialer(dialer: Dialer) -> Self {
        Self {
            dialer,
            opened_tx: StdMutex::new(None),
            connections: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(60),           // outbound の最大寿命
            idle_timeout: Duration::from_secs(10),  // outbound のアイドル上限
            max_connections: 100,
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// accept した接続を登録する
    ///
    /// **これを呼ばないと NAT 内の相手へ送り返せない。**
    /// 送信時に `get_connection` がこれを見つけて再利用する。
    pub async fn register_inbound(&self, connection: Connection) {
        // デュアルスタックでは v4 ピアが ::ffff:a.b.c.d に見える。
        // 正規化しないと検索キーと一致せず Connection Reversal が壊れる
        let addr = normalize(connection.remote_address());
        let now = Instant::now();

        let mut pool = self.connections.write().await;
        pool.insert(addr, ConnectionEntry {
            connection,
            origin: Origin::Inbound,
            last_used: now,
            created_at: now,
        });
    }

    /// 接続を取得する
    ///
    /// 生きている接続があれば**由来を問わず再利用する**。
    /// 相手が NAT 内なら、相手が張った接続だけが到達経路になる。
    pub async fn get_connection(&self, addr: SocketAddr, server_name: &str) -> Result<Connection> {
        let addr = normalize(addr);
        self.cleanup().await;

        if let Some(conn) = self.take_live(addr).await {
            return Ok(conn);
        }

        // 生きた接続が無いのでダイヤルする
        let connection = self.dialer.connect(addr, server_name).await?;

        // ダイヤルした接続も受信を回してもらう
        if let Some(tx) = self.opened_tx.lock().unwrap().as_ref() {
            let _ = tx.send(connection.clone());
        }

        {
            let mut pool = self.connections.write().await;

            if pool.len() >= self.max_connections {
                Self::evict_lru(&mut pool);
            }

            let now = Instant::now();
            pool.insert(addr, ConnectionEntry {
                connection: connection.clone(),
                origin: Origin::Outbound,
                last_used: now,
                created_at: now,
            });
        }

        Ok(connection)
    }

    /// keepalive 付きの接続を張り、寿命で捨てずに保つ
    ///
    /// 返信トンネルの終端に使う。相手（ガード）はこの接続の上でしか
    /// 自分へ返信を届けられない（自分が NAT の内側でも、広告アドレスが無くても）。
    /// 既に保っている生きた接続があればそれを返す。
    pub async fn pin_connection(&self, addr: SocketAddr, server_name: &str) -> Result<Connection> {
        let addr = normalize(addr);
        {
            let pool = self.connections.read().await;
            if let Some(entry) = pool.get(&addr)
                && entry.origin == Origin::Pinned
                && entry.is_alive()
            {
                return Ok(entry.connection.clone());
            }
        }

        let connection = self.dialer.connect_keepalive(addr, server_name).await?;

        // 受信も回してもらう（返信はこの接続の上で届く）
        if let Some(tx) = self.opened_tx.lock().unwrap().as_ref() {
            let _ = tx.send(connection.clone());
        }

        let now = Instant::now();
        let mut pool = self.connections.write().await;
        if pool.len() >= self.max_connections {
            Self::evict_lru(&mut pool);
        }
        pool.insert(addr, ConnectionEntry {
            connection: connection.clone(),
            origin: Origin::Pinned,
            last_used: now,
            created_at: now,
        });
        Ok(connection)
    }

    /// 生きた接続があるか（診断用）
    pub async fn has_live_connection(&self, addr: SocketAddr) -> bool {
        self.take_live(addr).await.is_some()
    }

    /// 生きている接続があれば返す（ダイヤルはしない）
    ///
    /// NAT 内ノード宛てで、相手が接続を張っていない場合は `None`。
    /// 呼び出し側は「今は届かない」と判断できる。
    pub async fn live_connection(&self, addr: SocketAddr) -> Option<Connection> {
        self.take_live(addr).await
    }

    async fn take_live(&self, addr: SocketAddr) -> Option<Connection> {
        let addr = normalize(addr);
        let mut pool = self.connections.write().await;
        let entry = pool.get_mut(&addr)?;

        if !entry.is_alive() {
            pool.remove(&addr);
            return None;
        }

        // outbound だけ寿命を見る。
        // inbound を寿命で切ると NAT 内ノードへの唯一の経路を捨てることになる
        if entry.origin == Origin::Outbound
            && entry.created_at.elapsed() >= self.ttl
        {
            pool.remove(&addr);
            return None;
        }

        entry.last_used = Instant::now();
        Some(entry.connection.clone())
    }

    /// 掃除を明示的に走らせる（定期メンテナンス用）
    ///
    /// 送信のたびに全走査すると書き込みロックがホットパスを直列化するので、
    /// 通常は間隔を空けて償却している。定期タスクからはこちらを呼ぶ。
    pub async fn maintain(&self) {
        let mut last = self.last_cleanup.write().await;
        *last = Instant::now() - CLEANUP_INTERVAL;
        drop(last);
        self.cleanup().await;
    }

    /// 死んだ接続と、期限切れの outbound を掃除する
    async fn cleanup(&self) {
        {
            let last = self.last_cleanup.read().await;
            if last.elapsed() < CLEANUP_INTERVAL {
                return;
            }
        }
        {
            let mut last = self.last_cleanup.write().await;
            if last.elapsed() < CLEANUP_INTERVAL {
                return; // 別タスクが先に走らせた
            }
            *last = Instant::now();
        }

        let mut pool = self.connections.write().await;

        pool.retain(|_addr, entry| {
            if !entry.is_alive() {
                return false;
            }

            // inbound と pinned は相手が閉じるまで保持する
            if entry.origin != Origin::Outbound {
                return true;
            }

            entry.created_at.elapsed() < self.ttl
                && entry.last_used.elapsed() < self.idle_timeout
        });
    }

    /// LRU 削除。**inbound は最後の手段としてのみ落とす**
    fn evict_lru(pool: &mut HashMap<SocketAddr, ConnectionEntry>) {
        let victim = pool
            .iter()
            .filter(|(_, e)| e.origin == Origin::Outbound)
            .min_by_key(|(_, e)| e.last_used)
            .map(|(addr, _)| *addr)
            .or_else(|| {
                pool.iter()
                    .min_by_key(|(_, e)| e.last_used)
                    .map(|(addr, _)| *addr)
            });

        if let Some(addr) = victim {
            pool.remove(&addr);
        }
    }

    pub async fn size(&self) -> usize {
        self.connections.read().await.len()
    }

    /// 保持している inbound 接続の数（診断用）
    ///
    /// これが 0 の場合、NAT 内ノードへは何も送り返せない。
    pub async fn inbound_count(&self) -> usize {
        self.connections
            .read()
            .await
            .values()
            .filter(|e| e.origin == Origin::Inbound)
            .count()
    }

    pub async fn clear(&self) {
        let mut pool = self.connections.write().await;
        for (_, entry) in pool.drain() {
            entry.connection.close(0u32.into(), b"pool cleared");
        }
    }
}
