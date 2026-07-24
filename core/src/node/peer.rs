use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    // 将来的に: last_seen, protocol_version, latencyなど
}

pub struct PeerManager {
    peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_peer(&self, addr: SocketAddr) {
        // デュアルスタックでは v4 ピアが ::ffff:a.b.c.d に見える。
        // 正規化しないと同じノードが2重に載る
        let addr = crate::net::addr::normalize(addr);
        let mut peers = self.peers.write().await;
        peers.insert(addr, PeerInfo { addr });
    }

    pub async fn remove_peer(&self, addr: &SocketAddr) {
        let addr = crate::net::addr::normalize(*addr);
        let mut peers = self.peers.write().await;
        peers.remove(&addr);
    }

    /// ランダムに最大count個のピアを選択して返す（Gossip用）
    ///
    /// **必ず一様乱択すること。** `keys().take(n)` のような決定論的な選択だと、
    /// 早期に接続した攻撃者ノードが永久に拡散先へ居座り、
    /// Sybil ノードが Gossip の観測点を固定できてしまう。
    pub async fn get_random_peers(&self, count: usize) -> Vec<SocketAddr> {
        use rand::seq::SliceRandom;

        let peers = self.peers.read().await;
        let mut addrs: Vec<SocketAddr> = peers.keys().cloned().collect();
        addrs.shuffle(&mut rand::thread_rng());
        addrs.truncate(count);
        addrs
    }

    /// 接続中のピア数
    pub async fn len(&self) -> usize {
        self.peers.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.peers.read().await.is_empty()
    }
}
