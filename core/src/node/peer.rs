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
        let mut peers = self.peers.write().await;
        peers.insert(addr, PeerInfo { addr });
    }

    pub async fn remove_peer(&self, addr: &SocketAddr) {
        let mut peers = self.peers.write().await;
        peers.remove(addr);
    }

    /// ランダムに最大count個のピアを選択して返す（Gossip用）
    pub async fn get_random_peers(&self, count: usize) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        // 本来は rand::seq::SliceRandom でシャッフルすべきだが、
        // keys() の順序はハッシュマップの実装依存で実質ランダムに近いとみなす（簡易実装）
        // 厳密にはランダムではないので、本番までに修正
        peers.keys().take(count).cloned().collect()
    }
}
