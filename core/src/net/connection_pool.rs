use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use quinn::Connection;
use crate::error::Result;
use crate::net::quic::QuicClient;

/// 接続のメタデータ
struct ConnectionEntry {
    connection: Connection,
    last_used: Instant,
    created_at: Instant,
}

/// QUIC 接続のプール
/// TTL と最大接続数を管理し、アイドル接続を自動削除
pub struct ConnectionPool {
    quic_client: Arc<QuicClient>,
    connections: Arc<RwLock<HashMap<SocketAddr, ConnectionEntry>>>,
    ttl: Duration,
    idle_timeout: Duration,
    max_connections: usize,
}

impl ConnectionPool {
    /// 新しい Connection Pool を作成
    pub fn new(quic_client: Arc<QuicClient>) -> Self {
        Self {
            quic_client,
            connections: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(60),           // 接続の最大寿命: 60秒
            idle_timeout: Duration::from_secs(10),  // アイドルタイムアウト: 10秒
            max_connections: 100,                   // 最大接続数
        }
    }

    /// 接続を取得（既存の接続を再利用、または新規作成）
    pub async fn get_connection(&self, addr: SocketAddr, server_name: &str) -> Result<Connection> {
        // クリーンアップを実行
        self.cleanup().await;

        // 既存の接続をチェック
        {
            let mut pool = self.connections.write().await;
            if let Some(entry) = pool.get_mut(&addr) {
                let now = Instant::now();

                // TTL チェック
                if now.duration_since(entry.created_at) < self.ttl {
                    // 接続が有効
                    entry.last_used = now;
                    return Ok(entry.connection.clone());
                } else {
                    // TTL 超過、削除
                    pool.remove(&addr);
                }
            }
        }

        // 新しい接続を作成
        let connection = self.quic_client.connect(addr, server_name).await?;

        // プールに追加
        {
            let mut pool = self.connections.write().await;

            // 最大接続数チェック（LRU削除）
            if pool.len() >= self.max_connections {
                self.evict_lru(&mut pool).await;
            }

            let now = Instant::now();
            pool.insert(addr, ConnectionEntry {
                connection: connection.clone(),
                last_used: now,
                created_at: now,
            });
        }

        Ok(connection)
    }

    /// アイドル接続と期限切れ接続をクリーンアップ
    async fn cleanup(&self) {
        let mut pool = self.connections.write().await;
        let now = Instant::now();

        pool.retain(|_addr, entry| {
            // TTL チェック
            if now.duration_since(entry.created_at) >= self.ttl {
                return false;
            }

            // アイドルタイムアウトチェック
            if now.duration_since(entry.last_used) >= self.idle_timeout {
                return false;
            }

            // 接続が閉じられているかチェック
            if entry.connection.close_reason().is_some() {
                return false;
            }

            true
        });
    }

    /// LRU（最も使われていない）接続を削除
    async fn evict_lru(&self, pool: &mut HashMap<SocketAddr, ConnectionEntry>) {
        if let Some((&addr, _)) = pool.iter()
            .min_by_key(|(_, entry)| entry.last_used)
        {
            pool.remove(&addr);
        }
    }

    /// プール内の接続数を取得（デバッグ用）
    pub async fn size(&self) -> usize {
        self.connections.read().await.len()
    }

    /// すべての接続をクローズしてプールをクリア
    pub async fn clear(&self) {
        let mut pool = self.connections.write().await;
        for (_, entry) in pool.drain() {
            entry.connection.close(0u32.into(), b"pool cleared");
        }
    }
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[tokio::test]
    async fn test_connection_pool_basic() {
        // Basic functionality test would go here
        // Requires mock QuicClient
    }
}
