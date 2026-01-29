use crate::error::Result;
use crate::Config;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashSet;

pub struct GossipServer {
    // 簡易的な重複検知キャッシュ
    // 本番環境では Bloom Filter や TTL 付きキャッシュを使うべき
    seen_messages: Arc<Mutex<HashSet<Vec<u8>>>>,
}

impl GossipServer {
    pub fn new(_config: &Config) -> Self {
        Self {
            seen_messages: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Hintパケットを処理する。
    /// 戻り値: true = 新規メッセージ（拡散対象）、false = 重複（無視）
    pub async fn handle_hint(&self, hint_payload: &[u8]) -> Result<bool> {
        let mut seen = self.seen_messages.lock().await;

        // 単純なバイト列比較だが、Hintパケット全体をキーにする
        // メモリ効率を考慮するならハッシュ値のみ保存すべきだが、プロトタイプなので簡易実装
        if seen.contains(hint_payload) {
            return Ok(false);
        }

        // 新規登録
        seen.insert(hint_payload.to_vec());

        // TODO: 定期的なクリーンアップ (Cache Eviction)

        Ok(true)
    }
}
