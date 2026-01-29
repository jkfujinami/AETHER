use crate::error::{Result, AetherError};
use sled::Db;
use std::path::Path;
use crate::Config;

pub struct MailboxServer {
    db: Db,
    // capacity management, TTL checking handled by scavenging thread
}

impl MailboxServer {
    pub fn new(path: &Path, _config: &Config) -> Result<Self> {
        let db = sled::open(path).map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(Self { db })
    }

    pub async fn handle_put(&self, payload: &[u8]) -> Result<()> {
        // Payload expected: [Key(32)][Value(...)]
        if payload.len() < 32 {
            return Err(AetherError::Protocol("Mailbox PUT payload too short".into()));
        }
        let (key, value) = payload.split_at(32);

        // TODO: 容量チェック、TTL設定

        self.db.insert(key, value).map_err(|e| AetherError::Storage(e.to_string()))?;

        Ok(())
    }

    pub async fn handle_get(&self, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        // Payload expected: [Key(32)]
        if payload.len() < 32 {
             return Err(AetherError::Protocol("Mailbox GET payload too short".into()));
        }
        let key = &payload[0..32];
        if let Some(ivec) = self.db.get(key).map_err(|e| AetherError::Storage(e.to_string()))? {
             // 取得したら消すべきか？シュレーディンガーメールボックスの定義では消す
             self.db.remove(key).map_err(|e| AetherError::Storage(e.to_string()))?;
             Ok(Some(ivec.to_vec()))
        } else {
            Ok(None)
        }
    }

    // Tunnel用: [tunnel:{tunnel_id}:{timestamp}] -> Data
    pub async fn store_tunnel_message(&self, tunnel_id: &[u8; 32], data: &[u8]) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        // Key: "tunnel:" + tunnel_id + now(u128 big endian)
        let mut key = Vec::with_capacity(7 + 32 + 16);
        key.extend_from_slice(b"tunnel:");
        key.extend_from_slice(tunnel_id);
        key.extend_from_slice(&now.to_be_bytes());

        self.db.insert(key, data).map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(())
    }

    // 指定したtunnel_id宛のメッセージを全て取得し、削除して返す
    pub async fn fetch_tunnel_messages(&self, tunnel_id: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
        let mut prefix = Vec::with_capacity(7 + 32);
        prefix.extend_from_slice(b"tunnel:");
        prefix.extend_from_slice(tunnel_id);

        let mut messages = Vec::new();

        // Scan prefix
        for item in self.db.scan_prefix(&prefix) {
            let (k, v) = item.map_err(|e| AetherError::Storage(e.to_string()))?;
            messages.push(v.to_vec());
            self.db.remove(k).map_err(|e| AetherError::Storage(e.to_string()))?;
        }

        Ok(messages)
    }
}
