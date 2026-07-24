use crate::error::{Result, AetherError};
use crate::protocol::hint::current_timestamp;
use serde::{Serialize, Deserialize};
use sled::Db;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::Config;

/// 1エントリの最大サイズ (1MB)
pub const MAX_ENTRY_BYTES: usize = 1024 * 1024;

/// Tunnel 用エントリのキー接頭辞
const TUNNEL_PREFIX: &[u8] = b"tunnel:";

/// 索引エントリのキー接頭辞（19.7 / Phase 2-3）
const INDEX_PREFIX: &[u8] = b"index:";

/// 1索引につき返す記述子の上限（増幅・肥大対策。19.7）
pub const MAX_INDEX_ENTRIES: usize = 256;

/// ディスク使用量の再測定間隔（秒）
const SIZE_CACHE_TTL_SECS: u64 = 30;

/// 保存されるエントリ
///
/// TTL 判定のために「最後に触られた時刻」を持つ。作成時とアクセス時に更新され、
/// **参照されるほど寿命が延びる**（アクセス連動 TTL / 18.3-B）。
/// これが無いと期限切れ判定ができず Mailbox が無制限に膨らむ。
#[derive(Debug, Serialize, Deserialize)]
struct MailboxEntry {
    value: Vec<u8>,
    /// 作成 or 最終アクセス時刻 (UNIX秒)。TTL はここから測る。
    refreshed_at: u64,
}

pub struct MailboxServer {
    db: Db,
    /// エントリの保持期間（秒）
    ttl_seconds: u64,
    /// DB 全体の容量上限（バイト）
    capacity_bytes: u64,
    /// 直近に測ったディスク使用量
    cached_size: AtomicU64,
    /// 上記を測った時刻 (UNIX秒)
    size_checked_at: AtomicU64,
}

impl MailboxServer {
    pub fn new(path: &Path, config: &Config) -> Result<Self> {
        let db = sled::open(path).map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(Self {
            db,
            ttl_seconds: config.message_ttl_hours * 3600,
            capacity_bytes: config.mailbox_capacity_mb * 1024 * 1024,
            cached_size: AtomicU64::new(0),
            size_checked_at: AtomicU64::new(0),
        })
    }

    /// Payload: [Key(32)][Value(...)]
    pub async fn handle_put(&self, payload: &[u8]) -> Result<()> {
        if payload.len() < 32 {
            return Err(AetherError::Protocol("Mailbox PUT payload too short".into()));
        }
        let (key, value) = payload.split_at(32);

        if value.len() > MAX_ENTRY_BYTES {
            return Err(AetherError::Mailbox(format!(
                "Entry too large: {} bytes (max {})",
                value.len(),
                MAX_ENTRY_BYTES
            )));
        }

        self.ensure_capacity()?;
        self.insert_entry(key, value)
    }

    /// Payload: [Key(32)]
    ///
    /// **no-burn + アクセス連動 TTL（18.3-B / 19.1.2 解決）。**
    /// 取得しても削除せず、代わりに寿命を延ばす。これにより:
    /// - 公開コンテンツが「1回取得で消える／取りに行くだけで検閲される」を防ぐ
    /// - 参照され続けるものは生き残り、放置されたものは TTL で自然消滅する
    ///
    /// 私信でも実害は無い（保持者は中身を読めないので、消しても得は小さい）。
    /// 期限切れのエントリはその場で掃除して None を返す。
    pub async fn handle_get(&self, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        if payload.len() < 32 {
            return Err(AetherError::Protocol("Mailbox GET payload too short".into()));
        }
        let key = &payload[0..32];

        let Some(raw) = self.db.get(key).map_err(|e| AetherError::Storage(e.to_string()))? else {
            return Ok(None);
        };

        let entry = Self::decode_entry(&raw)?;
        let now = current_timestamp();

        if self.is_expired(&entry, now) {
            // 死んでいるエントリは読んだついでに掃除する（no-burn は生きた値だけ）
            let _ = self.db.remove(key);
            return Ok(None);
        }

        // アクセスで寿命を延ばす。ただし毎読み込みで書き戻すと書き込み増幅になるため、
        // TTL の半分を過ぎた時だけ触り直す（読み頻度に依らず書き込みは TTL/2 に1回）。
        if now.saturating_sub(entry.refreshed_at) >= self.ttl_seconds / 2 {
            self.insert_entry(key, &entry.value)?;
        }

        Ok(Some(entry.value))
    }

    // Tunnel用: [tunnel:{tunnel_id}:{timestamp}] -> Data
    pub async fn store_tunnel_message(&self, tunnel_id: &[u8; 32], data: &[u8]) -> Result<()> {
        if data.len() > MAX_ENTRY_BYTES {
            return Err(AetherError::Mailbox(format!(
                "Tunnel message too large: {} bytes (max {})",
                data.len(),
                MAX_ENTRY_BYTES
            )));
        }

        self.ensure_capacity()?;

        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        // Key: "tunnel:" + tunnel_id + now(u128 big endian)
        let mut key = Vec::with_capacity(TUNNEL_PREFIX.len() + 32 + 16);
        key.extend_from_slice(TUNNEL_PREFIX);
        key.extend_from_slice(tunnel_id);
        key.extend_from_slice(&now_nanos.to_be_bytes());

        self.insert_entry(&key, data)
    }

    /// 指定した tunnel_id 宛のメッセージを全て取得し、削除して返す
    pub async fn fetch_tunnel_messages(&self, tunnel_id: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
        let mut prefix = Vec::with_capacity(TUNNEL_PREFIX.len() + 32);
        prefix.extend_from_slice(TUNNEL_PREFIX);
        prefix.extend_from_slice(tunnel_id);

        let now = current_timestamp();
        let mut messages = Vec::new();

        for item in self.db.scan_prefix(&prefix) {
            let (k, v) = item.map_err(|e| AetherError::Storage(e.to_string()))?;
            self.db.remove(&k).map_err(|e| AetherError::Storage(e.to_string()))?;

            let entry = Self::decode_entry(&v)?;
            if !self.is_expired(&entry, now) {
                messages.push(entry.value);
            }
        }

        Ok(messages)
    }

    /// 索引に記述子を1件追加する（19.7 / Phase 2-3）
    ///
    /// キー: `index:{index_key(32)}:{record_id(32)}`。**追記型**で、
    /// 複数の公開者が同じ索引へ足しても互いを上書きしない（集合＝ユニオン）。
    /// `record_id` で重複排除される。no-burn + アクセス連動 TTL は他と共通。
    pub async fn handle_index_put(&self, payload: &[u8]) -> Result<()> {
        // payload: [index_key(32)][record_id(32)][record...]
        if payload.len() < 64 {
            return Err(AetherError::Protocol("IndexPut payload too short".into()));
        }
        let record = &payload[64..];
        if record.len() > MAX_ENTRY_BYTES {
            return Err(AetherError::Mailbox("Index record too large".into()));
        }

        self.ensure_capacity()?;

        let mut key = Vec::with_capacity(INDEX_PREFIX.len() + 64);
        key.extend_from_slice(INDEX_PREFIX);
        key.extend_from_slice(&payload[0..64]); // index_key ‖ record_id
        self.insert_entry(&key, record)
    }

    /// 索引の記述子を列挙する（19.7 / Phase 2-3）
    ///
    /// **削除しない（no-burn）。** 期限切れは除外し、上限で頭打ち。
    /// アクセスで生きているエントリの寿命を延ばす（人気な索引は残る）。
    pub async fn handle_index_list(&self, index_key: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
        let mut prefix = Vec::with_capacity(INDEX_PREFIX.len() + 32);
        prefix.extend_from_slice(INDEX_PREFIX);
        prefix.extend_from_slice(index_key);

        let now = current_timestamp();
        let mut out = Vec::new();

        for item in self.db.scan_prefix(&prefix) {
            let (k, v) = item.map_err(|e| AetherError::Storage(e.to_string()))?;
            let Ok(entry) = Self::decode_entry(&v) else { continue };
            if self.is_expired(&entry, now) {
                continue;
            }
            // アクセスで延命（no-burn + アクセス連動 TTL）
            if now.saturating_sub(entry.refreshed_at) >= self.ttl_seconds / 2 {
                let _ = self.insert_entry(&k, &entry.value);
            }
            out.push(entry.value);
            if out.len() >= MAX_INDEX_ENTRIES {
                break;
            }
        }
        Ok(out)
    }

    /// 期限切れエントリを削除する。戻り値は削除件数
    ///
    /// 定期タスクから呼ぶこと。呼ばれないと Mailbox は無制限に膨らみ、
    /// 任意の相手からのディスク枯渇 DoS が成立する。
    pub fn cleanup_expired(&self) -> Result<usize> {
        let now = current_timestamp();
        let mut removed = 0;

        for item in self.db.iter() {
            let (k, v) = item.map_err(|e| AetherError::Storage(e.to_string()))?;

            // 壊れたエントリも掃除対象にする
            let expired = match Self::decode_entry(&v) {
                Ok(entry) => self.is_expired(&entry, now),
                Err(_) => true,
            };

            if expired {
                self.db.remove(&k).map_err(|e| AetherError::Storage(e.to_string()))?;
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// 現在の使用量（バイト）
    pub fn size_on_disk(&self) -> Result<u64> {
        self.db.size_on_disk().map_err(|e| AetherError::Storage(e.to_string()))
    }

    /// 保持エントリ数
    pub fn len(&self) -> usize {
        self.db.len()
    }

    pub fn is_empty(&self) -> bool {
        self.db.is_empty()
    }

    // ---- 内部 ----

    fn insert_entry(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let entry = MailboxEntry {
            value: value.to_vec(),
            refreshed_at: current_timestamp(),
        };
        let encoded = bincode::serialize(&entry)
            .map_err(|e| AetherError::Serialization(e.to_string()))?;

        self.db.insert(key, encoded).map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(())
    }

    fn decode_entry(raw: &[u8]) -> Result<MailboxEntry> {
        bincode::deserialize(raw)
            .map_err(|e| AetherError::Storage(format!("Corrupt mailbox entry: {}", e)))
    }

    fn is_expired(&self, entry: &MailboxEntry, now: u64) -> bool {
        now.saturating_sub(entry.refreshed_at) > self.ttl_seconds
    }

    /// 容量上限を超えていたら GC を試み、それでも超えていれば拒否する
    ///
    /// `size_on_disk()` はディレクトリを stat するため、PUT のたびに呼ぶと
    /// 書き込みのホットパスに syscall が乗る。直近の測定値をキャッシュし、
    /// [`SIZE_CACHE_TTL`] 経過するか上限に近づいた時だけ測り直す。
    fn ensure_capacity(&self) -> Result<()> {
        let cached = self.cached_size.load(Ordering::Relaxed);
        let last_check = self.size_checked_at.load(Ordering::Relaxed);
        let now = current_timestamp();

        let stale = now.saturating_sub(last_check) >= SIZE_CACHE_TTL_SECS;
        // 上限の8割を超えていたらキャッシュを信用せず毎回測る
        let near_limit = cached >= self.capacity_bytes / 100 * 80;

        if !stale && !near_limit {
            return Ok(());
        }

        let size = self.size_on_disk()?;
        self.cached_size.store(size, Ordering::Relaxed);
        self.size_checked_at.store(now, Ordering::Relaxed);

        if size < self.capacity_bytes {
            return Ok(());
        }

        self.cleanup_expired()?;

        let size = self.size_on_disk()?;
        self.cached_size.store(size, Ordering::Relaxed);

        if size >= self.capacity_bytes {
            return Err(AetherError::Mailbox("Mailbox capacity exceeded".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_with(ttl_hours: u64) -> (MailboxServer, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = Config { message_ttl_hours: ttl_hours, ..Default::default() };
        let server = MailboxServer::new(dir.path(), &config).unwrap();
        (server, dir)
    }

    fn put_payload(key: u8, value: &[u8]) -> Vec<u8> {
        let mut p = vec![key; 32];
        p.extend_from_slice(value);
        p
    }

    #[tokio::test]
    async fn get_does_not_burn_the_entry() {
        // no-burn（18.3-B）：取得しても消えず、何度でも読める。
        // 公開コンテンツの「1回取得で消える／取りに行くだけで検閲」を防ぐ核。
        let (s, _dir) = server_with(1);
        s.handle_put(&put_payload(1, b"public")).await.unwrap();

        assert_eq!(s.handle_get(&[1u8; 32]).await.unwrap().as_deref(), Some(&b"public"[..]));
        assert_eq!(
            s.handle_get(&[1u8; 32]).await.unwrap().as_deref(),
            Some(&b"public"[..]),
            "no-burn: 2回目も同じ値が読める"
        );
    }

    #[tokio::test]
    async fn access_extends_the_ttl() {
        // アクセス連動 TTL：期限ぎりぎりのエントリを読むと寿命が延びる。
        let (s, _dir) = server_with(24);

        // 作成から 20 時間経過（TTL 24h、半分=12h を超えているのでアクセスで touch される）
        let stale = MailboxEntry {
            value: b"popular".to_vec(),
            refreshed_at: current_timestamp() - 20 * 3600,
        };
        s.db.insert([9u8; 32], bincode::serialize(&stale).unwrap()).unwrap();

        // 読む → まだ生きているので値が返り、refreshed_at が現在時刻に更新される
        assert_eq!(
            s.handle_get(&[9u8; 32]).await.unwrap().as_deref(),
            Some(&b"popular"[..])
        );

        // 更新後は「経過 0 時間」扱いなので、cleanup をかけても消えない
        assert_eq!(s.cleanup_expired().unwrap(), 0, "アクセスで延命されたので消えない");
        assert_eq!(s.len(), 1);
    }

    #[tokio::test]
    async fn oversized_entry_is_rejected() {
        let (s, _dir) = server_with(1);
        let huge = vec![0u8; MAX_ENTRY_BYTES + 1];

        let err = s.handle_put(&put_payload(2, &huge)).await.unwrap_err();
        assert!(matches!(err, AetherError::Mailbox(_)));
        assert!(s.is_empty(), "拒否したエントリが残ってはいけない");
    }

    #[tokio::test]
    async fn expired_entry_is_not_returned() {
        let (s, _dir) = server_with(0);

        // refreshed_at を過去にずらして期限切れを再現
        let entry = MailboxEntry { value: b"old".to_vec(), refreshed_at: current_timestamp() - 10 };
        s.db.insert([3u8; 32], bincode::serialize(&entry).unwrap()).unwrap();

        assert_eq!(s.handle_get(&[3u8; 32]).await.unwrap(), None);
    }

    #[tokio::test]
    async fn cleanup_removes_only_expired() {
        let (s, _dir) = server_with(0);

        let fresh = MailboxEntry { value: b"fresh".to_vec(), refreshed_at: current_timestamp() };
        let stale = MailboxEntry { value: b"stale".to_vec(), refreshed_at: current_timestamp() - 10 };
        s.db.insert([4u8; 32], bincode::serialize(&fresh).unwrap()).unwrap();
        s.db.insert([5u8; 32], bincode::serialize(&stale).unwrap()).unwrap();

        assert_eq!(s.cleanup_expired().unwrap(), 1);
        assert_eq!(s.len(), 1);
    }

    #[tokio::test]
    async fn corrupt_entries_are_swept() {
        let (s, _dir) = server_with(24);
        s.db.insert([6u8; 32], b"not bincode".to_vec()).unwrap();

        assert_eq!(s.cleanup_expired().unwrap(), 1);
        assert!(s.is_empty());
    }

    #[tokio::test]
    async fn tunnel_messages_roundtrip() {
        let (s, _dir) = server_with(24);
        let tid = [7u8; 32];

        s.store_tunnel_message(&tid, b"first").await.unwrap();
        s.store_tunnel_message(&tid, b"second").await.unwrap();

        let msgs = s.fetch_tunnel_messages(&tid).await.unwrap();
        assert_eq!(msgs, vec![b"first".to_vec(), b"second".to_vec()]);
        assert!(s.fetch_tunnel_messages(&tid).await.unwrap().is_empty(), "取得後は消える");
    }
}
