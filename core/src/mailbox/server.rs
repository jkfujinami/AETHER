use crate::error::{Result, AetherError};
use crate::protocol::hint::current_timestamp;
use crate::storage::at_rest;
use serde::{Serialize, Deserialize};
use sled::Db;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::Config;
use crate::mailbox::index::IndexRecord;

/// 暗号鍵から sled キー用の HMAC 鍵を導く（暗号鍵そのものは使い回さない）
fn derive_blind_key(cipher_key: &[u8; 32]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, cipher_key);
    let mut out = [0u8; 32];
    hk.expand(b"aether_mailbox_blind_v1", &mut out)
        .expect("32 バイトは HKDF の上限内");
    out
}

/// 1エントリの最大サイズ (1MB)
pub const MAX_ENTRY_BYTES: usize = 1024 * 1024;

/// Tunnel 用エントリのキー接頭辞
const TUNNEL_PREFIX: &[u8] = b"tunnel:";

/// 索引エントリのキー接頭辞（19.7 / Phase 2-3）
const INDEX_PREFIX: &[u8] = b"index:";

/// 保存時暗号化のメタツリー・カナリア（KeyStore とは別の値 / 3-1）
const META_TREE: &str = "aether_mailbox_meta";
const CANARY_PLAINTEXT: &[u8] = b"aether-mailbox-canary-v1";

/// 1索引につき返す記述子の上限（増幅・肥大対策。19.7）
pub const MAX_INDEX_ENTRIES: usize = 256;

/// 索引の記述子 1 件の上限（名前・親の一覧が入っても十分な大きさ）
pub const MAX_INDEX_RECORD_BYTES: usize = 8 * 1024;

/// 索引の一覧の返信に載せるバイト数の上限（トンネルのパケット上限より十分小さく）
pub const MAX_INDEX_REPLY_BYTES: usize = 512 * 1024;

/// 1 つの索引に保持する記述子の上限。超えたら PoW の弱いものから入れ替える
pub const MAX_STORED_PER_INDEX: usize = 4096;

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
    /// 保存時暗号化の鍵（`Some` なら値を暗号化して保存する / 押収対策・3-1）
    cipher_key: Option<[u8; 32]>,
    /// sled のキーを隠す HMAC 鍵（保存時暗号化のときだけ。[`Self::blind`]）
    blind_key: Option<[u8; 32]>,
    /// 索引の記述子に要求する PoW 難易度（Hint と同じ SHA-256 PoW）
    pow_difficulty: u32,
    /// トンネル本文のキーに付ける連番（到着順を保つ。時刻は入れない）
    tunnel_seq: AtomicU64,
}

impl MailboxServer {
    /// 平文で開く（テスト・暗号化しない場合）
    pub fn new(path: &Path, config: &Config) -> Result<Self> {
        Self::open(path, config, None)
    }

    /// パスフレーズで**保存時暗号化**して開く（押収対策 / 3-1）
    ///
    /// 保持する Mailbox エントリ（送信者が既に封じたシャード・索引・トンネル本文）を
    /// さらにローカル鍵で暗号化する。押収されてもパスフレーズ無しには読めない。
    ///
    /// **注意:** 既存の**平文** Mailbox をこのモードで開くと、古いエントリは復号できず
    /// GC で掃除される。Mailbox はキャッシュ相当なので実害は小さいが、in-place 移行は非対応。
    pub fn new_encrypted(path: &Path, config: &Config, passphrase: &str) -> Result<Self> {
        let db = sled::open(path).map_err(|e| AetherError::Storage(e.to_string()))?;
        let key = at_rest::unlock_db(&db, passphrase, META_TREE, CANARY_PLAINTEXT)?;
        Self::from_db(db, config, Some(key))
    }

    fn open(path: &Path, config: &Config, cipher_key: Option<[u8; 32]>) -> Result<Self> {
        let db = sled::open(path).map_err(|e| AetherError::Storage(e.to_string()))?;
        Self::from_db(db, config, cipher_key)
    }

    fn from_db(db: Db, config: &Config, cipher_key: Option<[u8; 32]>) -> Result<Self> {
        Ok(Self {
            db,
            ttl_seconds: config.message_ttl_hours * 3600,
            capacity_bytes: config.mailbox_capacity_mb * 1024 * 1024,
            cached_size: AtomicU64::new(0),
            size_checked_at: AtomicU64::new(0),
            blind_key: cipher_key.map(|k| derive_blind_key(&k)),
            cipher_key,
            pow_difficulty: u32::from(config.pow_difficulty),
            tunnel_seq: AtomicU64::new(0),
        })
    }

    /// 保存時暗号化が有効か
    pub fn is_encrypted(&self) -> bool {
        self.cipher_key.is_some()
    }

    /// Payload: [Key(32)][Value(...)]
    ///
    /// **先に置かれた値を上書きしない（first-write-wins）。** 同じ値の再 PUT
    /// （ダウンローダの再シード・投稿者の置き直し）は寿命を延ばすだけ。
    ///
    /// 上書きを許すと、置き場所を計算できる者（公開コンテンツなら板の読者全員）が
    /// 中身を差し替え・消去できる。私信の置き場所は送受信者しか知らないので影響しない。
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

        let slot = self.blind(b"mbx", key);
        if let Some(existing) = self.live_entry(&slot)? {
            if existing.value != value {
                return Err(AetherError::Mailbox(
                    "Entry already holds a different value; not overwriting".into(),
                ));
            }
            return self.insert_entry(&slot, value);
        }

        self.ensure_capacity(value.len())?;
        self.insert_entry(&slot, value)
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
        let slot = self.blind(b"mbx", &payload[0..32]);

        let Some(entry) = self.live_entry(&slot)? else {
            return Ok(None);
        };

        // アクセスで寿命を延ばす。ただし毎読み込みで書き戻すと書き込み増幅になるため、
        // TTL の半分を過ぎた時だけ触り直す（読み頻度に依らず書き込みは TTL/2 に1回）。
        if current_timestamp().saturating_sub(entry.refreshed_at) >= self.ttl_seconds / 2 {
            self.insert_entry(&slot, &entry.value)?;
        }

        Ok(Some(entry.value))
    }

    /// Tunnel 用: `tunnel:{tunnel_id}:{連番}` -> Data
    ///
    /// 連番は到着順を保つだけのもので、時刻は入れない（押収時に受信時刻が残らないように）。
    pub async fn store_tunnel_message(&self, tunnel_id: &[u8; 32], data: &[u8]) -> Result<()> {
        if data.len() > MAX_ENTRY_BYTES {
            return Err(AetherError::Mailbox(format!(
                "Tunnel message too large: {} bytes (max {})",
                data.len(),
                MAX_ENTRY_BYTES
            )));
        }

        self.ensure_capacity(data.len())?;

        let seq = self.tunnel_seq.fetch_add(1, Ordering::Relaxed);
        let mut key = self.tunnel_prefix(tunnel_id);
        key.extend_from_slice(&seq.to_be_bytes());

        self.insert_entry(&key, data)
    }

    /// 指定した tunnel_id 宛のメッセージを全て取得し、削除して返す
    pub async fn fetch_tunnel_messages(&self, tunnel_id: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
        let prefix = self.tunnel_prefix(tunnel_id);
        let now = current_timestamp();
        let mut messages = Vec::new();

        for item in self.db.scan_prefix(&prefix) {
            let (k, v) = item.map_err(|e| AetherError::Storage(e.to_string()))?;
            self.db.remove(&k).map_err(|e| AetherError::Storage(e.to_string()))?;

            // 壊れた 1 件で残りを取りこぼさない
            let Ok(entry) = self.decode_entry(&v) else { continue };
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
    ///
    /// 保持者がここで確かめること（確かめないと、読者の誰でも板を検閲できた）:
    /// - `record_id` が本当にその記述子の ID か（違えば他人の書き込みを ID 指定で上書きできた）
    /// - PoW を満たすか（クライアントだけが確かめていた）
    /// - 大きさが [`MAX_INDEX_RECORD_BYTES`] 以下か（1MB の記述子を数件置くと、一覧の返信が
    ///   パケットの上限を超えて誰も索引を引けなくなった）
    ///
    /// 1 つの索引が [`MAX_STORED_PER_INDEX`] 件に達したら、PoW が最も弱い（同じなら最も
    /// 古い）記述子と入れ替える。新しい記述子の方が弱ければ受け付けない。
    pub async fn handle_index_put(&self, payload: &[u8]) -> Result<()> {
        // payload: [index_key(32)][record_id(32)][record...]
        if payload.len() < 64 {
            return Err(AetherError::Protocol("IndexPut payload too short".into()));
        }
        let index_key: &[u8; 32] = payload[0..32].try_into().expect("長さ確認済み");
        let record_id: &[u8; 32] = payload[32..64].try_into().expect("長さ確認済み");
        let record = &payload[64..];
        if record.len() > MAX_INDEX_RECORD_BYTES {
            return Err(AetherError::Mailbox("Index record too large".into()));
        }

        let parsed = IndexRecord::decode(record)?;
        if parsed.id() != *record_id {
            return Err(AetherError::Protocol("IndexPut record_id does not match the record".into()));
        }
        if !parsed.verify_pow(self.pow_difficulty) {
            return Err(AetherError::Protocol("IndexPut record fails PoW".into()));
        }

        let slot = self.index_slot(index_key, record_id);
        if self.live_entry(&slot)?.is_some() {
            // 同じ ID ＝同じ中身。寿命を延ばすだけ
            return self.insert_entry(&slot, record);
        }

        // 満杯なら最も弱い記述子と入れ替える
        let stored = self.index_entries(index_key)?;
        if stored.len() >= MAX_STORED_PER_INDEX
            && let Some(weakest) = stored.iter().min_by_key(|e| (e.pow_bits, e.refreshed_at))
        {
            if parsed.pow_bits() <= weakest.pow_bits {
                return Err(AetherError::Mailbox("Index is full of stronger records".into()));
            }
            self.db
                .remove(&weakest.key)
                .map_err(|e| AetherError::Storage(e.to_string()))?;
        }

        self.ensure_capacity(record.len())?;
        self.insert_entry(&slot, record)
    }

    /// 索引の記述子を列挙する（19.7 / Phase 2-3）
    ///
    /// **削除しない（no-burn）。** 期限切れは除外し、PoW の強い順（同じなら新しい順）に、
    /// 件数 [`MAX_INDEX_ENTRIES`] とバイト数 [`MAX_INDEX_REPLY_BYTES`] の上限まで返す。
    ///
    /// 以前はキーの辞書順で先頭から返していたので、`0x00…` で始まる ID の記述子を
    /// 256 件置くだけで、ほかの書き込みをすべて一覧から追い出せた。強い順にすると、
    /// 追い出すには正規の書き込みより強い PoW を件数ぶん払う必要がある。
    ///
    /// アクセスで生きているエントリの寿命を延ばす（人気な索引は残る）。
    pub async fn handle_index_list(&self, index_key: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
        let mut entries = self.index_entries(index_key)?;
        entries.sort_by(|a, b| {
            b.pow_bits
                .cmp(&a.pow_bits)
                .then(b.refreshed_at.cmp(&a.refreshed_at))
        });

        let now = current_timestamp();
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for e in entries {
            if out.len() >= MAX_INDEX_ENTRIES || bytes + e.value.len() > MAX_INDEX_REPLY_BYTES {
                break;
            }
            // アクセスで延命（no-burn + アクセス連動 TTL）
            if now.saturating_sub(e.refreshed_at) >= self.ttl_seconds / 2 {
                let _ = self.insert_entry(&e.key, &e.value);
            }
            bytes += e.value.len();
            out.push(e.value);
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
            let expired = match self.decode_entry(&v) {
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

    /// sled に置くキー
    ///
    /// 保存時暗号化が有効なら `HMAC(blind_key, 用途 ‖ ID)` にする。値を暗号化しても
    /// **キーは平文でディスクに残る**ので、そのままだと押収したディスクと既知ファイルの
    /// シャード鍵を突き合わせて「このノードは既知のファイル X を保持していた」を
    /// パスフレーズ無しに示せた（公開コンテンツは収束暗号で、板の鍵も公開されている）。
    /// 平文モードは押収に耐えない前提なので、そのまま使う。
    fn blind(&self, domain: &[u8], id: &[u8]) -> Vec<u8> {
        match &self.blind_key {
            Some(k) => {
                use hmac::{Hmac, Mac};
                let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(k)
                    .expect("HMAC は任意長の鍵を取れる");
                mac.update(domain);
                mac.update(id);
                mac.finalize().into_bytes().to_vec()
            }
            None => id.to_vec(),
        }
    }

    fn tunnel_prefix(&self, tunnel_id: &[u8; 32]) -> Vec<u8> {
        let mut key = TUNNEL_PREFIX.to_vec();
        key.extend_from_slice(&self.blind(b"tun", tunnel_id));
        key
    }

    fn index_prefix(&self, index_key: &[u8; 32]) -> Vec<u8> {
        let mut key = INDEX_PREFIX.to_vec();
        key.extend_from_slice(&self.blind(b"idx", index_key));
        key
    }

    fn index_slot(&self, index_key: &[u8; 32], record_id: &[u8; 32]) -> Vec<u8> {
        let mut key = self.index_prefix(index_key);
        key.extend_from_slice(&self.blind(b"rec", record_id));
        key
    }

    /// 1 つの索引の生きている記述子（期限切れ・壊れたものは除く）
    fn index_entries(&self, index_key: &[u8; 32]) -> Result<Vec<IndexEntry>> {
        let now = current_timestamp();
        let mut out = Vec::new();
        for item in self.db.scan_prefix(self.index_prefix(index_key)) {
            let (k, v) = item.map_err(|e| AetherError::Storage(e.to_string()))?;
            let Ok(entry) = self.decode_entry(&v) else { continue };
            if self.is_expired(&entry, now) {
                continue;
            }
            let Ok(record) = IndexRecord::decode(&entry.value) else { continue };
            out.push(IndexEntry {
                key: k.to_vec(),
                pow_bits: record.pow_bits(),
                refreshed_at: entry.refreshed_at,
                value: entry.value,
            });
        }
        Ok(out)
    }

    /// 生きているエントリを読む。期限切れならその場で消して `None`
    fn live_entry(&self, key: &[u8]) -> Result<Option<MailboxEntry>> {
        let Some(raw) = self.db.get(key).map_err(|e| AetherError::Storage(e.to_string()))? else {
            return Ok(None);
        };
        let entry = match self.decode_entry(&raw) {
            Ok(e) => e,
            Err(_) => {
                let _ = self.db.remove(key);
                return Ok(None);
            }
        };
        if self.is_expired(&entry, current_timestamp()) {
            // 死んでいるエントリは読んだついでに掃除する（no-burn は生きた値だけ）
            let _ = self.db.remove(key);
            return Ok(None);
        }
        Ok(Some(entry))
    }

    fn insert_entry(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let entry = MailboxEntry {
            value: value.to_vec(),
            refreshed_at: current_timestamp(),
        };
        let encoded = bincode::serialize(&entry)
            .map_err(|e| AetherError::Serialization(e.to_string()))?;

        // 保存時暗号化が有効なら値ごと暗号化してから置く（押収対策 / 3-1）
        let stored = match &self.cipher_key {
            Some(k) => at_rest::encrypt_value(k, &encoded)?,
            None => encoded,
        };

        let grew = (key.len() + stored.len()) as u64;
        self.db.insert(key, stored).map_err(|e| AetherError::Storage(e.to_string()))?;
        self.cached_size.fetch_add(grew, Ordering::Relaxed);
        Ok(())
    }

    fn decode_entry(&self, raw: &[u8]) -> Result<MailboxEntry> {
        // 暗号化が有効なら先に復号する。正しい鍵は open 時にカナリアで検証済みなので、
        // ここで復号に失敗するのは壊れたエントリ（＝ cleanup 対象）だけ。
        let plain = match &self.cipher_key {
            Some(k) => at_rest::decrypt_value(k, raw)?,
            None => raw.to_vec(),
        };
        bincode::deserialize(&plain)
            .map_err(|e| AetherError::Storage(format!("Corrupt mailbox entry: {}", e)))
    }

    fn is_expired(&self, entry: &MailboxEntry, now: u64) -> bool {
        now.saturating_sub(entry.refreshed_at) > self.ttl_seconds
    }

    /// 保存しているキーと値の合計バイト数（論理サイズ）
    ///
    /// `size_on_disk()` は sled が領域を回収するまで減らないので、容量の判断には使わない
    /// （追い出しても減らず、追い出し続けて全部消してしまう）。
    fn logical_size(&self) -> Result<u64> {
        let mut total = 0u64;
        for item in self.db.iter() {
            let (k, v) = item.map_err(|e| AetherError::Storage(e.to_string()))?;
            total += (k.len() + v.len()) as u64;
        }
        Ok(total)
    }

    /// `incoming` バイトを置く余地を作る
    ///
    /// 上限を超えそうなら、まず期限切れを掃除し、それでも足りなければ
    /// **最後に触られたのが最も古いエントリから追い出す**（上限の 8 割まで）。
    ///
    /// 以前は上限に達すると新しい PUT を拒否していた。PUT には認証も PoW も無いので、
    /// 攻撃者 1 人がゴミで上限まで埋めるだけで、網全体の新しい保存が止まった。
    /// 追い出し方式なら網は動き続け、取得され続けている（＝寿命が延び続けている）
    /// コンテンツほど残る。ゴミで埋めて正規のものを押し出す攻撃は残るので、
    /// その費用を上げるのは別の課題（送信元ごとの流量制限など）。
    ///
    /// 論理サイズはここで数え直す（[`SIZE_CACHE_TTL_SECS`] ごと）。間は書き込みのたびに
    /// 概算で足し上げる。
    fn ensure_capacity(&self, incoming: usize) -> Result<()> {
        let now = current_timestamp();
        let last_check = self.size_checked_at.load(Ordering::Relaxed);
        if now.saturating_sub(last_check) >= SIZE_CACHE_TTL_SECS {
            self.cached_size.store(self.logical_size()?, Ordering::Relaxed);
            self.size_checked_at.store(now, Ordering::Relaxed);
        }

        if self.cached_size.load(Ordering::Relaxed) + incoming as u64 <= self.capacity_bytes {
            return Ok(());
        }

        self.cleanup_expired()?;
        let mut size = self.logical_size()?;
        let target = self.capacity_bytes / 100 * 80;
        if size + incoming as u64 > self.capacity_bytes {
            let mut entries: Vec<(u64, Vec<u8>, u64)> = Vec::new();
            for item in self.db.iter() {
                let (k, v) = item.map_err(|e| AetherError::Storage(e.to_string()))?;
                let refreshed = self.decode_entry(&v).map(|e| e.refreshed_at).unwrap_or(0);
                entries.push((refreshed, k.to_vec(), (k.len() + v.len()) as u64));
            }
            entries.sort_by_key(|e| e.0);
            for (_, key, bytes) in entries {
                if size + incoming as u64 <= target {
                    break;
                }
                self.db.remove(&key).map_err(|e| AetherError::Storage(e.to_string()))?;
                size = size.saturating_sub(bytes);
            }
        }
        self.cached_size.store(size, Ordering::Relaxed);
        self.size_checked_at.store(now, Ordering::Relaxed);

        if size + incoming as u64 > self.capacity_bytes {
            return Err(AetherError::Mailbox("Mailbox capacity exceeded".into()));
        }
        Ok(())
    }
}

/// 索引の記述子 1 件（並べ替え・入れ替えの判断用）
struct IndexEntry {
    key: Vec<u8>,
    pow_bits: u32,
    refreshed_at: u64,
    value: Vec<u8>,
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
    async fn encrypted_mailbox_hides_values_on_disk_but_serves_them() {
        // 保存時暗号化：ディスク上の値は暗号文だが、開けば正しく取り出せる（押収対策 / 3-1）
        let dir = tempfile::tempdir().unwrap();
        let config = Config { message_ttl_hours: 24, ..Default::default() };

        {
            let s = MailboxServer::new_encrypted(dir.path(), &config, "correct horse").unwrap();
            assert!(s.is_encrypted());
            s.handle_put(&put_payload(1, b"a-secret-shard")).await.unwrap();

            // no-burn で読める
            assert_eq!(
                s.handle_get(&[1u8; 32]).await.unwrap().as_deref(),
                Some(&b"a-secret-shard"[..])
            );
        }

        // 生の sled を直接覗くと、平文のシャードは現れない（暗号化されている）
        {
            let raw = sled::open(dir.path()).unwrap();
            assert!(raw.get([1u8; 32]).unwrap().is_none(), "キーが平文で残ってはいけない");
            let (_, stored) = raw.iter().next().unwrap().unwrap();
            assert!(
                !stored.windows(14).any(|w| w == b"a-secret-shard"),
                "値が平文で残ってはいけない"
            );
        }

        // 同じパスフレーズで開き直せば読める
        let s = MailboxServer::new_encrypted(dir.path(), &config, "correct horse").unwrap();
        assert_eq!(
            s.handle_get(&[1u8; 32]).await.unwrap().as_deref(),
            Some(&b"a-secret-shard"[..])
        );

        // 誤ったパスフレーズは弾く（カナリア）
        assert!(MailboxServer::new_encrypted(dir.path(), &config, "wrong").is_err());
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

    #[tokio::test]
    async fn put_does_not_overwrite_a_different_value() {
        let (s, _dir) = server_with(24);
        s.handle_put(&put_payload(1, b"original")).await.unwrap();
        assert!(s.handle_put(&put_payload(1, b"forged")).await.is_err());
        s.handle_put(&put_payload(1, b"original")).await.unwrap();
        assert_eq!(s.handle_get(&[1u8; 32]).await.unwrap().as_deref(), Some(&b"original"[..]));
    }

    fn index_put(index_key: [u8; 32], rec: &IndexRecord) -> Vec<u8> {
        let mut p = index_key.to_vec();
        p.extend_from_slice(&rec.id());
        p.extend_from_slice(&rec.encode().unwrap());
        p
    }

    fn record(name: &str, pow: u32) -> IndexRecord {
        let d = crate::mailbox::index::IndexDescriptor {
            content_ref: [0; 32],
            name: name.into(),
            size: 1,
            timestamp: 0,
            chunked: false,
            parents: Vec::new(),
        };
        IndexRecord::create(&[5; 32], &d, pow).unwrap()
    }

    #[tokio::test]
    async fn index_put_rejects_a_mismatched_record_id() {
        let (s, _dir) = server_with(24);
        let legit = record("legit", 10);
        let forged = record("forged", 10);
        // 正規の ID を名乗って別の中身を置く
        let mut p = [9u8; 32].to_vec();
        p.extend_from_slice(&legit.id());
        p.extend_from_slice(&forged.encode().unwrap());
        assert!(s.handle_index_put(&p).await.is_err());
        // PoW を満たさない記述子も弾く
        assert!(s.handle_index_put(&index_put([9; 32], &record("lazy", 0))).await.is_err() || record("lazy", 0).pow_bits() >= 10);

        s.handle_index_put(&index_put([9; 32], &legit)).await.unwrap();
        assert_eq!(s.handle_index_list(&[9; 32]).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn index_put_rejects_oversized_records() {
        let (s, _dir) = server_with(24);
        let big = record(&"x".repeat(MAX_INDEX_RECORD_BYTES), 0);
        assert!(s.handle_index_put(&index_put([9; 32], &big)).await.is_err());
    }

    #[tokio::test]
    async fn index_list_puts_stronger_pow_first() {
        let (s, _dir) = server_with(24);
        let weak = record("weak", 10);
        let strong = record("strong", 14);
        s.handle_index_put(&index_put([9; 32], &weak)).await.unwrap();
        s.handle_index_put(&index_put([9; 32], &strong)).await.unwrap();
        let listed = s.handle_index_list(&[9; 32]).await.unwrap();
        assert_eq!(IndexRecord::decode(&listed[0]).unwrap(), strong);
    }

    #[tokio::test]
    async fn full_mailbox_evicts_the_oldest_instead_of_refusing() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config { message_ttl_hours: 24, mailbox_capacity_mb: 1, ..Default::default() };
        let s = MailboxServer::new(dir.path(), &config).unwrap();

        let old = MailboxEntry { value: vec![1; 600 * 1024], refreshed_at: current_timestamp() - 100 };
        s.db.insert([1u8; 32], bincode::serialize(&old).unwrap()).unwrap();

        s.handle_put(&put_payload(2, &vec![2; 600 * 1024])).await.unwrap();
        assert!(s.handle_get(&[1u8; 32]).await.unwrap().is_none(), "古いものから追い出す");
        assert!(s.handle_get(&[2u8; 32]).await.unwrap().is_some());
    }
}
