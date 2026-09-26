//! クライアント本体 ── ノードの起動と、送受信の手順が共有する状態

use crate::config::{ClientConfig, NodeMode};
use crate::error::{ClientError, Result};
use crate::events::{self, EventSender};
use crate::keys::KeyFiles;
use aether_core::Config;
use aether_core::crypto::identity::{Identity, NodeId};
use aether_core::net::guard::GuardSet;
use aether_core::node::server::NodeServer;
use aether_core::storage::keystore::KeyStore;
use std::sync::Arc;
use std::time::Duration;

/// 起動直後、種ノードからリレー一覧が届くまで待つ上限
const RELAY_WAIT: Duration = Duration::from_secs(30);

/// AETHER クライアント
///
/// CLI と GUI が共有する。ノードを 1 台立て、その上で送信・検索・取得・受信を行う。
/// **Onion 回路は常に 3 ホップ（固定ガード → 中間 → 出口）**で組み、短い回路へは落とさない。
pub struct AetherClient {
    pub(crate) keys: KeyFiles,
    pub(crate) node: Arc<NodeServer>,
    /// 固定ガード。回路を組むたびに成否を記録して永続化する
    pub(crate) guards: tokio::sync::Mutex<GuardSet>,
    pub(crate) events: EventSender,
    pub(crate) min_relays: usize,
    pub(crate) relay_mode: bool,
    /// 1 プロセス 1 ハンドル（sled の排他ロック）。私信を使うときに開く
    keystore: std::sync::Mutex<Option<Arc<KeyStore>>>,
    /// 書き出し待ちの送信回路（[`AetherClient::flush`] で待つ）
    pub(crate) pending_flush: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// 受信中なら、その購読（友だち追加で増やす）
    pub(crate) receiver: std::sync::Mutex<Option<Arc<crate::receive::Receiver>>>,
}

impl AetherClient {
    /// ノードを起動して網に参加する
    ///
    /// `events` へ進捗を流す。受け手は [`crate::event_channel`] で作ったものを渡す。
    pub async fn start(config: ClientConfig, events: EventSender) -> Result<Arc<Self>> {
        let keys = KeyFiles::new(&config.data_dir, config.passphrase.clone());
        if let Some(w) = keys.plaintext_warning() {
            events::warning(&events, w);
        }
        std::fs::create_dir_all(keys.data_dir())?;

        // ノードの鍵：一回限りなら使い捨て、常駐なら relay.key（どちらも私信の身元ではない）
        let (identity, core_config) = match &config.mode {
            NodeMode::Ephemeral => (
                Identity::generate(),
                Config {
                    listen_port: config.port,
                    node_id_pow_difficulty: 0,
                    advertise_self: false,
                    directory_pow_difficulty: config.network.directory_pow_difficulty,
                    pow_difficulty: config.network.hint_pow_difficulty,
                    ..Default::default()
                },
            ),
            NodeMode::Relay(opts) => {
                let core_config = Config {
                    listen_port: config.port,
                    node_id_pow_difficulty: opts.pow_difficulty,
                    enable_port_mapping: opts.allow_port_mapping,
                    epoch_beacon: opts.epoch_beacon,
                    node_id_pow_nonce: keys.load_relay_pow(),
                    directory_pow_difficulty: config.network.directory_pow_difficulty,
                    pow_difficulty: config.network.hint_pow_difficulty,
                    ..Default::default()
                };
                if opts.pow_difficulty < core_config.directory_pow_difficulty {
                    events::warning(
                        &events,
                        format!(
                            "PoW 難易度 {} は網の要求 ({}) 未満です。他ノードに記述子を弾かれ、リレーとして扱われません",
                            opts.pow_difficulty, core_config.directory_pow_difficulty
                        ),
                    );
                }
                if opts.pow_difficulty > 0 && core_config.node_id_pow_nonce.is_none() {
                    events::progress(
                        &events,
                        format!(
                            "NodeId PoW (難易度 {}) を計算中…（初回だけ。1 分ほどかかることがあります）",
                            opts.pow_difficulty
                        ),
                    );
                }
                (keys.load_or_create_relay_identity()?, core_config)
            }
        };

        // 初回は NodeId PoW を解くので重い（難易度 16 で平均 20 秒、運が悪いと 1 分）。
        // 非同期ランタイムのスレッドを塞がないよう別スレッドで作る
        let mut node = {
            let (port, db, cfg, pass) = (
                config.port,
                keys.mailbox_db_path(),
                core_config.clone(),
                keys.passphrase().map(str::to_owned),
            );
            tokio::task::spawn_blocking(move || {
                NodeServer::with_config_passphrase(port, identity, &db, &cfg, pass.as_deref())
            })
            .await
            .map_err(|e| ClientError::invalid(format!("ノードの起動に失敗しました: {}", e)))??
        };

        // 到達性を確定させる（しないと 127.0.0.1 を広告し続ける）。一回限りは広告しないので不要
        if let NodeMode::Relay(opts) = &config.mode {
            // 解いた PoW を残す（次回の起動は検証だけで済む）
            if keys.load_relay_pow() != Some(node.descriptor.pow_nonce) {
                keys.save_relay_pow(node.descriptor.pow_nonce)?;
            }
            match opts.advertise {
                Some(addr) => {
                    node.declare_reachable(addr).await;
                    events::progress(&events, format!("到達性: 宣言済み {} (Tier 0)", addr));
                }
                None => {
                    events::progress(&events, "到達性を判定中 (STUN / ポートマッピング)...");
                    let r = node.discover_reachability(&core_config).await?;
                    events::progress(
                        &events,
                        format!("到達性: {:?} @ {} ({})", r.tier, r.advertised, r.reason),
                    );
                }
            }
        }

        let node = Arc::new(node);

        // run() が受信ループを立ててから参加要求を出す（応答はこちらが張った接続の上で返る）
        let running = node.clone();
        let running_events = events.clone();
        tokio::spawn(async move {
            if let Err(e) = running.run().await {
                events::warning(&running_events, format!("ノードが停止しました: {}", e));
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        if let Some(seed) = config.seed {
            node.bootstrap(seed).await?;
            events::progress(&events, format!("種ノード {} へ参加要求を送信しました", seed));
        }

        let relay_mode = matches!(config.mode, NodeMode::Relay(_));
        if relay_mode {
            // フィルタ判定はリレーが 2 台以上要るので、収束を待ってから走らせる
            let node = node.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                node.check_filtering_shared().await;
            });
        }

        let guards = GuardSet::load(&keys.guard_path())?;

        Ok(Arc::new(Self {
            keys,
            node,
            guards: tokio::sync::Mutex::new(guards),
            events,
            min_relays: config.min_relays,
            relay_mode,
            keystore: std::sync::Mutex::new(None),
            pending_flush: std::sync::Mutex::new(Vec::new()),
            receiver: std::sync::Mutex::new(None),
        }))
    }

    /// イベントを購読する
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<crate::ClientEvent> {
        self.events.subscribe()
    }

    /// 私信の宛先としての自分の NodeId（identity.key）
    pub fn my_node_id(&self) -> Result<NodeId> {
        Ok(self.keys.load_identity()?.public_id())
    }

    pub fn keys(&self) -> &KeyFiles {
        &self.keys
    }

    /// 下層のノード（診断用）
    pub fn node(&self) -> &Arc<NodeServer> {
        &self.node
    }

    /// 現在の状態
    pub async fn status(&self) -> Status {
        Status {
            known_relays: self.node.directory_size().await,
            stored_entries: self.node.mailbox().len(),
            relay_mode: self.relay_mode,
        }
    }

    /// 既知リレーが `min_relays` を超えるまで待つ
    pub async fn wait_for_relays(&self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + RELAY_WAIT;
        while self.node.directory_size().await <= self.min_relays {
            if tokio::time::Instant::now() > deadline {
                return Err(ClientError::network(format!(
                    "リレーが {} 台見つかりませんでした（現在 {} 台）",
                    self.min_relays,
                    self.node.directory_size().await
                )));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Ok(())
    }

    /// KeyStore を開く（初回だけ。以後は同じハンドルを共有）
    pub(crate) fn keystore(&self) -> Result<Arc<KeyStore>> {
        let mut slot = self.keystore.lock().unwrap();
        if let Some(ks) = slot.as_ref() {
            return Ok(ks.clone());
        }
        let ks = Arc::new(self.keys.open_keystore()?);
        *slot = Some(ks.clone());
        Ok(ks)
    }

    /// X3DH のプレキーを用意する（無ければ生成して永続化）
    ///
    /// 受信・公開タスクより**先に**呼ぶこと。未生成を掴むと初回接触に応答できない。
    pub(crate) fn ensure_prekeys(&self) -> Result<()> {
        let ks = self.keystore()?;
        if ks.load_prekeys()?.is_none() {
            let id = self.keys.load_identity()?;
            let (bundle, secrets) = aether_core::crypto::x3dh::generate_prekeys(&id, false);
            ks.save_prekeys(&bundle, &secrets)?;
            events::progress(&self.events, "X3DH プレキーを生成しました（初回接触を受信できます）");
        }
        Ok(())
    }
}

/// クライアントの状態
#[derive(Debug, Clone, serde::Serialize)]
pub struct Status {
    pub known_relays: usize,
    pub stored_entries: usize,
    pub relay_mode: bool,
}

/// 板の鍵から contacts マップ用の合成 NodeId を作る
///
/// 公開の書き込みには特定の宛先が無い。板の鍵をローカルの contacts マップに
/// 収めるための安定した鍵として、鍵のハッシュを NodeId 代わりに使う。
pub(crate) fn board_target(k_pub: &[u8; 32]) -> NodeId {
    NodeId(aether_core::crypto::keyword::subscription_id(k_pub))
}
