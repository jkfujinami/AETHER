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
    /// 匿名性のための遅延の切り替え
    pub(crate) privacy: crate::config::PrivacyOptions,
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

        // 常駐ノードは、前回とネットワーク（IP）が変わっていたら鍵・ポートを作り直して立て直す。
        // 立て直しは 1 回まで（2 回目は判定を記録するだけ）
        let mut rotated = false;
        let node = loop {
            // 待ち受けポート。常駐で指定が無ければ、初回にランダムに選んで以後は使い続ける
            let port = match (&config.mode, config.port) {
                (NodeMode::Relay(_), 0) => relay_port(&keys)?,
                (_, p) => p,
            };

            // ノードの鍵：一回限りなら使い捨て、常駐なら relay.key（どちらも私信の身元ではない）
            let (identity, core_config) = match &config.mode {
                NodeMode::Ephemeral => (
                    Identity::generate(),
                    Config {
                        listen_port: port,
                        node_id_pow_difficulty: 0,
                        advertise_self: false,
                        directory_pow_difficulty: config.network.directory_pow_difficulty,
                        pow_difficulty: config.network.hint_pow_difficulty,
                        ..Default::default()
                    },
                ),
                NodeMode::Relay(opts) => {
                    let core_config = Config {
                        listen_port: port,
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
                    port,
                    keys.mailbox_db_path(),
                    core_config.clone(),
                    keys.passphrase().map(str::to_owned),
                );
                // 立て直しの直後は、前のノードの DB ロックが解けるまで少し待つことがある
                let attempts = if rotated { 20 } else { 1 };
                let mut tried = 0;
                loop {
                    tried += 1;
                    let (db, cfg, pass): (std::path::PathBuf, Config, Option<String>) =
                        (db.clone(), cfg.clone(), pass.clone());
                    // DB を開けずに失敗したときは PoW を解く前に返る（Mailbox を先に開く）ので、
                    // 再試行しても PoW を解き直さない
                    let identity = Identity::from_bytes(&identity.to_bytes())?;
                    let built = tokio::task::spawn_blocking(move || {
                        NodeServer::with_config_passphrase(port, identity, &db, &cfg, pass.as_deref())
                    })
                    .await
                    .map_err(|e| ClientError::invalid(format!("ノードの起動に失敗しました: {}", e)))?;
                    match built {
                        Ok(n) => break n,
                        Err(_) if tried < attempts => tokio::time::sleep(Duration::from_millis(100)).await,
                        Err(e) => return Err(e.into()),
                    }
                }
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

            if let NodeMode::Relay(_) = &config.mode {
                let current = network_key(node.descriptor.addr);
                let previous = keys
                    .read_secure(&keys.relay_net_path())?
                    .and_then(|b| String::from_utf8(b).ok());
                if let (Some(cur), Some(prev)) = (&current, &previous)
                    && cur != prev
                    && !rotated
                {
                    events::progress(
                        &events,
                        "ネットワークが変わったので、リレーの鍵と待ち受けポートを作り直します（前の場所と結びつけられないように）",
                    );
                    drop(node);
                    keys.discard_relay_identity()?;
                    keys.write_secure(&keys.relay_net_path(), cur.as_bytes())?;
                    rotated = true;
                    continue;
                }
                if let Some(cur) = &current
                    && previous.as_ref() != Some(cur)
                {
                    keys.write_secure(&keys.relay_net_path(), cur.as_bytes())?;
                }
            }
            break node;
        };

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
            privacy: config.privacy.clone(),
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

/// 鍵を作り直す単位の「ネットワーク」（IPv4 はアドレス、IPv6 は /64）
///
/// **常駐ノードの NodeId とポートは公開のリレー一覧に載る。** 同じ鍵のまま IP だけが
/// 変わると、一覧を見るだけで「自宅 → 職場 → 外出先」を同じ人として追える
/// （受信するには常駐が必要なので、受信者は必ず一覧に載る）。IP が変わったら鍵と
/// ポートを作り直し、前の場所と結びつけられないようにする。
///
/// IPv6 は一時アドレスが日に何度も変わるので /64（回線単位）で比べる。
/// ループバック・未指定（ローカルの試験網）は `None`（作り直さない）。
fn network_key(addr: std::net::SocketAddr) -> Option<String> {
    use std::net::IpAddr;
    match aether_core::net::addr::normalize(addr).ip() {
        ip if ip.is_loopback() || ip.is_unspecified() => None,
        IpAddr::V4(v4) => Some(v4.to_string()),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            Some(format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3]))
        }
    }
}

/// 常駐ノードの待ち受けポート（初回にランダムに選んで保存する）
///
/// **固定の既定ポート（旧 9000）は使わない。** 全員が同じポートで待ち受けると、
/// ポート番号だけで AETHER の利用者を一覧化できる。一方で毎回変えると
/// 記述子のアドレスが変わり続け、他人のガードとして使い続けてもらえない。
fn relay_port(keys: &KeyFiles) -> Result<u16> {
    let path = keys.relay_port_path();
    if let Some(p) = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .filter(|p| *p != 0)
    {
        return Ok(p);
    }
    // 動的・私用ポートの範囲から選ぶ（よく使われるサービスのポートと重ならない）
    let port = 49152 + rand::random::<u16>() % (65535 - 49152);
    std::fs::write(&path, port.to_string())?;
    Ok(port)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_key_compares_ipv6_by_prefix_and_skips_loopback() {
        let a = network_key("[2001:db8:1:2:aaaa::1]:5000".parse().unwrap());
        let b = network_key("[2001:db8:1:2:bbbb::9]:6000".parse().unwrap());
        assert_eq!(a, b, "同じ /64 の一時アドレスは同じネットワーク");
        assert_ne!(a, network_key("[2001:db8:1:3::1]:5000".parse().unwrap()));
        assert_eq!(network_key("203.0.113.5:1".parse().unwrap()).as_deref(), Some("203.0.113.5"));
        assert_eq!(network_key("[::ffff:203.0.113.5]:1".parse().unwrap()).as_deref(), Some("203.0.113.5"));
        assert!(network_key("127.0.0.1:1".parse().unwrap()).is_none());
    }

    #[test]
    fn relay_port_is_random_once_then_stable() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        let first = relay_port(&keys).unwrap();
        assert!(first >= 49152, "動的ポートの範囲外: {}", first);
        assert_eq!(relay_port(&keys).unwrap(), first, "起動のたびに変わるとガードに使われない");
    }
}
