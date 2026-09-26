//! クライアントの起動設定

use std::net::SocketAddr;
use std::path::PathBuf;

/// クライアントの起動設定
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// データディレクトリ（鍵・Mailbox・ガード情報）
    pub data_dir: PathBuf,
    /// 保存時暗号化のパスフレーズ。`None` は平文（押収に弱い）
    ///
    /// identity.key・relay.key・keystore.db・mailbox.db をまとめて解錠する。
    pub passphrase: Option<String>,
    /// 待ち受けポート（0 = OS 任せ）
    pub port: u16,
    /// 種ノード
    pub seed: Option<SocketAddr>,
    /// 回路を組む前に待つ既知リレー数の下限
    pub min_relays: usize,
    pub mode: NodeMode,
    /// 網全体で揃える値。**既定値のまま使うこと**（テスト網だけが下げる）
    pub network: NetworkParams,
}

/// 網全体で揃える値
///
/// 1 台だけ変えると他ノードと話が合わなくなる（記述子を弾かれる・Hint を捨てられる）。
#[derive(Debug, Clone)]
pub struct NetworkParams {
    /// 受け取った記述子に要求する NodeId PoW 難易度
    pub directory_pow_difficulty: u32,
    /// Hint に要求する PoW 難易度
    pub hint_pow_difficulty: u8,
}

impl Default for NetworkParams {
    fn default() -> Self {
        let c = aether_core::Config::default();
        Self {
            directory_pow_difficulty: c.directory_pow_difficulty,
            hint_pow_difficulty: c.pow_difficulty,
        }
    }
}

/// ノードの振る舞い
#[derive(Debug, Clone)]
pub enum NodeMode {
    /// 一回限りのクライアント（送信・検索・取得だけ）
    ///
    /// ノードの鍵は起動のたびに使い捨て、PoW も解かない。他ノードの検証で弾かれるので
    /// 網には広まらず、NodeId と IP の対応も残らない。**受信はできない**
    /// （Hint はディレクトリ上のリレーにしか流れない）。
    Ephemeral,
    /// 常駐リレー。受信（Hint の購読）もできる
    ///
    /// ノードの鍵は relay.key（私信の身元とは別）。記述子は網全体へ配られる。
    Relay(RelayOptions),
}

#[derive(Debug, Clone)]
pub struct RelayOptions {
    /// 到達可能と宣言するアドレス。`None` なら STUN で判定する
    pub advertise: Option<SocketAddr>,
    /// ルータへのポートマッピング要求を許可する（リース表に痕跡が残る）
    pub allow_port_mapping: bool,
    /// NodeId の PoW 難易度。網の要求値未満だと他ノードに弾かれる
    pub pow_difficulty: u32,
    /// エポックビーコン（網全体で揃える）
    pub epoch_beacon: bool,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            advertise: None,
            allow_port_mapping: false,
            pow_difficulty: aether_core::crypto::pow::node_id::DEFAULT_DIFFICULTY,
            epoch_beacon: false,
        }
    }
}
