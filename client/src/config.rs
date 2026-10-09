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
    /// 匿名性のために入れる遅延の切り替え（使いやすさとの兼ね合い）
    pub privacy: PrivacyOptions,
}

/// 匿名性のために入れる遅延の切り替え
///
/// どれも「いつ」を観測者から隠すための遅延で、切ると速くなる代わりに守りが弱まる。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct PrivacyOptions {
    /// 自分宛ての Hint を見つけてから本体を取りに行くまで 0〜60 秒ずらす（既定: 有効）
    ///
    /// 切るとすぐ届く。代わりに、Hint を放流した送信者（や送信者と組んだ者）が
    /// 「放流の直後に取得が出たか」をガードや回線の照会と突き合わせて、受信者を
    /// 特定しやすくなる。
    pub delay_fetch: bool,
    /// 本体を置いてから Hint を放流するまで、網の Hint の流量に応じて遅らせる（既定: 有効）
    ///
    /// 大きな本体ほど長く待つ（最大 6 時間）。切るとすぐ放流する。代わりに、
    /// 「大きな送信の直後に Hint が出た」ことから送信と Hint を結びつけやすくなる。
    pub delay_release: bool,
    /// トーク（私信）の履歴を端末に保存する（既定: 有効）
    ///
    /// 保存すると、次に書く発言の親（会話の先端）を履歴から決められ、遅れて届いた発言も
    /// 書かれた位置に並ぶ（[`crate::talks`]）。代わりに会話の平文が端末に残る
    /// （パスフレーズがあれば暗号化される）。切ると親を付けずに送る。
    pub save_talk_history: bool,
    /// 自分が上げるファイルの大きさを 2 倍刻みに切り上げて置く（既定: 有効）
    ///
    /// ガードは自分のクライアントが置いた量・取った量を見ている。大きさがそのまま出ると、
    /// 公開ファイルが多い網では 1 回の取得から候補がごく少数に絞られる（Part 24 の L5）。
    /// チャンク数を `max(4, 2 の冪)` に増やし、足した分はファイルごとに別の中身の埋め草にする。
    /// **効くのは置く側だけ**: 取る人は置かれた形（埋め草込み）をそのまま全部取るので、
    /// 上げた人がこれを切っていれば、取る人の量からも大きさが出る。
    /// 代わりに、上り・保存と、取る人の下りが最大 2 倍（平均 1.4 倍）になる。切ると切り上げも埋め草もしない。
    pub pad_file_size: bool,
}

impl Default for PrivacyOptions {
    fn default() -> Self {
        Self {
            delay_fetch: true,
            delay_release: true,
            save_talk_history: true,
            pad_file_size: true,
        }
    }
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
    /// ガードとして一覧に無い送り手から受ける上りの、IP ごとの速さ（バイト/秒。0 = 無制限）
    ///
    /// 各ガードの手元の判断なので他ノードと揃える必要はないが、127.0.0.1 に全部が
    /// 集まる試験網で外せるよう、ここに置く。
    pub guest_upload_rate: u64,
    /// 一覧に載っているリレーから受ける上りの、IP ごとの速さ（0 = 無制限）
    pub relay_upload_rate: u64,
}

impl Default for NetworkParams {
    fn default() -> Self {
        let c = aether_core::Config::default();
        Self {
            directory_pow_difficulty: c.directory_pow_difficulty,
            hint_pow_difficulty: c.pow_difficulty,
            guest_upload_rate: c.guest_upload_rate,
            relay_upload_rate: c.relay_upload_rate,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_privacy_json_without_pad_file_size_still_loads_with_default_on() {
        // 切り替えを足す前に保存された設定（pad_file_size が無い）でも読め、既定の有効になる
        let old = r#"{"delay_fetch":false,"delay_release":true,"save_talk_history":false}"#;
        let p: PrivacyOptions = serde_json::from_str(old).unwrap();
        assert!(p.pad_file_size, "無い項目は既定（有効）");
        assert!(!p.delay_fetch && !p.save_talk_history, "あった項目はそのまま");
        // 空の設定でも読める
        assert_eq!(serde_json::from_str::<PrivacyOptions>("{}").unwrap(), PrivacyOptions::default());
        // 明示的に切った値は保たれる
        let off: PrivacyOptions = serde_json::from_str(r#"{"pad_file_size":false}"#).unwrap();
        assert!(!off.pad_file_size);
    }
}
