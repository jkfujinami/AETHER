use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen_port: u16,
    pub stun_servers: Vec<String>,

    // Mailbox
    pub mailbox_capacity_mb: u64,
    pub message_ttl_hours: u64,

    // Crypto
    pub pow_difficulty: u8,
    /// NodeId 生成に要求する PoW 難易度
    ///
    /// リング座標のグラインディング対策 (設計書 18.5.3)。
    /// 高いほど Sybil コストが上がるが、起動時に1回だけその時間がかかる。
    pub node_id_pow_difficulty: u32,
    /// 前回解いた NodeId PoW の解（あれば検証だけして使う）
    ///
    /// PoW は NodeId に対して一度解けば変わらない。起動のたびに解き直すと
    /// 難易度 16 で十数秒〜かかる。呼び出し側が保存しておいて渡す。
    /// 検証に通らない（鍵や難易度が変わった）ときは解き直す。
    pub node_id_pow_nonce: Option<u64>,
    /// 受け取った記述子に要求する NodeId PoW 難易度
    ///
    /// **自分が解く難易度とは別。** 一回限りのクライアントは自分の PoW を省くが、
    /// 回路を組むのはまさにそのクライアントなので、ここを 0 にすると
    /// PoW 無しの偽リレーを無制限に取り込み、回路を Sybil で埋められる。
    /// 網全体で揃える値（テスト以外で下げないこと）。
    pub directory_pow_difficulty: u32,
    /// 自分をリレーとして網に広告するか
    ///
    /// **一回限りのクライアントは `false`。** PEX 要求に自分の記述子を載せず、
    /// 他ノードのディレクトリに残らない（PoW の有無に頼らず明示的に）。
    pub advertise_self: bool,

    // 到達性
    /// ルータへのポートマッピング要求を許可するか
    ///
    /// **既定オフ。** 成功すれば punch 不要の完全な到達性が得られるが、
    /// ルータのリース表に痕跡が残る（再起動を跨いで残る機種がある）。
    /// IPv6 や punch にはこの痕跡が無いので、利用者に選ばせる。
    pub enable_port_mapping: bool,

    // Ghost Mode
    pub active_poll_interval_secs: u64,
    pub ghost_poll_interval_secs: u64,

    // Traffic Shaping
    pub enable_cover_traffic: bool,
    pub target_fps: u32,

    /// エポックビーコン（drand 由来の日次シード）を有効にするか (3-4)
    ///
    /// 位置グラインディング対策。リング座標に日次の公開乱数を混ぜ、グラインドした
    /// NodeId を1日で無効化する。**シードは全ノードで一致していなければならない**
    /// （食い違うと保持者計算がずれて網が分裂する）ため、これは事実上
    /// **網全体で揃える protocol フラグ**であり、個別 opt-in はできない。
    /// 既定オフ（＝固定 placeholder シード・現状の挙動）。
    ///
    /// 有効時は各ノードが日次で drand へ HTTPS 取得する（弱いフィンガープリント。
    /// 将来 exit/Tor 経由に差し替え可能）。
    pub epoch_beacon: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_port: 0,
            // **2台以上必要。** 1台では NAT のマッピング挙動を判定できない
            stun_servers: vec![
                "stun.l.google.com:19302".into(),
                "stun1.l.google.com:19302".into(),
            ],

            mailbox_capacity_mb: 100,
            message_ttl_hours: 168, // 1 week
            pow_difficulty: 10,
            node_id_pow_difficulty: crate::crypto::pow::node_id::DEFAULT_DIFFICULTY,
            node_id_pow_nonce: None,
            directory_pow_difficulty: crate::crypto::pow::node_id::DEFAULT_DIFFICULTY,
            advertise_self: true,
            enable_port_mapping: false,
            active_poll_interval_secs: 10,
            ghost_poll_interval_secs: 60,

            enable_cover_traffic: false,
            target_fps: 30,

            epoch_beacon: false,
        }
    }
}
