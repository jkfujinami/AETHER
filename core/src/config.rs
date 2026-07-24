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
            node_id_pow_difficulty: 16,
            enable_port_mapping: false,
            active_poll_interval_secs: 10,
            ghost_poll_interval_secs: 60,

            enable_cover_traffic: false,
            target_fps: 30,
        }
    }
}
