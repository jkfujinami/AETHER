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
            stun_servers: vec!["stun.l.google.com:19302".into()],

            mailbox_capacity_mb: 100,
            message_ttl_hours: 168, // 1 week
            pow_difficulty: 10,
            active_poll_interval_secs: 10,
            ghost_poll_interval_secs: 60,

            enable_cover_traffic: false,
            target_fps: 30,
        }
    }
}
