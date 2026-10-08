//! 画面の設定（種ノード・参加のしかた・匿名性の切り替え）
//!
//! 起動時にこれを読み、保存済みで自動接続が有効なら、そのまま接続を試みる。
//!
//! **パスフレーズは保存しない。** 保存すると押収されたときに鍵ごと読まれる。
//! 鍵が暗号化されていれば、起動のたびに尋ねる。
//!
//! 設定そのものは平文で置く（パスフレーズより前に読む必要がある）。書かれているのは
//! 種ノード（公開のリレー）と切り替えだけで、データ置き場がある時点で AETHER を
//! 使っていることは分かるので、新たに漏れるものは少ない。

use aether_client::PrivacyOptions;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// 種ノード（host:port）
    pub seed: String,
    /// 常駐（リレー）として参加するか。トークの受信には必須
    pub relay: bool,
    /// リレーとして到達可能と宣言するアドレス（空なら STUN で判定）
    pub advertise: String,
    /// 起動したら保存した設定で自動的に接続する
    pub auto_connect: bool,
    /// 匿名性のための遅延など（接続中でも変えられる）
    pub privacy: PrivacyOptions,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            seed: String::new(),
            relay: true,
            advertise: String::new(),
            auto_connect: true,
            privacy: PrivacyOptions::default(),
        }
    }
}

fn path(data_dir: &Path) -> PathBuf {
    data_dir.join("settings.json")
}

/// 保存した設定（初回起動なら `None`）
pub fn load(data_dir: &Path) -> Option<Settings> {
    let bytes = std::fs::read(path(data_dir)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn save(data_dir: &Path, settings: &Settings) -> Result<(), String> {
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    let json = serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?;
    // 途中で落ちても壊れた設定を残さない（書いてから置き換える）
    let tmp = path(data_dir).with_extension("json.tmp");
    std::fs::write(&tmp, json).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path(data_dir)).map_err(|e| e.to_string())
}
