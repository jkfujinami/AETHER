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

/// 参加のしかた
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JoinMode {
    /// 一回限り（掲示板と送信だけ）
    Ephemeral,
    /// 常駐（隠れた保持者）。一覧に載らず、欠片を預かる。トークは受け取れない
    #[default]
    Resident,
    /// 常駐＋中継。一覧に載る。トークの受信には必須
    Relay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// 種ノード（host:port）
    pub seed: String,
    /// 参加のしかた
    pub mode: JoinMode,
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
            mode: JoinMode::default(),
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
    parse(&bytes)
}

/// 設定ファイルの中身を読む
///
/// 古い設定（参加のしかたが `relay: true/false` の 2 択）も読める。当時の「常駐」は中継を兼ねていた
/// ので `Relay`、「一回限り」は `Ephemeral` として扱う（受信できていた人が黙って受信できなくならない）。
fn parse(bytes: &[u8]) -> Option<Settings> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let legacy = match (value.get("mode"), value.get("relay").and_then(|v| v.as_bool())) {
        (None, Some(true)) => Some(JoinMode::Relay),
        (None, Some(false)) => Some(JoinMode::Ephemeral),
        _ => None,
    };
    let mut settings: Settings = serde_json::from_value(value).ok()?;
    if let Some(mode) = legacy {
        settings.mode = mode;
    }
    Some(settings)
}

pub fn save(data_dir: &Path, settings: &Settings) -> Result<(), String> {
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    let json = serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?;
    // 途中で落ちても壊れた設定を残さない（書いてから置き換える）
    let tmp = path(data_dir).with_extension("json.tmp");
    std::fs::write(&tmp, json).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path(data_dir)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_two_way_settings_still_load() {
        let relay = parse(br#"{"seed":"127.0.0.1:1","relay":true,"advertise":"","auto_connect":true}"#).unwrap();
        assert_eq!(relay.mode, JoinMode::Relay, "古い常駐は中継を兼ねていた");
        let once = parse(br#"{"seed":"127.0.0.1:1","relay":false}"#).unwrap();
        assert_eq!(once.mode, JoinMode::Ephemeral);
        assert_eq!(once.seed, "127.0.0.1:1");
    }

    #[test]
    fn new_settings_round_trip_and_default_is_resident() {
        let s = Settings { mode: JoinMode::Relay, ..Default::default() };
        let json = serde_json::to_vec(&s).unwrap();
        assert_eq!(parse(&json).unwrap().mode, JoinMode::Relay);
        assert_eq!(parse(b"{}").unwrap().mode, JoinMode::Resident);
        assert!(!String::from_utf8(json).unwrap().contains("\"relay\":"), "古い項目は書き戻さない");
    }
}
