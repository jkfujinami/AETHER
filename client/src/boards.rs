//! 板 ── 実体は乱数 32 バイトの ID、名前はラベル
//!
//! # なぜキーワードではなく乱数 ID か
//!
//! - **衝突しない。** 無関係な 2 つの集まりが同じ名前を付けても、別の板になる。
//! - **推測で覗けない。** キーワードだと「雑談」「ニュース」のようなありがちな名前は
//!   辞書を総当たりすれば読める。乱数 256 ビットは総当たりできない。
//!
//! 公式の板（[`builtin_boards`]）の ID はアプリに埋め込むので、**誰でも読める公開板**になる
//! （5ch と同じ）。守られるのは「誰が書いたか」であって「何が書かれたか」ではない。
//! 非公開板は ID を渡された人だけが入れる。
//!
//! ラベルは重複しうる（偽の「雑談」は誰でも作れる）ので、ID から作る短い指紋を必ず並べて見せる。

use crate::error::{ClientError, Result};
use crate::keys::KeyFiles;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 板を共有する文字列の接頭辞
pub const BOARD_URI_PREFIX: &str = "aether-board:";

/// 板の鍵の導出に混ぜるタグ
const BOARD_KEY_DOMAIN: &[u8] = b"aether_board_key_v1";
/// 指紋の導出に混ぜるタグ
const FINGERPRINT_DOMAIN: &[u8] = b"aether_board_fp_v1";

/// 公式の板（ID は一度だけ乱数で作って固定した）
const BUILTIN: &[(&str, &str)] = &[(
    "雑談",
    "f9a726a2b5dcf525b91fd12a8d50124f9535ac34b89c40781f2179b6f518becd",
)];

/// 板の ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoardId(pub [u8; 32]);

impl BoardId {
    /// 新しい板の ID（非公開板を作るとき）
    pub fn random() -> Self {
        Self(rand::random())
    }

    /// `aether-board:<hex>` または hex から読む
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        let hex_part = s.strip_prefix(BOARD_URI_PREFIX).unwrap_or(s);
        Ok(Self(crate::parse_hex32(hex_part, "板の ID")?))
    }

    /// 書き込みを封じる鍵（索引の位置もここから決まる）
    ///
    /// ID をそのまま鍵にせず、用途のタグを混ぜて導出する（将来 ID を別の用途に使っても鍵と重ならない）。
    pub fn key(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(BOARD_KEY_DOMAIN)
            .chain_update(self.0)
            .finalize()
            .into()
    }

    /// 共有用の文字列（QR にもこの形で入れる）
    pub fn uri(&self) -> String {
        format!("{}{}", BOARD_URI_PREFIX, hex::encode(self.0))
    }

    /// 見分けるための短い指紋（例: `a3f9`）
    pub fn fingerprint(&self) -> String {
        let h = Sha256::new()
            .chain_update(FINGERPRINT_DOMAIN)
            .chain_update(self.0)
            .finalize();
        hex::encode(&h[..2])
    }
}

/// 画面に出す板の情報
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardInfo {
    /// `aether-board:<hex>`
    pub uri: String,
    pub label: String,
    pub fingerprint: String,
    /// 公式の板か（公開・アプリに埋め込み）
    pub builtin: bool,
}

impl BoardInfo {
    fn new(id: &BoardId, label: &str, builtin: bool) -> Self {
        Self {
            uri: id.uri(),
            label: label.to_string(),
            fingerprint: id.fingerprint(),
            builtin,
        }
    }

    pub fn id(&self) -> Result<BoardId> {
        BoardId::parse(&self.uri)
    }
}

/// 公式の板
pub fn builtin_boards() -> Vec<BoardInfo> {
    BUILTIN
        .iter()
        .map(|(label, hex_id)| {
            let id = BoardId::parse(hex_id).expect("埋め込みの板 ID は正しい");
            BoardInfo::new(&id, label, true)
        })
        .collect()
}

/// 公式の板をラベルで引く（CLI の `--board 雑談` 用）
pub fn resolve_board(input: &str) -> Result<BoardId> {
    let s = input.trim();
    if let Some((_, hex_id)) = BUILTIN.iter().find(|(label, _)| *label == s) {
        return BoardId::parse(hex_id);
    }
    BoardId::parse(s).map_err(|_| {
        ClientError::invalid(format!(
            "板が分かりません: {}（公式の板の名前か aether-board:… を指定してください）",
            s
        ))
    })
}

/// お気に入りに保存する形
#[derive(Serialize, Deserialize)]
struct Favorite {
    uri: String,
    label: String,
    added_at: u64,
}

impl KeyFiles {
    fn favorites_path(&self) -> std::path::PathBuf {
        self.data_dir().join("boards.bin")
    }

    /// お気に入りの板（公式の板は含まない）
    pub fn load_favorite_boards(&self) -> Result<Vec<BoardInfo>> {
        let Some(json) = self.read_secure(&self.favorites_path())? else {
            return Ok(Vec::new());
        };
        let favs: Vec<Favorite> = serde_json::from_slice(&json)
            .map_err(|e| ClientError::invalid(format!("お気に入りの板が壊れています: {}", e)))?;
        favs.iter()
            .map(|f| Ok(BoardInfo::new(&BoardId::parse(&f.uri)?, &f.label, false)))
            .collect()
    }

    /// 板をお気に入りに入れる（同じ板ならラベルを上書き）
    pub fn add_favorite_board(&self, id: &BoardId, label: &str) -> Result<BoardInfo> {
        let label = label.trim();
        if label.is_empty() {
            return Err(ClientError::invalid("板の名前を入れてください"));
        }
        let mut favs: Vec<Favorite> = match self.read_secure(&self.favorites_path())? {
            Some(json) => serde_json::from_slice(&json).unwrap_or_default(),
            None => Vec::new(),
        };
        let uri = id.uri();
        favs.retain(|f| f.uri != uri);
        favs.push(Favorite {
            uri,
            label: label.to_string(),
            added_at: aether_core::protocol::hint::current_timestamp(),
        });
        let json = serde_json::to_vec(&favs).expect("Favorite は直列化できる");
        self.write_secure(&self.favorites_path(), &json)?;
        Ok(BoardInfo::new(id, label, false))
    }

    /// お気に入りの板を削除する
    ///
    /// 公式の板はそもそもお気に入りに入っていないので、ここには来ない
    /// （呼び出し側で公式かどうかを確認すること）。
    pub fn remove_favorite_board(&self, id: &BoardId) -> Result<()> {
        let uri = id.uri();
        let mut favs: Vec<Favorite> = match self.read_secure(&self.favorites_path())? {
            Some(json) => serde_json::from_slice(&json).unwrap_or_default(),
            None => Vec::new(),
        };
        let before = favs.len();
        favs.retain(|f| f.uri != uri);
        if favs.len() == before {
            return Err(ClientError::invalid("お気に入りに登録されていません"));
        }
        let json = serde_json::to_vec(&favs).expect("Favorite は直列化できる");
        self.write_secure(&self.favorites_path(), &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_board_resolves_by_label() {
        let boards = builtin_boards();
        assert_eq!(boards[0].label, "雑談");
        assert_eq!(resolve_board("雑談").unwrap(), boards[0].id().unwrap());
    }

    #[test]
    fn uri_roundtrip_and_key_differs_from_id() {
        let id = BoardId::random();
        assert_eq!(BoardId::parse(&id.uri()).unwrap(), id);
        assert_ne!(id.key(), id.0);
        assert_eq!(id.fingerprint().len(), 4);
    }

    #[test]
    fn favorites_are_encrypted_with_a_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), Some("pass".into()));
        let id = BoardId::random();
        keys.add_favorite_board(&id, "身内の板").unwrap();

        let raw = std::fs::read(dir.path().join("boards.bin")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("身内の板"), "平文で残っている");
        let favs = keys.load_favorite_boards().unwrap();
        assert_eq!(favs.len(), 1);
        assert_eq!(favs[0].id().unwrap(), id);
    }

    #[test]
    fn remove_favorite_board_removes_entry() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        let id = BoardId::random();
        keys.add_favorite_board(&id, "身内の板").unwrap();
        keys.remove_favorite_board(&id).unwrap();
        assert!(keys.load_favorite_boards().unwrap().is_empty());
    }

    #[test]
    fn remove_favorite_board_errs_if_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), None);
        assert!(keys.remove_favorite_board(&BoardId::random()).is_err());
    }
}
