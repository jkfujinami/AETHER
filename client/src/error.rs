//! クライアント API のエラー

/// クライアント API のエラー
///
/// GUI へそのまま文字列で見せられるよう、`Display` は利用者向けの文にする。
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Core(#[from] aether_core::AetherError),

    #[error("ファイル操作に失敗しました: {0}")]
    Io(#[from] std::io::Error),

    /// 設定・入力の誤り（利用者が直せるもの）
    #[error("{0}")]
    Invalid(String),

    /// 網の状態が足りない（リレー不足・到達不能など）
    #[error("{0}")]
    Network(String),
}

impl ClientError {
    pub(crate) fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }

    pub(crate) fn network(msg: impl Into<String>) -> Self {
        Self::Network(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;
