use thiserror::Error;

pub type Result<T> = std::result::Result<T, AetherError>;

#[derive(Error, Debug)]
pub enum AetherError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("QUIC error: {0}")]
    Quic(String), // quinnのエラーを文字列でラップ、あるいは直接ラップ

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Mailbox error: {0}")]
    Mailbox(String),

    #[error("Storage error: {0}")]
    Storage(String), // sledエラー等

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

// TODO: impl From for other error types as needed
impl From<bincode::Error> for AetherError {
    fn from(err: bincode::Error) -> Self {
        AetherError::Serialization(err.to_string())
    }
}
