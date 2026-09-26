//! E2E テスト用の共通ヘルパー
//!
//! 固定 `sleep` で待つとテストが遅くなるうえ、遅いマシンでは不安定になる。
//! ここでは**条件が満たされるまでポーリング**する。
//! 待ち時間は実際にかかった分だけになり、上限を超えたら失敗する。

#![allow(dead_code)]

use aether_core::crypto::identity::Identity;
use aether_core::net::quic::QuicClient;
use aether_core::node::server::NodeServer;
use aether_core::Config;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// ポーリング間隔
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// 既定の待ち上限
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// `condition` が true を返すまで待つ
///
/// # Panics
/// `timeout` を超えても満たされなかった場合、`label` を添えて panic する。
pub async fn wait_until<F, Fut>(label: &str, timeout: Duration, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;

    loop {
        if condition().await {
            return;
        }
        if Instant::now() >= deadline {
            panic!("timed out after {:?} waiting for: {}", timeout, label);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// ノードを起動し、**実際に接続を受け付けるようになるまで**待つ
///
/// `run()` が accept ループに入るのを固定 sleep で待つと、
/// 遅いマシンで不安定になるうえ速いマシンでは無駄に待つ。
/// テスト用設定
///
/// **NodeId PoW を無効にする。**
/// 既定の難易度 16 は Argon2id 65536 回で、デバッグビルドでは
/// ノード1台あたり数分かかりテストが実質停止する。
/// 難易度そのものは `crypto::pow` の単体テストで検証済み。
pub fn test_config() -> Config {
    Config {
        node_id_pow_difficulty: 0,
        directory_pow_difficulty: 0,
        // Hint PoW もテストでは無効化（生成・検証の一致を保ちつつ即座に回す）
        pow_difficulty: 0,
        ..Default::default()
    }
}

pub async fn spawn_ready_node(
    port: u16,
    identity: Identity,
    db_path: &std::path::Path,
) -> Arc<NodeServer> {
    let server = Arc::new(
        NodeServer::with_config(port, identity, db_path, &test_config()).unwrap(),
    );

    let running = server.clone();
    tokio::spawn(async move {
        if let Err(e) = running.run().await {
            eprintln!("node on port {} stopped: {}", port, e);
        }
    });

    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // QuicClient は UDP ソケットと rustls 設定を張るので、ループ内で作ると
    // ポーリングのたびに大量のソケットを作って CPU を焼く。1回だけ作る。
    let probe = QuicClient::new().expect("failed to create probe client");
    wait_until(
        &format!("node on port {} to accept connections", port),
        DEFAULT_TIMEOUT,
        || {
            let probe = &probe;
            async move { probe.connect(addr).await.is_ok() }
        },
    )
    .await;

    server
}

/// 指定アドレスが接続を受け付けるまで待つ
pub async fn wait_for_listener(addr: SocketAddr) {
    // QuicClient は UDP ソケットと rustls 設定を張るので、ループ内で作らない
    let probe = QuicClient::new().expect("failed to create probe client");
    wait_until(
        &format!("{} to accept connections", addr),
        DEFAULT_TIMEOUT,
        || {
            let probe = &probe;
            async move { probe.connect(addr).await.is_ok() }
        },
    )
    .await;
}

/// Mailbox に少なくとも `expected` 件たまるまで待つ
///
/// `handle_get` / `fetch_tunnel_messages` は取得時に削除する (Burn-on-Read) ため、
/// ポーリングには非破壊な `len()` を使う。
pub async fn wait_for_mailbox_entries(server: &Arc<NodeServer>, expected: usize) {
    let mailbox = server.mailbox();
    wait_until(
        &format!("mailbox to hold {} entry/entries", expected),
        DEFAULT_TIMEOUT,
        || {
            let mailbox = mailbox.clone();
            async move { mailbox.len() >= expected }
        },
    )
    .await;
}

/// 「起きないこと」を確認するための短い猶予
///
/// 非到達を証明することはできないので、上限を短く固定して
/// 「この時間内には起きなかった」までを主張する。
pub const NEGATIVE_CHECK_GRACE: Duration = Duration::from_millis(300);

pub async fn settle() {
    tokio::time::sleep(NEGATIVE_CHECK_GRACE).await;
}
