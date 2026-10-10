//! 結合テストの共通部品（実ノードを localhost に並べる）

#![allow(dead_code)]

use aether_client::{
    AetherClient, ClientConfig, ClientEvent, NetworkParams, NodeMode, PrivacyOptions,
    RelayOptions,
};
use aether_core::Config;
use aether_core::crypto::identity::Identity;
use aether_core::node::server::NodeServer;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// テスト網：PoW を全部切る（既定の難易度はデバッグビルドでは遅すぎる）
pub fn test_network() -> NetworkParams {
    NetworkParams {
        directory_pow_difficulty: 0,
        hint_pow_difficulty: 0,
        // 全部 127.0.0.1 なので、IP ごとの上り制限は外す
        guest_upload_rate: 0,
        relay_upload_rate: 0,
        manifest_page_stripes: None,
    }
}

pub fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 到達可能（Tier 0）なリレーを `n` 台立て、互いに知り合うまで待つ
pub async fn spawn_relays(n: usize) -> (Vec<Arc<NodeServer>>, Vec<tempfile::TempDir>) {
    let config = Config {
        node_id_pow_difficulty: 0,
        directory_pow_difficulty: 0,
        pow_difficulty: 0,
        guest_upload_rate: 0,
        relay_upload_rate: 0,
        ..Default::default()
    };
    let mut nodes = Vec::new();
    let mut dirs = Vec::new();
    for _ in 0..n {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let mut node =
            NodeServer::with_config(port, Identity::generate(), dir.path(), &config).unwrap();
        node.declare_reachable(format!("127.0.0.1:{}", port).parse().unwrap())
            .await;
        let node = Arc::new(node);
        let running = node.clone();
        tokio::spawn(async move {
            let _ = running.run().await;
        });
        nodes.push(node);
        dirs.push(dir);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let seed = nodes[0].descriptor.addr;
    for node in &nodes[1..] {
        node.bootstrap(seed).await.unwrap();
    }
    wait_until("relays know each other", Duration::from_secs(20), || {
        let nodes = nodes.clone();
        async move {
            for node in &nodes {
                if node.directory_size().await < n {
                    return false;
                }
            }
            true
        }
    })
    .await;
    (nodes, dirs)
}

/// 隠れた保持者を `n` 台立てる（`NodeMode::Resident` のクライアント。leaseSet が網に行き渡るまで待つ）
///
/// 今の試験網のリレー（`spawn_relays`）は `NodeServer` だけで保持者にならない。置く・取るには、
/// leaseSet を出す常駐クライアントが要る。待つのは、各保持者が leaseSet を出し、
/// `relays` の全員のディレクトリに載るまで。取る側・置く側のクライアントが知るまでは
/// [`wait_for_leases`] で別に待つ。
pub async fn spawn_holders(
    relays: &[Arc<NodeServer>],
    n: usize,
) -> (Vec<Arc<AetherClient>>, Vec<tempfile::TempDir>) {
    let seed = relays[0].descriptor.addr;
    let mut holders = Vec::new();
    let mut dirs = Vec::new();
    for _ in 0..n {
        let dir = tempfile::tempdir().unwrap();
        holders.push(hidden_holder(dir.path(), seed, aether_client::event_channel()).await);
        dirs.push(dir);
    }
    for (i, holder) in holders.iter().enumerate() {
        wait_until(&format!("holder {} issues a lease set", i), Duration::from_secs(180), || {
            let holder = holder.clone();
            async move { holder.holder_status().lease_set.is_some() }
        })
        .await;
    }
    let sids: Vec<[u8; 32]> = holders.iter().map(|h| h.holder_status().lease_set.unwrap().sid).collect();
    wait_until("every relay learns the lease sets", Duration::from_secs(120), || {
        let relays = relays.to_vec();
        let sids = sids.clone();
        async move {
            for node in &relays {
                let dir = node.directory();
                let dir = dir.read().await;
                if !sids.iter().all(|sid| dir.lease_set(sid).is_some()) {
                    return false;
                }
            }
            true
        }
    })
    .await;
    (holders, dirs)
}

/// `observers` の全員が、`holders` の全員の leaseSet をディレクトリに持つまで待つ
///
/// 置き場所はディレクトリから手元で計算するので、持たない保持者は置く・取る相手から外れる
/// （小さな試験網では、置く側と取る側の見え方が食い違うと取れない）。
pub async fn wait_for_leases(observers: &[Arc<AetherClient>], holders: &[Arc<AetherClient>]) {
    let sids: Vec<[u8; 32]> = holders
        .iter()
        .map(|h| h.holder_status().lease_set.expect("leaseSet を出していない保持者").sid)
        .collect();
    for observer in observers {
        wait_until("an observer learns the lease sets", Duration::from_secs(120), || {
            let observer = observer.clone();
            let sids = sids.clone();
            async move {
                let dir = observer.node().directory();
                let dir = dir.read().await;
                sids.iter().all(|sid| dir.lease_set(sid).is_some())
            }
        })
        .await;
    }
}

pub async fn wait_until<F, Fut>(label: &str, timeout: Duration, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while !cond().await {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {}", label);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub fn ephemeral(data_dir: &std::path::Path, seed: SocketAddr) -> ClientConfig {
    ClientConfig {
        data_dir: data_dir.to_path_buf(),
        passphrase: None,
        port: 0,
        seed: Some(seed),
        min_relays: 4,
        mode: NodeMode::Ephemeral,
        network: test_network(),
        privacy: Default::default(),
    }
}

/// 隠れた保持者（常駐。一覧に載らず、私信は受け取らない）を 1 台立てる
pub async fn hidden_holder(
    data_dir: &std::path::Path,
    seed: SocketAddr,
    events: aether_client::EventSender,
) -> Arc<AetherClient> {
    AetherClient::start(
        ClientConfig {
            data_dir: data_dir.to_path_buf(),
            passphrase: None,
            port: free_port(),
            seed: Some(seed),
            min_relays: 4,
            mode: NodeMode::Resident,
            network: test_network(),
            privacy: Default::default(),
        },
        events,
    )
    .await
    .unwrap()
}

/// 常駐＋中継のクライアントを 1 台立てる（私信の身元 `identity` は data_dir に作ってある前提）
pub async fn resident(
    data_dir: &std::path::Path,
    seed: SocketAddr,
    events: aether_client::EventSender,
) -> Arc<AetherClient> {
    resident_with(data_dir, seed, events, Default::default()).await
}

/// 遅延の切り替えを指定して常駐クライアントを立てる
pub async fn resident_with(
    data_dir: &std::path::Path,
    seed: SocketAddr,
    events: aether_client::EventSender,
    privacy: PrivacyOptions,
) -> Arc<AetherClient> {
    let port = free_port();
    AetherClient::start(
        ClientConfig {
            data_dir: data_dir.to_path_buf(),
            passphrase: None,
            port,
            seed: Some(seed),
            min_relays: 4,
            mode: NodeMode::Relay(RelayOptions {
                advertise: Some(format!("127.0.0.1:{}", port).parse().unwrap()),
                allow_port_mapping: false,
                pow_difficulty: 0,
                epoch_beacon: false,
            }),
            network: test_network(),
            privacy,
        },
        events,
    )
    .await
    .unwrap()
}

pub async fn next_received(
    rx: &mut tokio::sync::broadcast::Receiver<ClientEvent>,
    who: &str,
) -> String {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match rx.recv().await {
                Ok(ClientEvent::Received { text, .. }) => return text,
                Ok(ClientEvent::Warning { message }) => eprintln!("{}: {}", who, message),
                _ => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{} が私信を受信しない", who))
}
