//! E2E: トラッカーを介したシグナリングとホールパンチングによるブートストラップ
//!
//! 静的ポート開放を行っていないノード同士が、WebSocket シグナリングサーバーを
//! 仲介役として互いの接続候補アドレスを交換し、NAT を抜いて自己組織化できるかを検証する。

use aether_core::crypto::identity::Identity;
use aether_core::net::signaling::{PunchPayload, TrackerMessage, TrackerPeer};
use aether_core::node::server::NodeServer;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

mod common;

/// テスト用の軽量インメモリ WebSocket シグナリングサーバー
async fn start_mock_tracker() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://127.0.0.1:{}", addr.port());

    type Tx = futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>, Message>;
    let peers: Arc<Mutex<HashMap<String, Tx>>> = Arc::new(Mutex::new(HashMap::new()));

    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let ws_stream = match accept_async(stream).await {
                Ok(ws) => ws,
                Err(_) => continue,
            };

            let peers = peers.clone();
            tokio::spawn(async move {
                let (mut write, mut read) = ws_stream.split();
                let mut my_peer_id: Option<String> = None;

                while let Some(Ok(msg)) = read.next().await {
                    let text = match msg {
                        Message::Text(t) => t,
                        _ => continue,
                    };

                    let req: match_msg::Req = match serde_json::from_str(&text) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };

                    if req.msg_type == "join" {
                        let peer_id = req.peer_id.unwrap();
                        my_peer_id = Some(peer_id.clone());

                        let mut lock = peers.lock().await;
                        // 既存の他のピア一覧を返す
                        let other_peers: Vec<TrackerPeer> = lock
                            .keys()
                            .filter(|k| *k != &peer_id)
                            .map(|k| TrackerPeer {
                                peer_id: k.clone(),
                                position: 0,
                            })
                            .collect();

                        let resp = TrackerMessage::Peers { peers: other_peers };
                        let _ = write.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;

                        lock.insert(peer_id, write);
                        break; // write は map 内で保持するためループを別タスクへ委譲
                    }
                }

                if let Some(peer_id) = my_peer_id {
                    while let Some(Ok(msg)) = read.next().await {
                        let text = match msg {
                            Message::Text(t) => t,
                            _ => continue,
                        };

                        let req: match_msg::Req = match serde_json::from_str(&text) {
                            Ok(r) => r,
                            Err(_) => continue,
                        };

                        if req.msg_type == "relay" {
                            let target = req.target_peer_id.unwrap();
                            let payload = req.payload.unwrap();
                            let mut lock = peers.lock().await;
                            if let Some(target_tx) = lock.get_mut(&target) {
                                let fwd = TrackerMessage::PunchOffer {
                                    peer: payload.peer,
                                    candidates: payload.candidates,
                                    sender_id: Some(peer_id.clone()),
                                    from: Some(peer_id.clone()),
                                };
                                let _ = target_tx
                                    .send(Message::Text(serde_json::to_string(&fwd).unwrap().into()))
                                    .await;
                            }
                        }
                    }

                    peers.lock().await.remove(&peer_id);
                }
            });
        }
    });

    (url, handle)
}

mod match_msg {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct Req {
        #[serde(rename = "type")]
        pub msg_type: String,
        #[serde(rename = "peerId")]
        pub peer_id: Option<String>,
        #[serde(rename = "targetPeerId")]
        pub target_peer_id: Option<String>,
        pub payload: Option<PunchPayload>,
    }
}

async fn spawn_node(port: u16) -> (Arc<NodeServer>, tempfile::TempDir, SocketAddr) {
    let dir = tempfile::tempdir().unwrap();
    let mut node =
        NodeServer::with_config(port, Identity::generate(), dir.path(), &common::test_config())
            .unwrap();

    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    node.declare_reachable(addr).await;

    let server = Arc::new(node);
    let running = server.clone();
    tokio::spawn(async move {
        let _ = running.run().await;
    });

    common::wait_for_listener(addr).await;
    (server, dir, addr)
}

#[tokio::test]
async fn two_nodes_bootstrap_via_signaling() {
    let (tracker_url, _tracker_handle) = start_mock_tracker().await;

    // ノード1（先行待機ノード）
    let (node1, _dir1, _addr1) = spawn_node(19651).await;

    // ノード1がシグナリングに接続（最初は相手がいない）
    let tracker_clone = tracker_url.clone();
    let n1_clone = node1.clone();
    let n1_task = tokio::spawn(async move {
        n1_clone.bootstrap_via_signaling(&tracker_clone).await
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // ノード2（後発参加ノード）
    let (node2, _dir2, _addr2) = spawn_node(19652).await;

    // ノード2がシグナリングに接続（ノード1を発見してパンチングを実行）
    let res2 = node2.bootstrap_via_signaling(&tracker_url).await;
    assert!(res2.is_ok(), "node2 failed to bootstrap via signaling");

    let _ = n1_task.await;

    // PEX によるディレクトリ収束を待つ
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let d1 = node1.directory.read().await.len();
        let d2 = node2.directory.read().await.len();
        if d1 >= 2 && d2 >= 2 {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("Directory sync timed out: node1 has {}, node2 has {}", d1, d2);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // 互いの NodeId が相手のディレクトリに登録されていることを確認
    let dir1 = node1.directory.read().await;
    let dir2 = node2.directory.read().await;
    assert!(dir1.get(&node2.descriptor.node_id).is_some());
    assert!(dir2.get(&node1.descriptor.node_id).is_some());
}
