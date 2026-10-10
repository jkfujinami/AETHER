//! Deno Deploy トラッカー等を用いた外部シグナリングクライアント
//!
//! # 役割
//!
//! 静的ポート開放を行っていない NAT 内のノード同士が、
//! WebSocket トラッカー経由で接続候補アドレスを交換（シグナリング）し、
//! STUN プローブによる Hole Punching をトリガーして直接 QUIC 接続を確立する。
//!
//! 接続確立後は純粋な P2P メッシュ（PEX / DHT）へ移行するため、
//! トラッカーは初期ブートストラップ時の一時的な仲介役としてのみ機能する。

use crate::crypto::identity::NodeId;
use crate::error::{AetherError, Result};
use crate::net::punch::{self, PunchSession};
use crate::net::shared_socket::SharedSocket;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

/// トラッカーと送受信するメッセージ型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TrackerMessage {
    #[serde(rename = "join")]
    Join {
        #[serde(rename = "peerId")]
        peer_id: String,
        position: u32,
        #[serde(rename = "isSeed")]
        is_seed: bool,
        #[serde(rename = "isCache")]
        is_cache: bool,
    },
    #[serde(rename = "peers")]
    Peers {
        peers: Vec<TrackerPeer>,
    },
    #[serde(rename = "relay")]
    Relay {
        #[serde(rename = "targetPeerId")]
        target_peer_id: String,
        payload: PunchPayload,
    },
    #[serde(rename = "punch_offer")]
    PunchOffer {
        peer: String,
        candidates: Vec<String>,
        #[serde(default)]
        sender_id: Option<String>,
        #[serde(default)]
        from: Option<String>,
    },
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "pong")]
    Pong,
    #[serde(rename = "error")]
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerPeer {
    #[serde(rename = "peerId")]
    pub peer_id: String,
    pub position: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunchPayload {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub peer: String,
    pub candidates: Vec<String>,
}

/// シグナリングクライアント
pub struct SignalingClient {
    tracker_url: String,
    node_id: NodeId,
    candidates: Vec<SocketAddr>,
}

impl SignalingClient {
    pub fn new(tracker_url: impl Into<String>, node_id: NodeId, candidates: Vec<SocketAddr>) -> Self {
        Self {
            tracker_url: tracker_url.into(),
            node_id,
            candidates,
        }
    }

    /// トラッカーに接続してピアを探索し、Hole Punching を仕掛けて接続可能相手のアドレスを返す
    pub async fn discover_and_punch(
        &self,
        socket: &std::sync::Arc<SharedSocket>,
        timeout_duration: Duration,
    ) -> Result<Vec<SocketAddr>> {
        info!("Connecting to signaling tracker: {}", self.tracker_url);
        let (ws_stream, _) = connect_async(&self.tracker_url)
            .await
            .map_err(|e| AetherError::Network(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e)))?;

        let (mut write, mut read) = ws_stream.split();

        // 1. Join 要求
        let my_peer_id = hex::encode(self.node_id.0);
        let join_msg = TrackerMessage::Join {
            peer_id: my_peer_id.clone(),
            position: 0,
            is_seed: true,
            is_cache: false,
        };
        let text = serde_json::to_string(&join_msg).map_err(|e| AetherError::Serialization(e.to_string()))?;
        write.send(Message::Text(text.into())).await.map_err(|e| {
            AetherError::Network(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
        })?;

        let deadline = tokio::time::Instant::now() + timeout_duration;
        let mut discovered_candidates = Vec::new();

        // 自ノードの候補アドレス文字列
        let my_candidate_strs: Vec<String> = self.candidates.iter().map(|a| a.to_string()).collect();

        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                msg_opt = read.next() => {
                    let Some(msg_res) = msg_opt else { break; };
                    let msg = match msg_res {
                        Ok(Message::Text(t)) => t,
                        Ok(Message::Close(_)) => break,
                        Ok(_) => continue,
                        Err(e) => {
                            warn!("WebSocket error: {}", e);
                            break;
                        }
                    };

                    let tracker_msg: TrackerMessage = match serde_json::from_str(&msg) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };

                    match tracker_msg {
                        TrackerMessage::Peers { peers } => {
                            debug!("Discovered {} peers from tracker", peers.len());
                            // 既存ピアに対して punch_offer を送信
                            for peer in peers {
                                if peer.peer_id == my_peer_id {
                                    continue;
                                }
                                let relay_msg = TrackerMessage::Relay {
                                    target_peer_id: peer.peer_id,
                                    payload: PunchPayload {
                                        msg_type: "punch_offer".to_string(),
                                        peer: my_peer_id.clone(),
                                        candidates: my_candidate_strs.clone(),
                                    },
                                };
                                if let Ok(serialized) = serde_json::to_string(&relay_msg) {
                                    let _ = write.send(Message::Text(serialized.into())).await;
                                }
                            }
                        }
                        TrackerMessage::PunchOffer { peer, candidates, sender_id, from } => {
                            let remote_id = sender_id.or(from).unwrap_or(peer);
                            debug!("Received punch offer from {}: {:?}", remote_id, candidates);

                            let target_addrs: Vec<SocketAddr> = candidates
                                .iter()
                                .filter_map(|s| s.parse::<SocketAddr>().ok())
                                .collect();

                            if !target_addrs.is_empty() {
                                // 相手に向けて STUN probe_round を打つ
                                let mut session = PunchSession::new();
                                let probe_deadline = tokio::time::Instant::now() + punch::PROBE_WINDOW;
                                while tokio::time::Instant::now() < probe_deadline {
                                    let _ = session.probe_round(socket, &target_addrs).await;
                                    tokio::time::sleep(punch::PROBE_INTERVAL).await;
                                }

                                discovered_candidates.extend(target_addrs.clone());
                                // 相手にも折り返し候補を送っていない場合は送る
                                let relay_back = TrackerMessage::Relay {
                                    target_peer_id: remote_id,
                                    payload: PunchPayload {
                                        msg_type: "punch_offer".to_string(),
                                        peer: my_peer_id.clone(),
                                        candidates: my_candidate_strs.clone(),
                                    },
                                };
                                if let Ok(serialized) = serde_json::to_string(&relay_back) {
                                    let _ = write.send(Message::Text(serialized.into())).await;
                                }

                                break;
                            }
                        }
                        TrackerMessage::Error { message } => {
                            warn!("Tracker error: {}", message);
                        }
                        _ => {}
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(500)) => {
                    if !discovered_candidates.is_empty() {
                        break;
                    }
                }
            }
        }

        Ok(discovered_candidates)
    }
}
