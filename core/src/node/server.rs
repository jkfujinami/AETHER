use crate::error::Result;
use crate::net::quic::QuicServer;
use crate::protocol::wire::{self, PacketType};
use crate::node::router::{Router, RoutingAction};
use crate::mailbox::server::MailboxServer;
use crate::net::gossip_server::GossipServer;
use crate::net::tunnel::TunnelRelay;
use crate::node::peer::PeerManager;
use crate::crypto::identity::Identity;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, debug};
use crate::Config;
use std::path::Path;
use std::net::SocketAddr;

pub struct NodeServer {
    pub server: QuicServer,
    pub router: Arc<Router>,
    pub mailbox: Arc<MailboxServer>,
    pub gossip: Arc<GossipServer>,
    pub tunnel_relay: Arc<RwLock<TunnelRelay>>,
    pub peers: Arc<PeerManager>,
    // identity: Arc<Identity>,
}


pub struct PacketContext {
    pub router: Arc<Router>,
    pub mailbox: Arc<MailboxServer>,
    pub gossip: Arc<GossipServer>,
    pub tunnel_relay: Arc<RwLock<TunnelRelay>>,
    pub peers: Arc<PeerManager>,
    pub local_addr: SocketAddr,
}

impl NodeServer {
    pub fn new(port: u16, identity: Identity, db_path: &Path) -> Result<Self> {
        let config = Config { listen_port: port, ..Default::default() };
        let server = QuicServer::new(&config)?;

        // Modules init
        let identity = Arc::new(identity);
        let router = Arc::new(Router::new(identity.clone())?);
        let mailbox = Arc::new(MailboxServer::new(db_path, &config)?);
        let gossip = Arc::new(GossipServer::new(&config));
        let tunnel_relay = Arc::new(RwLock::new(TunnelRelay::new()));
        let peers = Arc::new(PeerManager::new());

        Ok(Self {
            server,
            router,
            mailbox,
            gossip,
            tunnel_relay,
            peers,
        })
    }

    pub async fn run(&self) -> Result<()> {
        let local_addr = self.server.local_addr()?;
        info!("AETHER Node running on {}", local_addr);
        println!("Node listening on {}", local_addr);

        while let Some(conn) = self.server.accept().await {
            // Clone Arcs for the new task
            let router = self.router.clone();
            let mailbox = self.mailbox.clone();
            let gossip = self.gossip.clone();
            let tunnel_relay = self.tunnel_relay.clone();
            let peers = self.peers.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(conn, router, mailbox, gossip, tunnel_relay, peers, local_addr).await {
                    error!("Connection error: {}", e);
                }
            });
        }
        Ok(())
    }

    async fn handle_connection(
        conn: quinn::Incoming,
        router: Arc<Router>,
        mailbox: Arc<MailboxServer>,
        gossip: Arc<GossipServer>,
        tunnel_relay: Arc<RwLock<TunnelRelay>>,
        peers: Arc<PeerManager>,
        local_addr: SocketAddr
    ) -> Result<()> {
        let connection = conn.await.map_err(|e| crate::AetherError::Quic(e.to_string()))?;
        let remote_addr = connection.remote_address();
        println!("[SERVER DEBUG] New connection from {}", remote_addr);
        debug!("New connection from {}", remote_addr);

        // ピアリストに追加
        peers.add_peer(remote_addr).await;

        while let Ok(mut recv_stream) = connection.accept_uni().await {
            println!("[SERVER DEBUG] Accepted uni stream");

            let ctx = PacketContext {
                router: router.clone(),
                mailbox: mailbox.clone(),
                gossip: gossip.clone(),
                tunnel_relay: tunnel_relay.clone(),
                peers: peers.clone(),
                local_addr,
            };

            tokio::spawn(async move {
                match wire::read_packet(&mut recv_stream).await {
                    Ok((packet_type, payload)) => {
                        println!("[SERVER DEBUG] Read packet: {:?} ({} bytes)", packet_type, payload.len());
                        debug!("Received packet: {:?} ({} bytes)", packet_type, payload.len());

                        // パケット処理
                        if let Err(e) = Self::process_packet(packet_type, payload, ctx).await {
                            error!("Error processing packet: {}", e);
                            println!("[SERVER DEBUG] Error processing packet: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to read packet: {}", e);
                        println!("[SERVER DEBUG] Failed to read packet: {}", e);
                    }
                }
            });
        }
        Ok(())
    }

    async fn process_packet(
        packet_type: PacketType,
        payload: Vec<u8>,
        ctx: PacketContext,
    ) -> Result<()> {
        match packet_type {
            PacketType::OnionPacket => {

                match ctx.router.handle_packet(&payload).await? {
                    RoutingAction::Forwarded => {
                        // 転送完了
                        debug!("Onion packet forwarded");
                    },
                    RoutingAction::LocalProcessing(inner_payload) => {
                        debug!("Onion packet reached destination. Processing inner payload as MailboxPut.");
                        // TODO: プロトコルとして、Onionの中身が常にMailboxPutとは限らないが
                        // 現時点の実装ではMailboxへの配信として扱う
                        ctx.mailbox.handle_put(&inner_payload).await?;
                    }
                }
            },
            PacketType::GossipHint => {
                if ctx.gossip.handle_hint(&payload).await? {
                    info!("Received new Gossip Hint. Broadcasting...");

                    // 拡散 (3 peer)
                    let random_peers = ctx.peers.get_random_peers(3).await;
                    for peer_addr in random_peers {
                         // TODO: 実際にはここで QuicClient を使って送信する
                         // しかし NodeServer は Server であり Client 機能(送信)を持っていない構造になっている
                         // Router 内の QuicClient を借りるか、NodeServer も QuicClient を持つべき。

                         // 暫定対応: Router の forward_packet は private だが、QuicClient 機能は共有すべき。
                         // 後で NodeServer にも QuicClient を持たせるリファクタリングを行う。
                         debug!("(TODO) Broadcast hint to {}", peer_addr);
                    }
                }
            },
            PacketType::MailboxPut => {
                ctx.mailbox.handle_put(&payload).await?;
            },
            PacketType::MailboxGet => {
                 let result = ctx.mailbox.handle_get(&payload).await?;
                 // GETのリクエストに対してレスポンスを返す経路が必要だが
                 // uni-directional stream で受け取っているので、返信できない！
                 // 返信用の Onion Circuit (Reply Block) が必要。
                 // AETHER は非同期メッセージングなので、GETに対する応答も「新たなメッセージ」として送り返す必要がある。
                 // つまり Sender は Reply用のアドレスまたはCircuit情報を Payload に含める必要がある。
                 debug!("Mailbox GET processed. Found: {}", result.is_some());
            },
            PacketType::TunnelBuild => {
                println!("[DEBUG] Received TunnelBuild packet");
                match ctx.router.process_tunnel_build(&payload) {
                    Ok((tid, shared_secret, inst)) => {
                        if let Some(next) = inst.next_hop {
                            let mut relay = ctx.tunnel_relay.write().await;
                            relay.register_tunnel(tid, shared_secret, next, inst.next_tunnel_id);
                            println!("[DEBUG] Tunnel registered: ID={:?} -> {}", tid, next);
                            debug!("Tunnel registered: ID={:?} -> {}", tid, next);
                        } else {
                            // Inbound Tunnel では自分自身も「次のホップ」として指定されるはず
                             tracing::warn!("TunnelBuild with no next_hop received. Ignoring.");
                        }
                    },
                    Err(e) => {
                        error!("Failed to process TunnelBuild: {}", e);
                    }
                }
            },
            PacketType::TunnelData => {
                println!("[DEBUG] Received TunnelData packet");
                // Tunnel Data: [TunnelID(32)][Nonce(12)][EncryptedData]
                if payload.len() < 32 + 12 {
                    error!("TunnelData packet too short");
                    return Ok(());
                }

                let tunnel_id: [u8; 32] = payload[0..32].try_into().unwrap();
                let data = &payload[32..];

                let relay = ctx.tunnel_relay.read().await;
                match relay.process_tunnel_data(&tunnel_id, data) {
                    Ok(Some((next_hop, next_tunnel_id, forwarded_data))) => {
                        // Check if we are the destination (Inbound Tunnel Endpoint)
                        // Compare by port since local_addr might be 0.0.0.0 while next_hop is 127.0.0.1
                        println!("[DEBUG] Tunnel: next_hop={}, local_addr={}, next_hop.port()={}, local_addr.port()={}",
                                 next_hop, ctx.local_addr, next_hop.port(), ctx.local_addr.port());
                        if next_hop.port() == ctx.local_addr.port() {
                             println!("[DEBUG] Tunnel: reached endpoint (self), storing message for ID {:?}", tunnel_id);
                             debug!("Tunnel: reached endpoint (self), storing message for ID {:?}", tunnel_id);
                             // Store raw tunnel data. The client will fetch and decrypt it later.
                             // Not using next_tunnel_id, but the original tunnel_id as key.
                             if let Err(e) = ctx.mailbox.store_tunnel_message(&tunnel_id, &forwarded_data).await {
                                 error!("Store tunnel msg failed: {}", e);
                             }
                        } else {
                             // Forwarding
                             println!("[DEBUG] Tunnel: forwarding to {}", next_hop);
                             debug!("Tunnel: forwarding to {}", next_hop);

                             // New packet: [NextTunnelID][Nonce][EncData]
                             let mut next_payload = Vec::with_capacity(32 + forwarded_data.len());
                             next_payload.extend_from_slice(&next_tunnel_id);
                             next_payload.extend_from_slice(&forwarded_data);

                             // Drop lock before async call
                             drop(relay); // Important: drop lock here, not inside block if possible, but we branch

                             if let Err(e) = ctx.router.send_packet(next_hop, PacketType::TunnelData, &next_payload).await {
                                  error!("Tunnel forwarding failed: {}", e);
                             }
                             return Ok(()); // Lock already dropped or not needed
                        }
                        // If we didn't return, drop lock
                        // drop(relay); // Already dropped above if forwarding. If stored, drop now.
                    },
                    Ok(None) => {
                         // Should not happen with current logic, but just in case
                         debug!("Tunnel: process_tunnel_data returned None");
                    },
                    Err(e) => {
                        error!("Tunnel processing error: {}", e);
                    }
                }
                // Explicit drop if not forwarded (compiler will handle scope drop, but manual drop for clarity)
                // drop(relay);
            },
            _ => {
                info!("Unhandled packet type: {:?}", packet_type);
            }
        }
        Ok(())
    }

    // Test accessors
    pub fn mailbox(&self) -> Arc<MailboxServer> { self.mailbox.clone() }
    pub fn gossip(&self) -> Arc<GossipServer> { self.gossip.clone() }
}
