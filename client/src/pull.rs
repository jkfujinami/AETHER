//! Pull セッション ── 返信用 Inbound Tunnel と、要求を出す 3 ホップ回路
//!
//! ```text
//! 要求:  自分 → ガード → 中間1 → 出口 ──(MailboxGet / IndexQuery)──→ 保持者
//! 返信:  保持者 ──→ gateway → 中間2 → ガード ──(自分が張った接続)──→ 自分
//! ```
//!
//! - 保持者が見るのは gateway だけ。自分の IP を知るのはガードだけで、
//!   ガードは何を取りに行ったか（鍵）を知らない。
//! - **gateway と中間2 への構築指示は出口経由で届ける。** 直接送ると、
//!   構築者（＝受信者）の IP を gateway に晒して Inbound Tunnel の意味が消える。
//! - **ガードは返信を「自分が張った接続」の上で返す**（アドレス宛てにしない）。
//!   一回限りのクライアントは広告アドレスを持たず、NAT の内側にもいる。

use crate::client::AetherClient;
use crate::error::{ClientError, Result};
use aether_core::crypto::identity::NodeId;
use aether_core::mailbox::schrodinger::SchrodingerMailbox;
use aether_core::net::gossip::GossipClient;
use aether_core::net::relay::RelayClient;
use aether_core::net::tunnel::{InboundTunnel, TunnelEndpoint};
use aether_core::protocol::wire::PacketType;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 構築指示が各ホップへ行き渡るのを待つ時間
///
/// 指示より先に要求が保持者へ届き、返信が未登録の gateway で落ちるのを避ける。
const TUNNEL_SETTLE: Duration = Duration::from_millis(500);

pub(crate) struct PullSession {
    pub mailbox: SchrodingerMailbox,
    pub receive_tunnel_id: [u8; 32],
    pub reply_to: TunnelEndpoint,
    pub gateway: std::net::SocketAddr,
}

impl AetherClient {
    /// 返信トンネルと要求用の回路を張る
    ///
    /// `contacts` は Mailbox に載せる共有秘密。検索/取得は空、受信は購読中の秘密を渡す。
    pub(crate) async fn open_pull_session(
        &self,
        contacts: HashMap<NodeId, [u8; 32]>,
    ) -> Result<PullSession> {
        let circuit = self.build_circuit(&[]).await?;
        let me = self.node.descriptor.node_id;
        let guard = circuit.guard.clone();

        // 返信側の中間・gateway。要求回路の中間・出口とは重ねない（小さな網では出口だけ避ける）
        let directory = self.node.directory();
        let (middle2, gateway) = {
            let dir = directory.read().await;
            dir.circuit_hops(
                &guard.node_id,
                &[me, circuit.middle.node_id, circuit.exit.node_id],
                &[],
            )
            .or_else(|| dir.circuit_hops(&guard.node_id, &[me], &[circuit.exit.node_id]))
            .ok_or_else(|| {
                ClientError::network("返信トンネルを組めません（到達可能なリレーが足りません）")
            })?
        };

        let self_addr = self.node.descriptor.addr;
        let (tunnel, instructions) = InboundTunnel::build_to_builder(
            vec![gateway.addr, middle2.addr, guard.addr, self_addr],
            vec![
                gateway.x25519_pub,
                middle2.x25519_pub,
                guard.x25519_pub,
                self.node.descriptor.x25519_pub,
            ],
        )?;
        let [gw_build, mid_build, guard_build, self_build]: [(std::net::SocketAddr, Vec<u8>); 4] =
            instructions
                .try_into()
                .map_err(|_| ClientError::invalid("unexpected tunnel instruction count"))?;

        // ガード：自分の待ち受けと同じソケットから keepalive 付きで張り、その上で指示を渡す。
        // ガードは「この接続の相手」へ返信を届ける（next_hop = None）
        self.node.pin_connection(guard.addr).await?;
        self.node
            .send_direct(guard.addr, PacketType::TunnelBuild, &guard_build.1)
            .await?;
        // 自分の分はネットワークを通さない
        self.node.accept_own_tunnel_build(&self_build.1).await?;
        // 中間2・gateway：出口経由（自分の IP を見せない）
        circuit
            .client
            .send_onion_message_typed(PacketType::TunnelBuild, &mid_build.1, middle2.addr)
            .await?;
        circuit
            .client
            .send_onion_message_typed(PacketType::TunnelBuild, &gw_build.1, gateway.addr)
            .await?;

        let receive_tunnel_id = tunnel.receive_tunnel_id;
        let reply_to = tunnel.endpoint.clone();

        let mailbox = SchrodingerMailbox::with_directory(
            Arc::new(circuit.client),
            Arc::new(GossipClient::new(RelayClient::new()?)),
            Arc::new(Mutex::new(contacts)),
            self.node.directory(),
        );
        mailbox.register_inbound_tunnel(tunnel);

        tokio::time::sleep(TUNNEL_SETTLE).await;

        Ok(PullSession {
            mailbox,
            receive_tunnel_id,
            reply_to,
            gateway: gateway.addr,
        })
    }

    /// 自分宛てに届いた返信を取り出す（取り出したものは消える）
    pub(crate) async fn take_replies(&self, receive_tunnel_id: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
        Ok(self
            .node
            .mailbox()
            .fetch_tunnel_messages(receive_tunnel_id)
            .await?)
    }
}
