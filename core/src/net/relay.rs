use crate::error::{Result, AetherError};
use crate::net::quic::{QuicClient, QuicConnection};
use crate::net::connection_pool::ConnectionPool;
use crate::protocol::wire::{self, PacketType};
use crate::net::onion::OnionCircuit;
use std::net::SocketAddr;
use std::sync::Arc;


pub struct RelayClient {
    quic_client: Arc<QuicClient>,
    connection_pool: ConnectionPool,
    entry_connection: Option<QuicConnection>,
    circuit: Option<OnionCircuit>,
    // circuit_id: u32, // unused for now
}

impl RelayClient {
    pub fn new() -> Result<Self> {
        let quic_client = Arc::new(QuicClient::new()?);
        let connection_pool = ConnectionPool::new(quic_client.clone());
        Ok(Self {
            quic_client,
            connection_pool,
            entry_connection: None,
            circuit: None,
            // circuit_id: 1,
        })
    }

    /// 入口リレーに接続
    pub async fn connect_entry(&mut self, addr: SocketAddr) -> Result<()> {
        // サーバー名は証明書検証をスキップしているので何でも良いが、将来的に重要
        let conn = self.quic_client.connect(addr, "aether-relay").await?;
        self.entry_connection = Some(conn);
        Ok(())
    }

    /// 回路を手動で設定（テスト用・デバッグ用）
    pub fn set_circuit(&mut self, circuit: OnionCircuit) {
        self.circuit = Some(circuit);
    }

    /// 汎用パケット送信
    /// 指定されたタイプとペイロードでパケットを作成し、Entryノードへ送信する
    pub async fn send_raw_packet(&self, packet_type: PacketType, payload: &[u8]) -> Result<()> {
        let conn = self.entry_connection.as_ref()
            .ok_or(AetherError::Network(std::io::Error::new(std::io::ErrorKind::NotConnected, "No entry connection")))?;

        let mut send_stream = conn.open_uni().await
            .map_err(|e| AetherError::Quic(e.to_string()))?;

        wire::write_packet(&mut send_stream, packet_type, payload).await?;

        send_stream.finish()
            .map_err(|e| AetherError::Quic(e.to_string()))?;

        Ok(())
    }

    /// 特定のアドレスに直接パケットを送信する (Tunnel構築など)
    pub async fn send_direct_packet(&self, addr: SocketAddr, packet_type: PacketType, payload: &[u8]) -> Result<()> {
        // Connection Pool から接続を取得
        let conn = self.connection_pool.get_connection(addr, "aether-node").await?;
        let mut stream = conn.open_uni().await.map_err(|e| AetherError::Quic(e.to_string()))?;
        wire::write_packet(&mut stream, packet_type, payload).await?;
        stream.finish().map_err(|e| AetherError::Quic(e.to_string()))?;

        // Connection Pool が接続を保持するため、sleep 不要
        Ok(())
    }

    /// Onion Packet を送信 (Uni-directional Stream)
    /// メッセージは Onion ルーティングされて final_dest に届く
    pub async fn send_onion_message(&self, message: &[u8], final_dest: SocketAddr) -> Result<()> {
        let circuit = self.circuit.as_ref()
            .ok_or(AetherError::Config("No circuit established".into()))?;

        // Onion Packet 作成 (Wrap)
        let packet = circuit.wrap_packet(message, final_dest)?;

        // Raw Packet送信
        self.send_raw_packet(PacketType::OnionPacket, &packet).await
    }

    /// Entryへのコネクションを取得（テスト等で直接操作したい場合用）
    pub fn entry_connection(&self) -> Option<&QuicConnection> {
        self.entry_connection.as_ref()
    }
}
