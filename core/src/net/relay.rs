use crate::error::{Result, AetherError};
use crate::net::quic::{QuicClient, QuicConnection};
use crate::net::connection_pool::ConnectionPool;
use crate::protocol::wire::{self, InnerPacketType, PacketType};
use crate::net::onion::OnionCircuit;
use crate::net::guard::{Guard, GuardCandidate, GuardSet, GUARD_SAMPLE_SIZE};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// ガード1本への接続を諦めるまでの時間
const GUARD_CONNECT_TIMEOUT: Duration = Duration::from_secs(6);

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
    ///
    /// 入口の選択は本来 [`connect_guard`] に任せること。
    /// 毎回ランダムな入口へ繋ぐと、攻撃者のリレー占有率 f に対して
    /// 「生涯に一度でも敵の入口を引く」確率が 1 に収束する。
    pub async fn connect_entry(&mut self, addr: SocketAddr) -> Result<()> {
        // サーバー名は証明書検証をスキップしているので何でも良いが、将来的に重要
        let conn = self.quic_client.connect(addr).await?;
        self.entry_connection = Some(conn);
        Ok(())
    }

    /// 永続化されたガードを入口として接続する
    ///
    /// `guards` は呼び出し側が [`GuardSet::load`] で復元したもの。
    /// 標本が足りなければ `candidates` から補充し、結果を `path` へ書き戻す。
    ///
    /// **成否を必ず `GuardSet` に記録して永続化すること。**
    /// 記録しないと起動のたびに実質再抽選となり、ガード方式が無意味になる。
    pub async fn connect_guard(
        &mut self,
        guards: &mut GuardSet,
        candidates: &[GuardCandidate],
        path: &Path,
    ) -> Result<Guard> {
        let now = crate::protocol::hint::current_timestamp();
        guards.replenish(candidates, now);

        let mut last_err = None;

        // 標本を順に試す。1本目が落ちていても、すぐ再抽選はしない
        for _ in 0..GUARD_SAMPLE_SIZE {
            let Some(guard) = guards.current(now).cloned() else {
                break;
            };

            // 死んだガードで QUIC のタイムアウトまで固まらないよう頭打ちにする。
            // 打ち切りも失敗として記録しないと、標本内の次へ進めない。
            let attempt = tokio::time::timeout(GUARD_CONNECT_TIMEOUT, self.connect_entry(guard.addr));
            match attempt.await {
                Ok(Ok(())) => {
                    guards.record_success(&guard.node_id);
                    guards.save(path)?;
                    return Ok(guard);
                }
                Ok(Err(e)) => {
                    guards.record_failure(&guard.node_id);
                    last_err = Some(e);
                }
                Err(_) => {
                    guards.record_failure(&guard.node_id);
                    last_err = Some(AetherError::Config(format!(
                        "Guard {} timed out",
                        guard.addr
                    )));
                }
            }
        }

        guards.save(path)?;
        Err(last_err.unwrap_or_else(|| {
            AetherError::Config("No usable guard available".into())
        }))
    }

    /// 回路を手動で設定（テスト用・デバッグ用）
    pub fn set_circuit(&mut self, circuit: OnionCircuit) {
        self.circuit = Some(circuit);
    }

    /// 接続済みの入口から始まる経路で回路を組む
    ///
    /// `hops` は入口（接続済みのガード）から出口までの `(アドレス, X25519 公開鍵)`。
    /// 一時鍵はパケットごとに作り直す（[`OnionCircuit::wrap_packet`]）。
    pub fn set_path(&mut self, hops: &[(SocketAddr, [u8; 32])]) -> Result<()> {
        let mut circuit = OnionCircuit::new();
        for (addr, pubkey) in hops {
            circuit.add_hop(*addr, *pubkey)?;
        }
        self.circuit = Some(circuit);
        Ok(())
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
        let conn = self.connection_pool.get_connection(addr).await?;
        let mut stream = conn.open_uni().await.map_err(|e| AetherError::Quic(e.to_string()))?;
        wire::write_packet(&mut stream, packet_type, payload).await?;
        stream.finish().map_err(|e| AetherError::Quic(e.to_string()))?;

        // Connection Pool が接続を保持するため、sleep 不要
        Ok(())
    }

    /// Mailbox へ本体を送る (Onion 経由)
    ///
    /// **出口リレーは `mailbox` へ転送するだけで、自分では保存しない。**
    /// 出口と Mailbox が同一だと、Mailbox の位置が `H(mailbox_key ‖ K)` で
    /// 決定論的に決まる以上、攻撃者は Sybil 配置で狙ったコンテンツの
    /// 出口リレーになれてしまう（確率 f ではなく確定）。
    pub async fn send_onion_message(&self, message: &[u8], mailbox: SocketAddr) -> Result<()> {
        let inner = wire::build_mailbox_forward(mailbox, message)?;
        self.send_onion_raw(&inner).await
    }

    /// 任意の PacketType を出口リレー経由で `dest` へ届ける
    ///
    /// 出口リレーは中身を解釈せず、そのまま `dest` へ転送する。
    /// MailboxGet のように「Mailbox に届けたいが送信元を隠したい」要求に使う。
    pub async fn send_onion_message_typed(
        &self,
        packet_type: PacketType,
        message: &[u8],
        dest: SocketAddr,
    ) -> Result<()> {
        // MailboxForward は MailboxPut を前提とするため、
        // 他の種別は種別バイトを前置してから転送させる
        let mut body = Vec::with_capacity(1 + message.len());
        body.push(packet_type as u8);
        body.extend_from_slice(message);

        let inner = wire::build_typed_forward(dest, &body)?;
        self.send_onion_raw(&inner).await
    }

    /// 種別を指定して Onion Packet を送信する
    ///
    /// 出口リレーは `inner_type` を見て転送先モジュールを決める。
    pub async fn send_onion_inner(
        &self,
        inner_type: InnerPacketType,
        message: &[u8],
    ) -> Result<()> {
        self.send_onion_raw(&wire::build_inner_packet(inner_type, message)).await
    }

    /// 組み立て済みの inner packet を Onion で包んで送る
    async fn send_onion_raw(&self, inner: &[u8]) -> Result<()> {
        let circuit = self.circuit.as_ref()
            .ok_or(AetherError::Config("No circuit established".into()))?;

        let packet = circuit.wrap_packet(inner)?;
        self.send_raw_packet(PacketType::OnionPacket, &packet).await
    }

    /// Onion 回路が確立済みか
    pub fn has_circuit(&self) -> bool {
        self.circuit.is_some()
    }

    /// Entryへのコネクションを取得（テスト等で直接操作したい場合用）
    pub fn entry_connection(&self) -> Option<&QuicConnection> {
        self.entry_connection.as_ref()
    }
}
