use serde::{Serialize, Deserialize};
use crate::error::{Result, AetherError};
// use bytes::{Bytes, BytesMut, Buf, BufMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::net::SocketAddr;
use crate::net::tunnel::TunnelEndpoint;

pub const MAGIC: u32 = 0xAE74E201;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[repr(u8)]
pub enum PacketType {
    // 0x00 Reserved
    Unknown = 0x00,

    // Onion Routing
    OnionPacket = 0x01,

    // Gossip
    GossipHint = 0x10,
    /// 複数 Hint を1パケットにまとめたもの (bincode Vec<HintPacket>)
    GossipHintBatch = 0x11,
    /// 分散 Hint backlog の差分同期要求。自分が持つ id 集合 (bincode HintDigest)
    HintDigest = 0x12,
    /// 上記への応答。相手が欠けている Hint 群 (bincode Vec<HintPacket>)。
    /// **live gossip とは違い再拡散しない** ── 追いつき用の一方向配送。
    HintBacklog = 0x13,

    // Mailbox
    MailboxPut = 0x20,
    MailboxGet = 0x21,
    MailboxResponse = 0x22,

    // Peer Exchange (0x4x)
    PexRequest = 0x40,
    PexResponse = 0x41,

    // NAT 越え (0x5x)
    PunchRequest = 0x50,
    PunchNotify = 0x51,
    /// 「一度も話していない相手から自分へ撃たせてほしい」
    FilterCheck = 0x52,
    /// 仲介役から第三者への「このアドレスへ1発」
    FilterProbeOrder = 0x53,

    // Tunnel (I2P-style)
    TunnelData = 0x30,
    TunnelBuild = 0x31,

    // Handshake (今後実装)
    Handshake = 0xF0,
}

/// Onion の最終層に包まれる「中身」の種別
///
/// これが無いと出口リレーは復号したペイロードを常に MailboxPut として扱うしかなく、
/// Hint を Onion 経由で流せない (Part 17.2.2 の `process_final_payload` 相当)。
///
/// ワイヤ形式: `[InnerPacketType(1)] [Payload...]`
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[repr(u8)]
pub enum InnerPacketType {
    /// Gossip ネットワークへ Hint を投入する
    GossipHint = 0x10,
    /// 出口リレー自身の Mailbox へ保存する
    MailboxPut = 0x20,
    /// 別ノードの Mailbox へ転送する
    ///
    /// ペイロード形式: `[bincode(SocketAddr)][MailboxPut ペイロード]`
    ///
    /// **出口リレーと Mailbox を別ノードにするために必要。**
    /// 両者が同一だと、Mailbox の位置が `H(mailbox_key ‖ K)` で決定論的に
    /// 決まる以上、攻撃者は Sybil で狙ったコンテンツの出口リレーになれる。
    /// 確率 f ではなく確定で取られるため、入口さえ引けば相関が成立してしまう。
    MailboxForward = 0x21,
    /// 任意の種別のパケットを別ノードへ転送する
    ///
    /// ペイロード形式: `[bincode(SocketAddr)][PacketType(1)][本体]`
    ///
    /// MailboxGet を送信元を隠したまま Mailbox に届けるために使う。
    TypedForward = 0x22,
}

impl InnerPacketType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x10 => Some(InnerPacketType::GossipHint),
            0x20 => Some(InnerPacketType::MailboxPut),
            0x21 => Some(InnerPacketType::MailboxForward),
            0x22 => Some(InnerPacketType::TypedForward),
            _ => None,
        }
    }
}

/// `MailboxForward` のペイロードを組み立てる
pub fn build_mailbox_forward(dest: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let addr_bytes = bincode::serialize(&dest)
        .map_err(|e| AetherError::Serialization(e.to_string()))?;

    let mut buf = Vec::with_capacity(1 + addr_bytes.len() + payload.len());
    buf.push(InnerPacketType::MailboxForward as u8);
    buf.extend_from_slice(&addr_bytes);
    buf.extend_from_slice(payload);
    Ok(buf)
}

/// `MailboxForward` のペイロードから宛先と本体を取り出す
///
/// 種別バイトは既に [`parse_inner_packet`] で剥がれている前提。
pub fn parse_mailbox_forward(body: &[u8]) -> Result<(SocketAddr, &[u8])> {
    let mut cursor = std::io::Cursor::new(body);
    let dest: SocketAddr = bincode::deserialize_from(&mut cursor)
        .map_err(|e| AetherError::Protocol(format!("Invalid forward address: {}", e)))?;

    let consumed = cursor.position() as usize;
    Ok((dest, &body[consumed..]))
}

/// `TypedForward` のペイロードを組み立てる
pub fn build_typed_forward(dest: SocketAddr, typed_body: &[u8]) -> Result<Vec<u8>> {
    let addr_bytes = bincode::serialize(&dest)
        .map_err(|e| AetherError::Serialization(e.to_string()))?;

    let mut buf = Vec::with_capacity(1 + addr_bytes.len() + typed_body.len());
    buf.push(InnerPacketType::TypedForward as u8);
    buf.extend_from_slice(&addr_bytes);
    buf.extend_from_slice(typed_body);
    Ok(buf)
}

/// `TypedForward` のペイロードから宛先・種別・本体を取り出す
pub fn parse_typed_forward(body: &[u8]) -> Result<(SocketAddr, PacketType, &[u8])> {
    let (dest, rest) = parse_mailbox_forward(body)?;

    let (type_byte, payload) = rest
        .split_first()
        .ok_or_else(|| AetherError::Protocol("TypedForward missing packet type".into()))?;

    let packet_type = match type_byte {
        0x20 => PacketType::MailboxPut,
        0x21 => PacketType::MailboxGet,
        0x10 => PacketType::GossipHint,
        0x11 => PacketType::GossipHintBatch,
        other => {
            return Err(AetherError::Protocol(format!(
                "TypedForward may not carry packet type 0x{:02x}",
                other
            )))
        }
    };

    Ok((dest, packet_type, payload))
}

/// `MailboxGet` のペイロードを組み立てる
///
/// 形式: `[Key(32)][bincode(TunnelEndpoint)]`
///
/// **返信先を要求側が同梱する。** uni-directional stream で受けているため
/// Mailbox 側から素直に返せず、また返せてしまうと要求者の IP が割れる。
/// Inbound Tunnel の Gateway 宛てに投げ返してもらう。
pub fn build_mailbox_get(key: &[u8; 32], reply_to: &TunnelEndpoint) -> Result<Vec<u8>> {
    let endpoint_bytes = bincode::serialize(reply_to)
        .map_err(|e| AetherError::Serialization(e.to_string()))?;

    let mut buf = Vec::with_capacity(32 + endpoint_bytes.len());
    buf.extend_from_slice(key);
    buf.extend_from_slice(&endpoint_bytes);
    Ok(buf)
}

/// `MailboxGet` のペイロードを分解する
pub fn parse_mailbox_get(payload: &[u8]) -> Result<([u8; 32], TunnelEndpoint)> {
    if payload.len() < 32 {
        return Err(AetherError::Protocol("MailboxGet payload too short".into()));
    }

    let key: [u8; 32] = payload[0..32].try_into().expect("長さ確認済み");
    let reply_to: TunnelEndpoint = bincode::deserialize(&payload[32..])
        .map_err(|e| AetherError::Protocol(format!("Invalid reply endpoint: {}", e)))?;

    Ok((key, reply_to))
}

/// Onion 最終層のペイロードを組み立てる
pub fn build_inner_packet(inner_type: InnerPacketType, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(inner_type as u8);
    buf.extend_from_slice(payload);
    buf
}

/// Onion 最終層のペイロードを分解する
pub fn parse_inner_packet(data: &[u8]) -> Result<(InnerPacketType, &[u8])> {
    let (first, rest) = data.split_first()
        .ok_or_else(|| AetherError::Protocol("Empty inner packet".into()))?;

    let inner_type = InnerPacketType::from_byte(*first)
        .ok_or_else(|| AetherError::Protocol(format!("Unknown inner packet type: 0x{:02x}", first)))?;

    Ok((inner_type, rest))
}

/// パケット受信ヘルパー
/// u32 (Length) + u8 (Type) + Payload を読み込む
pub async fn read_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(PacketType, Vec<u8>)> {
    // Length: u32 big-endian
    let len = reader.read_u32().await.map_err(AetherError::Network)? as usize;

    if len > 10 * 1024 * 1024 { // 10MB limit
         return Err(AetherError::Protocol("Packet too large".into()));
    }

    // Type: u8
    let type_byte = reader.read_u8().await.map_err(AetherError::Network)?;
    let packet_type = match type_byte {
        0x01 => PacketType::OnionPacket,
        0x10 => PacketType::GossipHint,
        0x11 => PacketType::GossipHintBatch,
        0x12 => PacketType::HintDigest,
        0x13 => PacketType::HintBacklog,
        0x20 => PacketType::MailboxPut,
        0x21 => PacketType::MailboxGet,
        0x22 => PacketType::MailboxResponse,
        0x50 => PacketType::PunchRequest,
        0x51 => PacketType::PunchNotify,
        0x52 => PacketType::FilterCheck,
        0x53 => PacketType::FilterProbeOrder,
        0x40 => PacketType::PexRequest,
        0x41 => PacketType::PexResponse,
        0x30 => PacketType::TunnelData,
        0x31 => PacketType::TunnelBuild,
        0xF0 => PacketType::Handshake,
        _ => PacketType::Unknown,
    };

    // Payload
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await.map_err(AetherError::Network)?;

    Ok((packet_type, payload))
}

/// パケット送信ヘルパー
pub async fn write_packet<W: AsyncWrite + Unpin>(writer: &mut W, packet_type: PacketType, payload: &[u8]) -> Result<()> {
    // Length: Payloadの長さ (Type byte含まず、Payloadのみの長さとする)
    let len = payload.len() as u32;
    writer.write_u32(len).await.map_err(AetherError::Network)?;

    // Type
    let type_byte = packet_type as u8;
    writer.write_u8(type_byte).await.map_err(AetherError::Network)?;

    // Payload
    writer.write_all(payload).await.map_err(AetherError::Network)?;

    Ok(())
}
