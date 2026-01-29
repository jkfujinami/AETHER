use serde::{Serialize, Deserialize};
use crate::error::{Result, AetherError};
// use bytes::{Bytes, BytesMut, Buf, BufMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

    // Mailbox
    MailboxPut = 0x20,
    MailboxGet = 0x21,
    MailboxResponse = 0x22,

    // Tunnel (I2P-style)
    TunnelData = 0x30,
    TunnelBuild = 0x31,

    // Handshake (今後実装)
    Handshake = 0xF0,
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
        0x20 => PacketType::MailboxPut,
        0x21 => PacketType::MailboxGet,
        0x22 => PacketType::MailboxResponse,
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
