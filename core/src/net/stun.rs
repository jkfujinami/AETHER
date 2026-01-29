use crate::{Result, AetherError};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use stun::message::{Message, Getter};
use stun::agent::TransactionId;
use stun::xoraddr::XorMappedAddress;


pub struct StunResolver {
    stun_servers: Vec<String>,
}

impl StunResolver {
    pub fn new(stun_servers: Vec<String>) -> Self {
        Self { stun_servers }
    }

    /// STUNサーバーに問い合わせて、自身のグローバルIPアドレスを取得する
    /// 新しいソケットを作成し、解決後に破棄する
    pub async fn resolve(&self) -> Result<SocketAddr> {
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(AetherError::Network)?;
        self.resolve_with_socket(&socket).await
    }

    /// 既存のソケットを使用してSTUN解決を行う
    /// ソケットはこのメソッド内で借用されるだけなので、後で再利用可能
    pub async fn resolve_with_socket(&self, socket: &UdpSocket) -> Result<SocketAddr> {
         // ソケットをArc化しないと並列実行できないが、ここでは直列で試行する
         // UdpSocketのsend_to/recv_fromは&selfでいける

         for server_addr_str in &self.stun_servers {
            match self.resolve_one(socket, server_addr_str).await {
                Ok(addr) => return Ok(addr),
                Err(_e) => {
                    // eprintln!("STUN failed for {}: {}", server_addr_str, e);
                    continue;
                }
            }
        }

        Err(AetherError::Network(std::io::Error::other("All STUN servers failed")))
    }

    async fn resolve_one(&self, socket: &UdpSocket, server_addr_str: &str) -> Result<SocketAddr> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(server_addr_str)
            .await
            .map_err(AetherError::Network)?
            .collect();

        let server_addr = addrs.iter()
            .find(|a| a.is_ipv4())
            .ok_or_else(|| AetherError::Network(std::io::Error::new(std::io::ErrorKind::InvalidInput, "No IPv4 address for STUN server")))?;

        // メッセージ構築
        let mut msg = Message::new();
        msg.build(&[
            Box::new(stun::message::BINDING_REQUEST),
            Box::new(TransactionId::default()),
        ]).map_err(|e| AetherError::Network(std::io::Error::other(e.to_string())))?;

        socket.send_to(&msg.raw, server_addr).await.map_err(AetherError::Network)?;

        let mut buf = vec![0u8; 1024];
        let (len, _addr) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf)
        ).await
        .map_err(|_| AetherError::Network(std::io::Error::new(std::io::ErrorKind::TimedOut, "STUN timeout")))?
        .map_err(AetherError::Network)?;

        // メッセージパース
        let mut msg = Message::new();
        msg.raw = buf[..len].to_vec();
        msg.decode().map_err(|e| AetherError::Network(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())))?;

        let mut xor_addr = XorMappedAddress::default();
        xor_addr.get_from(&msg).map_err(|e| AetherError::Network(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())))?;

        Ok(SocketAddr::new(xor_addr.ip, xor_addr.port))
    }
}
