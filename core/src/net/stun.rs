//! STUN による外部アドレス発見
//!
//! # 必ず QUIC と同じソケットから撃つこと
//!
//! NAT は (内部ip:port, 外部ip:port) の対応を張るので、
//! **別ソケットで観測した外部アドレスは QUIC には使えない。**
//! [`StunResolver::resolve`] は独立ソケットを掘るため、
//! **自分の到達性を調べる用途には使ってはならない**（診断専用）。
//!
//! 広告用のアドレスを得るには [`StunResolver::resolve_on_shared`] を使う。

use crate::{Result, AetherError};
use crate::net::shared_socket::{SharedSocket, SideChannelDatagram};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
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

    /// **QUIC と同じソケットで**外部アドレスを解決する
    ///
    /// 得られたアドレスは、そのソケットに張られた NAT マッピングそのものなので、
    /// 広告してよい。punch のプローブも同じソケットから撃つこと。
    ///
    /// `side_rx` は [`SharedSocket`] が横取りした STUN 応答の受け口。
    pub async fn resolve_on_shared(
        &self,
        socket: &Arc<SharedSocket>,
        side_rx: &mut mpsc::UnboundedReceiver<SideChannelDatagram>,
    ) -> Result<SocketAddr> {
        for server in &self.stun_servers {
            match self.query_shared(socket, side_rx, server).await {
                Ok(addr) => return Ok(addr),
                Err(_) => continue,
            }
        }
        Err(AetherError::Network(std::io::Error::other("All STUN servers failed")))
    }

    async fn query_shared(
        &self,
        socket: &Arc<SharedSocket>,
        side_rx: &mut mpsc::UnboundedReceiver<SideChannelDatagram>,
        server: &str,
    ) -> Result<SocketAddr> {
        // v6 → v4（mapped）の順に試す。v4 だけの回線では v6 への送信が失敗するか応答が来ないので、
        // 1 つ目で諦めると、STUN サーバが AAAA を持つ限り外部アドレスを観測できなくなる
        let mut last_err = None;
        for server_addr in Self::server_addrs(server, socket.local_addr()?.is_ipv6()).await? {
            match Self::query_shared_addr(socket, side_rx, server_addr).await {
                Ok(addr) => return Ok(addr),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            AetherError::Network(std::io::Error::other(format!("No usable address for STUN server {}", server)))
        }))
    }

    async fn query_shared_addr(
        socket: &Arc<SharedSocket>,
        side_rx: &mut mpsc::UnboundedReceiver<SideChannelDatagram>,
        server_addr: SocketAddr,
    ) -> Result<SocketAddr> {
        let mut msg = Message::new();
        msg.build(&[
            Box::new(stun::message::BINDING_REQUEST),
            Box::new(TransactionId::default()),
        ])
        .map_err(|e| AetherError::Network(std::io::Error::other(e.to_string())))?;

        let sent_id = msg.transaction_id;

        socket
            .send_raw(server_addr, &msg.raw)
            .await
            .map_err(AetherError::Network)?;

        // 応答は SharedSocket が横取りして side channel に流してくる
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(AetherError::Network(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "STUN timeout",
                )));
            }

            let Ok(Some(datagram)) = tokio::time::timeout(remaining, side_rx.recv()).await else {
                continue;
            };

            let mut reply = Message::new();
            reply.raw = datagram.data;
            if reply.decode().is_err() {
                continue;
            }

            // 別のトランザクションの応答は無視する
            if reply.transaction_id != sent_id {
                continue;
            }

            let mut xor_addr = XorMappedAddress::default();
            xor_addr.get_from(&reply).map_err(|e| {
                AetherError::Network(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
            })?;

            // 両用ソケットで v4 のサーバへ撃つと、環境によって IPv4-mapped で
            // 観測されることがある。素の v4 に戻して他の箇所と揃える
            return Ok(crate::net::addr::normalize(SocketAddr::new(xor_addr.ip, xor_addr.port)));
        }
    }

    async fn server_addrs(server: &str, socket_is_ipv6: bool) -> Result<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(server)
            .await
            .map_err(AetherError::Network)?
            .collect();
        Ok(server_addr_candidates(&addrs, socket_is_ipv6))
    }


    /// 独立ソケットで問い合わせる（**診断専用**）
    ///
    /// ここで得たアドレスは別ソケットの NAT マッピングなので、
    /// **広告に使ってはならない。** 用途は「そもそも外部と喋れるか」の確認だけ。
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

/// STUN サーバの候補から、このソケットで撃てるアドレスを選ぶ
///
/// 待ち受けは v4・v6 両用なので `socket_is_ipv6` は事実上常に真になる。
/// サーバに AAAA が無くても観測できるよう、v6 が無ければ v4 を
/// IPv4-mapped にして撃つ。v4 だけのソケット（`0.0.0.0` に bind）では v4 だけ。
/// 試す順のアドレスの候補（v6 のもの → v4 を IPv4-mapped にしたもの）。v4 だけのソケットでは v4 だけ
fn server_addr_candidates(addrs: &[SocketAddr], socket_is_ipv6: bool) -> Vec<SocketAddr> {
    if !socket_is_ipv6 {
        return addrs.iter().filter(|a| a.is_ipv4()).copied().collect();
    }
    let v6 = addrs.iter().filter(|a| a.is_ipv6()).copied();
    let mapped = addrs.iter().filter_map(|a| match a {
        SocketAddr::V4(v4) => Some(SocketAddr::new(std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())),
        SocketAddr::V6(_) => None,
    });
    v6.chain(mapped).collect()
}

/// 一番目に試す候補（試験用）
#[cfg(test)]
fn pick_server_addr(addrs: &[SocketAddr], socket_is_ipv6: bool) -> Option<SocketAddr> {
    server_addr_candidates(addrs, socket_is_ipv6).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn dual_stack_socket_falls_back_to_mapped_ipv4_after_ipv6() {
        let addrs = [sa("192.0.2.1:3478"), sa("[2001:db8::1]:3478")];
        assert_eq!(
            server_addr_candidates(&addrs, true),
            vec![sa("[2001:db8::1]:3478"), sa("[::ffff:192.0.2.1]:3478")],
            "v4 だけの回線でも 2 つ目で観測できる"
        );
        assert_eq!(server_addr_candidates(&addrs, false), vec![sa("192.0.2.1:3478")]);
    }

    #[test]
    fn dual_stack_socket_prefers_ipv6_server() {
        let addrs = [sa("192.0.2.1:3478"), sa("[2001:db8::1]:3478")];
        assert_eq!(pick_server_addr(&addrs, true), Some(sa("[2001:db8::1]:3478")));
    }

    #[test]
    fn dual_stack_socket_maps_ipv4_only_server() {
        let addrs = [sa("192.0.2.1:3478")];
        let picked = pick_server_addr(&addrs, true).unwrap();
        assert!(picked.is_ipv6());
        assert_eq!(crate::net::addr::normalize(picked), sa("192.0.2.1:3478"));
    }

    #[test]
    fn ipv4_socket_uses_only_ipv4() {
        let addrs = [sa("[2001:db8::1]:3478"), sa("192.0.2.1:3478")];
        assert_eq!(pick_server_addr(&addrs, false), Some(sa("192.0.2.1:3478")));
        assert_eq!(pick_server_addr(&[sa("[2001:db8::1]:3478")], false), None);
    }

    use crate::net::shared_socket::SharedSocket;
    use quinn::default_runtime;

    /// STUN サーバの応答を模した最小のレスポンダ
    ///
    /// 受け取った Binding Request の transaction id をそのまま返し、
    /// XOR-MAPPED-ADDRESS に送信元を載せる。
    async fn fake_stun_server() -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                let mut req = Message::new();
                req.raw = buf[..len].to_vec();
                if req.decode().is_err() {
                    continue;
                }

                let mut resp = Message::new();
                resp.transaction_id = req.transaction_id;
                if resp
                    .build(&[
                        Box::new(stun::message::BINDING_SUCCESS),
                        Box::new(XorMappedAddress { ip: from.ip(), port: from.port() }),
                    ])
                    .is_err()
                {
                    continue;
                }
                let _ = socket.send_to(&resp.raw, from).await;
            }
        });

        addr
    }

    #[tokio::test]
    async fn resolves_the_mapping_of_the_quic_socket() {
        // ここが本質: 得られるアドレスは QUIC が使うソケットのマッピングであること。
        // 別ソケットの観測値を広告すると、そのアドレスには誰も繋げない。
        let server = fake_stun_server().await;

        let runtime = default_runtime().unwrap();
        let quic_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let quic_addr = quic_socket.local_addr().unwrap();

        let (shared, mut side_rx) = SharedSocket::from_std(quic_socket, &*runtime).unwrap();
        tokio::spawn(shared.clone().pump());

        let resolver = StunResolver::new(vec![server.to_string()]);
        let observed = resolver
            .resolve_on_shared(&shared, &mut side_rx)
            .await
            .expect("STUN 解決に失敗");

        assert_eq!(
            observed.port(),
            quic_addr.port(),
            "QUIC ソケットのマッピングになっていない。\
             別ソケットの観測値を広告しても誰も繋げない"
        );
    }

    #[tokio::test]
    async fn falls_through_to_the_next_server() {
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let alive = fake_stun_server().await;

        let runtime = default_runtime().unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (shared, mut side_rx) = SharedSocket::from_std(socket, &*runtime).unwrap();
        tokio::spawn(shared.clone().pump());

        let resolver = StunResolver::new(vec![dead.to_string(), alive.to_string()]);

        assert!(
            resolver.resolve_on_shared(&shared, &mut side_rx).await.is_ok(),
            "1台目が死んでいても2台目へ進むべき"
        );
    }

    #[tokio::test]
    async fn reports_failure_when_every_server_is_down() {
        let runtime = default_runtime().unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (shared, mut side_rx) = SharedSocket::from_std(socket, &*runtime).unwrap();

        let resolver = StunResolver::new(vec!["127.0.0.1:1".to_string()]);

        assert!(resolver.resolve_on_shared(&shared, &mut side_rx).await.is_err());
    }
}
