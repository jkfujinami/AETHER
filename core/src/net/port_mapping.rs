//! ルータにポートを開けさせる (PCP / NAT-PMP)
//!
//! # なぜ最初に試すのか
//!
//! **成功すれば本物の開放ポートが手に入り、hole punching が不要になる。**
//! 見知らぬ相手からの inbound を受けられる = 完全な到達性。
//!
//! punch は「調整済みの相手」としか繋がらないので、
//! ポートマッピングが通る環境ではそちらが圧倒的に強い。
//! BitTorrent クライアントが軒並みこれを実装しているのも同じ理由。
//!
//! # PCP と NAT-PMP は同じ 5351 番
//!
//! - **PCP** (RFC 6887) — 新しい。バージョン 2
//! - **NAT-PMP** (RFC 6886) — 古い。バージョン 0。対応機器が多い
//!
//! 宛先ポートが同じなので、**PCP を先に投げて駄目なら NAT-PMP** という
//! 順序で1つの実装から両方試せる。PCP 対応機は NAT-PMP も解釈する。
//!
//! # 残る痕跡（判断材料）
//!
//! マッピングは**ルータのリース表に残る**。残るのは
//! 「内部IP:ポート → 外部ポート」だけでソフト名は書かれないが、
//! 再起動を跨いで残る機種があり、消えない痕跡ではある。
//! IPv6 や punch にはこの痕跡がないので、既定オフのオプトインが妥当。

use crate::error::{AetherError, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

/// PCP / NAT-PMP の待ち受けポート
pub const MAPPING_PORT: u16 = 5351;

/// 1回の問い合わせを諦めるまでの時間
const REQUEST_TIMEOUT: Duration = Duration::from_millis(500);

/// 再送回数
///
/// UDP なので落ちることがある。RFC は指数バックオフを求めているが、
/// 「対応していないルータ」を素早く見切りたいので回数を絞る。
const ATTEMPTS: usize = 3;

/// 要求する既定のリース期間
///
/// 短すぎると更新が頻繁になり、長すぎるとルータが拒否することがある。
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(3600);

/// どちらの規格で成功したか
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingProtocol {
    Pcp,
    NatPmp,
}

/// 獲得したマッピング
#[derive(Debug, Clone)]
pub struct PortMapping {
    /// 外部から到達できるポート
    pub external_port: u16,
    /// PCP が返した外部 IP（NAT-PMP は返さないので `None`）
    pub external_ip: Option<IpAddr>,
    /// 有効期間。**この半分が経つ前に更新すること**
    pub lifetime: Duration,
    pub protocol: MappingProtocol,
}

impl PortMapping {
    /// 更新をかけるべき間隔
    ///
    /// リース切れの瞬間に到達性を失うので、余裕を持って半分で更新する。
    pub fn renew_after(&self) -> Duration {
        self.lifetime / 2
    }
}

pub struct PortMapper {
    gateway: SocketAddr,
}

impl PortMapper {
    pub fn new(gateway_ip: IpAddr) -> Self {
        Self {
            gateway: SocketAddr::new(gateway_ip, MAPPING_PORT),
        }
    }

    /// 既定ゲートウェイを推定して作る
    ///
    /// **推定なので外れることがある。** 判明している場合は
    /// [`PortMapper::new`] で明示すること。
    pub fn discover() -> Option<Self> {
        discover_gateway().map(Self::new)
    }

    pub fn gateway(&self) -> SocketAddr {
        self.gateway
    }

    /// ポートを開けさせる
    ///
    /// **PCP を先に試し、駄目なら NAT-PMP へ落ちる。**
    pub async fn request_mapping(
        &self,
        internal_port: u16,
        lifetime: Duration,
    ) -> Result<PortMapping> {
        let socket = UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
        ))
        .await
        .map_err(AetherError::Network)?;

        let local_ip = self.local_ip_towards_gateway(&socket).await?;

        if let Ok(mapping) = self
            .try_pcp(&socket, local_ip, internal_port, lifetime)
            .await
        {
            return Ok(mapping);
        }

        self.try_natpmp(&socket, internal_port, lifetime).await
    }

    /// マッピングを解放する（リース期間 0 で要求）
    ///
    /// 明示的に消しておくと、ルータのリース表に残る時間を短くできる。
    pub async fn release(&self, internal_port: u16) -> Result<()> {
        self.request_mapping(internal_port, Duration::ZERO)
            .await
            .map(|_| ())
    }

    async fn local_ip_towards_gateway(&self, socket: &UdpSocket) -> Result<Ipv4Addr> {
        // connect は実際にはパケットを送らないが、
        // どのインタフェースを使うかをカーネルに決めさせられる
        socket
            .connect(self.gateway)
            .await
            .map_err(AetherError::Network)?;

        match socket.local_addr().map_err(AetherError::Network)?.ip() {
            IpAddr::V4(v4) => Ok(v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped().ok_or_else(|| {
                AetherError::Config("Port mapping requires an IPv4 interface".into())
            }),
        }
    }

    async fn exchange(&self, socket: &UdpSocket, request: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 1100];

        for _ in 0..ATTEMPTS {
            if socket.send(request).await.is_err() {
                continue;
            }

            match tokio::time::timeout(REQUEST_TIMEOUT, socket.recv(&mut buf)).await {
                Ok(Ok(len)) => return Ok(buf[..len].to_vec()),
                _ => continue,
            }
        }

        Err(AetherError::Network(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "No response from gateway",
        )))
    }

    // ---- PCP (RFC 6887) ----

    async fn try_pcp(
        &self,
        socket: &UdpSocket,
        local_ip: Ipv4Addr,
        internal_port: u16,
        lifetime: Duration,
    ) -> Result<PortMapping> {
        let nonce: [u8; 12] = rand::random();
        let request = build_pcp_map_request(local_ip, internal_port, lifetime, &nonce);

        let response = self.exchange(socket, &request).await?;
        parse_pcp_map_response(&response, &nonce)
    }

    // ---- NAT-PMP (RFC 6886) ----

    async fn try_natpmp(
        &self,
        socket: &UdpSocket,
        internal_port: u16,
        lifetime: Duration,
    ) -> Result<PortMapping> {
        let request = build_natpmp_map_request(internal_port, lifetime);
        let response = self.exchange(socket, &request).await?;
        parse_natpmp_map_response(&response, internal_port)
    }
}

/// PCP MAP 要求を組み立てる
///
/// ヘッダ 24 バイト + MAP オペコード部 36 バイト = 60 バイト
pub fn build_pcp_map_request(
    local_ip: Ipv4Addr,
    internal_port: u16,
    lifetime: Duration,
    nonce: &[u8; 12],
) -> Vec<u8> {
    let mut req = Vec::with_capacity(60);

    // --- 共通ヘッダ (24 bytes) ---
    req.push(2); // Version = 2
    req.push(1); // R=0 (request) | Opcode=1 (MAP)
    req.extend_from_slice(&[0, 0]); // Reserved
    req.extend_from_slice(&(lifetime.as_secs() as u32).to_be_bytes());
    // クライアント IP は 128bit。v4 は IPv4-mapped で入れる
    req.extend_from_slice(&local_ip.to_ipv6_mapped().octets());

    // --- MAP オペコード部 (36 bytes) ---
    req.extend_from_slice(nonce);
    req.push(17); // Protocol = UDP
    req.extend_from_slice(&[0, 0, 0]); // Reserved
    req.extend_from_slice(&internal_port.to_be_bytes());
    req.extend_from_slice(&internal_port.to_be_bytes()); // 希望する外部ポート
    req.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets()); // 希望する外部 IP: 任せる

    req
}

/// PCP MAP 応答を解釈する
pub fn parse_pcp_map_response(data: &[u8], expected_nonce: &[u8; 12]) -> Result<PortMapping> {
    if data.len() < 60 {
        return Err(AetherError::Protocol("PCP response too short".into()));
    }
    if data[0] != 2 {
        return Err(AetherError::Protocol(format!(
            "Not a PCP response (version {})",
            data[0]
        )));
    }
    // R ビットが立っていなければ応答ではない
    if data[1] & 0x80 == 0 {
        return Err(AetherError::Protocol("PCP response bit not set".into()));
    }

    let result_code = data[3];
    if result_code != 0 {
        return Err(AetherError::Protocol(format!(
            "PCP request rejected (result code {})",
            result_code
        )));
    }

    let lifetime = u32::from_be_bytes(data[4..8].try_into().expect("長さ確認済み"));

    // オペコード部は 24 バイト目から
    let nonce = &data[24..36];
    if nonce != expected_nonce {
        // 別の要求への応答。取り違えるとポートを誤認する
        return Err(AetherError::Protocol("PCP nonce mismatch".into()));
    }

    let external_port = u16::from_be_bytes(data[42..44].try_into().expect("長さ確認済み"));
    let ip_bytes: [u8; 16] = data[44..60].try_into().expect("長さ確認済み");
    let external_ip = Ipv6Addr::from(ip_bytes);

    Ok(PortMapping {
        external_port,
        external_ip: Some(match external_ip.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(external_ip),
        }),
        lifetime: Duration::from_secs(u64::from(lifetime)),
        protocol: MappingProtocol::Pcp,
    })
}

/// NAT-PMP マッピング要求を組み立てる（12 バイト）
pub fn build_natpmp_map_request(internal_port: u16, lifetime: Duration) -> Vec<u8> {
    let mut req = Vec::with_capacity(12);

    req.push(0); // Version = 0
    req.push(1); // OP = 1 (UDP mapping)
    req.extend_from_slice(&[0, 0]); // Reserved
    req.extend_from_slice(&internal_port.to_be_bytes());
    req.extend_from_slice(&internal_port.to_be_bytes()); // 希望する外部ポート
    req.extend_from_slice(&(lifetime.as_secs() as u32).to_be_bytes());

    req
}

/// NAT-PMP 応答を解釈する（16 バイト）
pub fn parse_natpmp_map_response(data: &[u8], internal_port: u16) -> Result<PortMapping> {
    if data.len() < 16 {
        return Err(AetherError::Protocol("NAT-PMP response too short".into()));
    }
    if data[0] != 0 {
        return Err(AetherError::Protocol(format!(
            "Not a NAT-PMP response (version {})",
            data[0]
        )));
    }
    // 応答は OP に 128 を足したもの
    if data[1] != 129 {
        return Err(AetherError::Protocol(format!(
            "Unexpected NAT-PMP opcode {}",
            data[1]
        )));
    }

    let result_code = u16::from_be_bytes(data[2..4].try_into().expect("長さ確認済み"));
    if result_code != 0 {
        return Err(AetherError::Protocol(format!(
            "NAT-PMP request rejected (result code {})",
            result_code
        )));
    }

    let echoed_internal = u16::from_be_bytes(data[8..10].try_into().expect("長さ確認済み"));
    if echoed_internal != internal_port {
        return Err(AetherError::Protocol(
            "NAT-PMP response is for a different internal port".into(),
        ));
    }

    let external_port = u16::from_be_bytes(data[10..12].try_into().expect("長さ確認済み"));
    let lifetime = u32::from_be_bytes(data[12..16].try_into().expect("長さ確認済み"));

    Ok(PortMapping {
        external_port,
        // NAT-PMP のマッピング応答は外部 IP を返さない（別オペコードが必要）
        external_ip: None,
        lifetime: Duration::from_secs(u64::from(lifetime)),
        protocol: MappingProtocol::NatPmp,
    })
}

/// 既定ゲートウェイを推定する
///
/// **推定であって確定ではない。** 外部への経路に使われるインタフェースの
/// アドレスを調べ、その `.1` をゲートウェイと見なす。
/// 家庭用ルータではほぼ当たるが、外れる構成もある。
pub fn discover_gateway() -> Option<IpAddr> {
    // 実際にはパケットを送らない。経路選択だけカーネルにさせる
    let probe = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    probe.connect((Ipv4Addr::new(203, 0, 113, 1), 9)).ok()?;

    match probe.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], 1)))
        }
        IpAddr::V6(_) => None, // v6 なら NAT が無いのでマッピング自体が不要
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcp_success_response(nonce: &[u8; 12], external_port: u16, lifetime: u32) -> Vec<u8> {
        let mut resp = vec![0u8; 60];
        resp[0] = 2; // Version
        resp[1] = 0x80 | 1; // R=1 | MAP
        resp[3] = 0; // result = SUCCESS
        resp[4..8].copy_from_slice(&lifetime.to_be_bytes());
        resp[24..36].copy_from_slice(nonce);
        resp[36] = 17; // UDP
        resp[40..42].copy_from_slice(&9000u16.to_be_bytes()); // internal
        resp[42..44].copy_from_slice(&external_port.to_be_bytes());
        resp[44..60].copy_from_slice(&Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped().octets());
        resp
    }

    fn natpmp_success_response(internal: u16, external: u16, lifetime: u32) -> Vec<u8> {
        let mut resp = vec![0u8; 16];
        resp[0] = 0; // Version
        resp[1] = 129; // 128 + OP 1
        resp[2..4].copy_from_slice(&0u16.to_be_bytes()); // result = success
        resp[4..8].copy_from_slice(&12345u32.to_be_bytes()); // epoch
        resp[8..10].copy_from_slice(&internal.to_be_bytes());
        resp[10..12].copy_from_slice(&external.to_be_bytes());
        resp[12..16].copy_from_slice(&lifetime.to_be_bytes());
        resp
    }

    #[test]
    fn pcp_request_has_the_expected_shape() {
        let nonce = [0xAAu8; 12];
        let req = build_pcp_map_request(
            Ipv4Addr::new(192, 168, 1, 50),
            9000,
            Duration::from_secs(3600),
            &nonce,
        );

        assert_eq!(req.len(), 60, "PCP MAP 要求は 24 + 36 バイト");
        assert_eq!(req[0], 2, "Version = 2");
        assert_eq!(req[1], 1, "R=0 | Opcode=MAP");
        assert_eq!(&req[4..8], &3600u32.to_be_bytes());
        assert_eq!(&req[24..36], &nonce, "nonce が入っていない");
        assert_eq!(req[36], 17, "Protocol = UDP");
        assert_eq!(&req[40..42], &9000u16.to_be_bytes());
    }

    #[test]
    fn natpmp_request_has_the_expected_shape() {
        let req = build_natpmp_map_request(9000, Duration::from_secs(7200));

        assert_eq!(req.len(), 12, "NAT-PMP マッピング要求は 12 バイト");
        assert_eq!(req[0], 0, "Version = 0");
        assert_eq!(req[1], 1, "OP = UDP mapping");
        assert_eq!(&req[4..6], &9000u16.to_be_bytes());
        assert_eq!(&req[8..12], &7200u32.to_be_bytes());
    }

    #[test]
    fn parses_pcp_success() {
        let nonce = [0x5Au8; 12];
        let resp = pcp_success_response(&nonce, 41234, 1800);

        let mapping = parse_pcp_map_response(&resp, &nonce).unwrap();

        assert_eq!(mapping.external_port, 41234);
        assert_eq!(mapping.protocol, MappingProtocol::Pcp);
        assert_eq!(mapping.lifetime, Duration::from_secs(1800));
        assert_eq!(
            mapping.external_ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
        );
    }

    #[test]
    fn rejects_pcp_response_with_wrong_nonce() {
        // 取り違えると、開いていないポートを開いたと誤認する
        let resp = pcp_success_response(&[0x11u8; 12], 41234, 1800);
        assert!(parse_pcp_map_response(&resp, &[0x22u8; 12]).is_err());
    }

    #[test]
    fn rejects_pcp_error_result() {
        let nonce = [0x5Au8; 12];
        let mut resp = pcp_success_response(&nonce, 41234, 1800);
        resp[3] = 2; // NOT_AUTHORIZED
        assert!(parse_pcp_map_response(&resp, &nonce).is_err());
    }

    #[test]
    fn rejects_pcp_request_echoed_back() {
        // R ビットが立っていないものは応答ではない
        let nonce = [0x5Au8; 12];
        let mut resp = pcp_success_response(&nonce, 41234, 1800);
        resp[1] = 1; // R=0
        assert!(parse_pcp_map_response(&resp, &nonce).is_err());
    }

    #[test]
    fn parses_natpmp_success() {
        let resp = natpmp_success_response(9000, 41234, 3600);
        let mapping = parse_natpmp_map_response(&resp, 9000).unwrap();

        assert_eq!(mapping.external_port, 41234);
        assert_eq!(mapping.protocol, MappingProtocol::NatPmp);
        assert_eq!(mapping.lifetime, Duration::from_secs(3600));
        assert_eq!(mapping.external_ip, None, "NAT-PMP は外部 IP を返さない");
    }

    #[test]
    fn rejects_natpmp_response_for_another_port() {
        let resp = natpmp_success_response(8080, 41234, 3600);
        assert!(
            parse_natpmp_map_response(&resp, 9000).is_err(),
            "別ポートへの応答を受け入れてはならない"
        );
    }

    #[test]
    fn rejects_natpmp_error_result() {
        let mut resp = natpmp_success_response(9000, 41234, 3600);
        resp[2..4].copy_from_slice(&3u16.to_be_bytes()); // Network Failure
        assert!(parse_natpmp_map_response(&resp, 9000).is_err());
    }

    #[test]
    fn renews_at_half_the_lifetime() {
        // リース切れの瞬間に到達性を失うので余裕を持って更新する
        let mapping = PortMapping {
            external_port: 1,
            external_ip: None,
            lifetime: Duration::from_secs(3600),
            protocol: MappingProtocol::NatPmp,
        };
        assert_eq!(mapping.renew_after(), Duration::from_secs(1800));
    }

    /// PCP を無視して NAT-PMP だけ答える「古いルータ」
    async fn legacy_gateway() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 1100];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                // バージョン 0 (NAT-PMP) にだけ答える
                if len >= 12 && buf[0] == 0 {
                    let internal = u16::from_be_bytes(buf[4..6].try_into().unwrap());
                    let resp = natpmp_success_response(internal, 41234, 3600);
                    let _ = socket.send_to(&resp, from).await;
                }
            }
        });

        addr
    }

    #[tokio::test]
    async fn falls_back_to_natpmp_when_pcp_is_ignored() {
        // PCP 非対応の古いルータでも NAT-PMP で通ること
        let gateway = legacy_gateway().await;

        let mapper = PortMapper {
            gateway,
        };

        let mapping = mapper
            .request_mapping(9000, Duration::from_secs(3600))
            .await
            .expect("NAT-PMP へフォールバックできていない");

        assert_eq!(mapping.protocol, MappingProtocol::NatPmp);
        assert_eq!(mapping.external_port, 41234);
    }

    #[tokio::test]
    async fn reports_failure_when_the_gateway_is_silent() {
        // マッピング非対応の環境を素早く見切れること
        let mapper = PortMapper::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        let started = std::time::Instant::now();
        let result = mapper.request_mapping(9000, DEFAULT_LIFETIME).await;

        assert!(result.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "非対応ルータの見切りが遅い: {:?}",
            started.elapsed()
        );
    }
}
