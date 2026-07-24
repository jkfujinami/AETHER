//! 到達性の判定 — 「自分は何になれるか」を決める
//!
//! # 梯子
//!
//! 上ほど安くて強い。成功したところで打ち切る。
//!
//! ```text
//! 1. IPv6 が使える              → NAT が存在しない。Tier 0
//! 2. PCP / NAT-PMP が通る       → 本物の開放ポート。Tier 0
//! 3. **EIM かつ EIF**           → 送っていない相手からも入れる。**Tier 0**
//! 4. EIM だがフィルタ制限あり    → 調整付き punch で届く。Tier 1
//! 5. EDM (symmetric)            → punch 不可。Tier 2
//! ```
//!
//! # マッピングとフィルタは別の軸
//!
//! ```text
//! マッピング : 宛先ごとに外部ポートが変わるか  → EIM / EDM
//! フィルタ   : 送っていない相手からも入れるか  → EIF / 制限あり
//! ```
//!
//! **EIM を一律 Tier 1 にすると、本来 punch 不要で完全到達可能な
//! ノード（EIM + EIF）を取りこぼす。** ガード母集団が不当に小さくなるので、
//! フィルタ挙動を必ず判定すること。
//!
//! # Tier が何を決めるか
//!
//! | Tier | ガード | 出口 / Mailbox |
//! |------|--------|----------------|
//! | 0    | 可     | 可 |
//! | 1    | **不可** | 可（punch 経由） |
//! | 2    | 不可   | 部分的（Connection Reversal 経由） |
//!
//! **Tier 1 がガードになれない**のは、クライアントとの punch に仲介役が要り、
//! その仲介役が「この IP がこのガードに繋ごうとしている」を学ぶため。
//! ガード方式が守ろうとしているペアそのものが第三者に漏れる。
//!
//! # Tier 2 でも保持者にはなれる
//!
//! Connection Reversal があるので、到達不能でも
//! 「自分から張った接続の上で押し込んでもらう」形で保持者になれる。
//! これが無いとキャッシュが「自分が取りに行ったものだけ」になり、
//! 否認可能性 (設計書 18.3-C) が構造的に消える。

use crate::error::Result;
use crate::net::port_mapping::{PortMapper, PortMapping};
use crate::net::punch::{classify_mapping, NatFiltering, NatMapping};
use crate::net::shared_socket::{SharedSocket, SideChannelDatagram};
use crate::net::stun::StunResolver;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// ネットワーク上での役割
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier {
    /// 無条件に到達可能。ガードにもなれる
    Open = 0,
    /// 調整付き punch で到達可能。ガードにはなれない
    Punchable = 1,
    /// 到達不能。Connection Reversal 経由でのみ保持者になれる
    Reversed = 2,
}

impl Tier {
    /// ガード（クライアントの入口）になれるか
    ///
    /// **Tier 0 だけ。** punch が要る相手をガードにすると、
    /// 仲介役にクライアントとガードの対応が漏れる。
    pub fn can_be_guard(&self) -> bool {
        *self == Tier::Open
    }

    /// 見知らぬ相手からの inbound を受けられるか
    pub fn accepts_strangers(&self) -> bool {
        matches!(self, Tier::Open | Tier::Punchable)
    }
}

/// 判定結果
#[derive(Debug, Clone)]
pub struct Reachability {
    /// 広告すべきアドレス
    pub advertised: SocketAddr,
    pub tier: Tier,
    pub mapping: NatMapping,
    pub filtering: NatFiltering,
    /// 獲得したポートマッピング（**リース更新が要る**）
    pub port_mapping: Option<PortMapping>,
    /// どの段で決まったか（診断用）
    pub reason: &'static str,
}

/// 到達性を調べる
///
/// `local_addr` は QUIC が bind したアドレス。
/// `stun_servers` は**2台以上**渡すこと。1台では NAT 判定ができない。
pub async fn probe(
    socket: &Arc<SharedSocket>,
    side_rx: &mut mpsc::UnboundedReceiver<SideChannelDatagram>,
    local_addr: SocketAddr,
    stun_servers: &[String],
    allow_port_mapping: bool,
) -> Reachability {
    probe_with_filtering(
        socket,
        side_rx,
        local_addr,
        stun_servers,
        allow_port_mapping,
        NatFiltering::Unknown,
    )
    .await
}

/// フィルタ挙動が既に判明している場合の判定
///
/// フィルタ判定にはピア2台の協力が要る（一度も話していない相手から
/// 撃ってもらう必要がある）ため、ネットワーク参加後に行う。
/// 判明したらここへ渡し直すと Tier が上がることがある。
pub async fn probe_with_filtering(
    socket: &Arc<SharedSocket>,
    side_rx: &mut mpsc::UnboundedReceiver<SideChannelDatagram>,
    local_addr: SocketAddr,
    stun_servers: &[String],
    allow_port_mapping: bool,
    filtering: NatFiltering,
) -> Reachability {
    // --- 1. STUN で外部アドレスを観測 ---
    //
    // 複数の観測点から取るのは、アドレスを知るためだけでなく
    // **マッピング挙動を判定するため**。1点では判定できない。
    let observations = observe(socket, side_rx, stun_servers).await;

    let external = observations.first().copied();
    let mapping = classify_mapping(&observations);

    // --- 2. IPv6 ネイティブなら NAT が無い ---
    if let Some(addr) = external
        && addr.is_ipv6()
        && !addr.ip().is_loopback()
    {
        info!("Reachability: native IPv6, no NAT");
        return Reachability {
            advertised: addr,
            tier: Tier::Open,
            mapping,
            filtering,
            port_mapping: None,
            reason: "ipv6",
        };
    }

    // --- 3. ルータにポートを開けさせる ---
    //
    // 成功すれば本物の開放ポート = punch 不要
    if allow_port_mapping
        && let Some(mapped) = try_port_mapping(local_addr.port()).await
    {
        let ip = mapped
            .external_ip
            .or_else(|| external.map(|a| a.ip()));

        if let Some(ip) = ip {
            info!(
                "Reachability: port mapping via {:?}, external port {}",
                mapped.protocol, mapped.external_port
            );
            return Reachability {
                advertised: SocketAddr::new(ip, mapped.external_port),
                tier: Tier::Open,
                mapping,
                filtering,
                port_mapping: Some(mapped),
                reason: "port-mapping",
            };
        }
    }

    // --- 4. NAT の挙動で振り分ける ---
    match (external, mapping) {
        // **EIM かつ EIF は punch すら要らない。**
        // 送っていない相手からも入れるので、keepalive だけで完全到達可能
        (Some(addr), NatMapping::EndpointIndependent)
            if filtering.accepts_unsolicited() =>
        {
            info!("Reachability: EIM + EIF, fully open at {} without punching", addr);
            Reachability {
                advertised: addr,
                tier: Tier::Open,
                mapping,
                filtering,
                port_mapping: None,
                reason: "eim-eif",
            }
        }
        (Some(addr), NatMapping::EndpointIndependent) => {
            info!("Reachability: EIM NAT, punchable at {}", addr);
            Reachability {
                advertised: addr,
                tier: Tier::Punchable,
                mapping,
                filtering,
                port_mapping: None,
                reason: "eim-nat",
            }
        }
        (Some(addr), _) => {
            info!("Reachability: EDM/unknown NAT, relying on connection reversal");
            Reachability {
                advertised: addr,
                tier: Tier::Reversed,
                mapping,
                filtering,
                port_mapping: None,
                reason: "edm-nat",
            }
        }
        (None, _) => {
            // STUN が1台も応答しない。外部アドレスが分からない
            debug!("Reachability: no external address discovered");
            Reachability {
                advertised: local_addr,
                tier: Tier::Reversed,
                mapping: NatMapping::Unknown,
                filtering,
                port_mapping: None,
                reason: "no-observation",
            }
        }
    }
}

/// 各 STUN サーバから見た自分のアドレスを集める
///
/// **1台ずつ別々に問い合わせる。** マッピング挙動の判定には
/// 「宛先が違えば結果が違うか」を見る必要があるため、
/// 最初の1台で成功しても打ち切らない。
async fn observe(
    socket: &Arc<SharedSocket>,
    side_rx: &mut mpsc::UnboundedReceiver<SideChannelDatagram>,
    stun_servers: &[String],
) -> Vec<SocketAddr> {
    let mut observations = Vec::new();

    for server in stun_servers.iter().take(3) {
        let resolver = StunResolver::new(vec![server.clone()]);
        match resolver.resolve_on_shared(socket, side_rx).await {
            Ok(addr) => observations.push(addr),
            Err(e) => debug!("STUN {} failed: {}", server, e),
        }
    }

    observations
}

async fn try_port_mapping(internal_port: u16) -> Option<PortMapping> {
    let mapper = PortMapper::discover()?;
    debug!("Trying port mapping via {}", mapper.gateway());

    mapper
        .request_mapping(internal_port, crate::net::port_mapping::DEFAULT_LIFETIME)
        .await
        .ok()
}

/// ポートマッピングのリースを更新し続ける
///
/// **リースが切れた瞬間に到達性を失う。**
/// 獲得したら必ずこれを spawn すること。
pub fn spawn_renewal(mapping: PortMapping, internal_port: u16) -> Result<()> {
    let Some(mapper) = PortMapper::discover() else {
        return Ok(());
    };

    tokio::spawn(async move {
        let mut interval = mapping.renew_after().max(Duration::from_secs(30));

        loop {
            tokio::time::sleep(interval).await;

            match mapper
                .request_mapping(internal_port, crate::net::port_mapping::DEFAULT_LIFETIME)
                .await
            {
                Ok(renewed) => {
                    debug!("Port mapping renewed: external {}", renewed.external_port);
                    interval = renewed.renew_after().max(Duration::from_secs(30));
                }
                Err(e) => {
                    debug!("Port mapping renewal failed: {}", e);
                    // 失敗しても短い間隔で再試行する。
                    // 諦めると到達性を失ったまま気づけない
                    interval = Duration::from_secs(60);
                }
            }
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_open_tier_can_be_a_guard() {
        // punch が要る相手をガードにすると、仲介役に
        // クライアントとガードの対応が漏れる
        assert!(Tier::Open.can_be_guard());
        assert!(!Tier::Punchable.can_be_guard());
        assert!(!Tier::Reversed.can_be_guard());
    }

    #[test]
    fn reversed_tier_does_not_accept_strangers() {
        assert!(Tier::Open.accepts_strangers());
        assert!(Tier::Punchable.accepts_strangers());
        assert!(
            !Tier::Reversed.accepts_strangers(),
            "到達不能ノードを見知らぬ相手の受け口にすると届かない"
        );
    }

    #[test]
    fn tiers_are_ordered_by_capability() {
        assert!(Tier::Open < Tier::Punchable);
        assert!(Tier::Punchable < Tier::Reversed);
    }

    /// EIM でもフィルタ次第で Tier が変わることを、判定関数の分岐で確認する
    #[test]
    fn eim_with_eif_is_fully_open() {
        // マッピングだけ見て一律 Tier 1 にすると、
        // 本来 punch 不要のノードを取りこぼしてガード母集団が縮む
        assert!(NatFiltering::EndpointIndependent.accepts_unsolicited());
        assert!(!NatFiltering::Restricted.accepts_unsolicited());

        // 判定していない状態では安全側（punch が要る前提）に倒す
        assert!(!NatFiltering::Unknown.accepts_unsolicited());
    }

    #[tokio::test]
    async fn falls_back_to_reversed_without_any_observation() {
        use quinn::default_runtime;

        let runtime = default_runtime().unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let local = socket.local_addr().unwrap();
        let (shared, mut side_rx) = SharedSocket::from_std(socket, &*runtime).unwrap();
        tokio::spawn(shared.clone().pump());

        // 応答しない STUN サーバしか無い状況
        let result = probe(
            &shared,
            &mut side_rx,
            local,
            &["127.0.0.1:1".to_string()],
            false, // ポートマッピングは試さない
        )
        .await;

        assert_eq!(result.tier, Tier::Reversed);
        assert_eq!(result.mapping, NatMapping::Unknown);
        assert_eq!(result.reason, "no-observation");
        assert_eq!(
            result.advertised, local,
            "観測できなければローカルアドレスにフォールバックする"
        );
    }
}
