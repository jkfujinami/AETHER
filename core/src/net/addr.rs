//! アドレスの正規化とデュアルスタック bind
//!
//! # なぜ正規化が要るか
//!
//! デュアルスタックのソケット（`[::]` に v6only=false で bind）では、
//! **IPv4 のピアが `::ffff:a.b.c.d` という IPv4-mapped IPv6 アドレスとして見える。**
//!
//! ```text
//! ディレクトリに載っている値 : 127.0.0.1:9000
//! 接続を受けたときの値       : [::ffff:127.0.0.1]:9000
//! ```
//!
//! この2つは `SocketAddr` として等しくない。正規化しないと:
//!
//! - Connection Reversal が壊れる（登録キーと検索キーが一致しない）
//! - ピア一覧に同じノードが2重に載る
//! - K最近接の計算が食い違う
//!
//! アドレスをキーに使う場所では**必ず** [`normalize`] を通すこと。

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};

/// IPv4-mapped IPv6 を素の IPv4 に戻す
///
/// それ以外はそのまま返す。冪等。
pub fn normalize(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

/// デュアルスタックの UDP ソケットを開く
///
/// `[::]` に v6only=false で bind すると、**1つのソケットで v4 と v6 の
/// 両方を受けられる。** 日本の IPoE 環境では IPv6 が使えると NAT が
/// 存在しないため、punch なしで到達可能になる。
///
/// IPv6 が使えない環境では `0.0.0.0` にフォールバックする。
pub fn bind_dual_stack(port: u16) -> io::Result<UdpSocket> {
    match bind_v6_dual(port) {
        Ok(socket) => Ok(socket),
        Err(_) => UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port))),
    }
}

fn bind_v6_dual(port: u16) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;

    // これを外さないと v4 が入ってこない
    socket.set_only_v6(false)?;

    // nonblocking は quinn 側 (quinn-udp の UdpSocketState) が設定する。
    // ここで設定すると v4 フォールバック経路 (UdpSocket::bind) と挙動がずれる

    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    socket.bind(&addr.into())?;

    Ok(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn unmaps_ipv4_mapped_addresses() {
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:9000".parse().unwrap();
        let plain: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        assert_eq!(normalize(mapped), plain);
    }

    #[test]
    fn leaves_plain_ipv4_alone() {
        let addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        assert_eq!(normalize(addr), addr);
    }

    #[test]
    fn leaves_real_ipv6_alone() {
        let addr: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        assert_eq!(normalize(addr), addr);
    }

    #[test]
    fn is_idempotent() {
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:5555".parse().unwrap();
        assert_eq!(normalize(normalize(mapped)), normalize(mapped));
    }

    #[test]
    fn mapped_and_plain_would_otherwise_differ() {
        // 正規化しないと Connection Reversal の登録キーと検索キーが一致しない
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:9000".parse().unwrap();
        let plain: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        assert_ne!(mapped, plain, "この前提が崩れるなら正規化は不要になる");
        assert_eq!(normalize(mapped), normalize(plain));
    }

    #[test]
    fn dual_stack_socket_accepts_both_families() {
        let socket = bind_dual_stack(0).expect("bind に失敗");
        let local = socket.local_addr().unwrap();

        // IPv6 で bind できていれば v4 も受けられる。
        // v4 フォールバックした場合はここが V4 になる
        if local.is_ipv6() {
            let v4_sender = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
            let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local.port());

            v4_sender.send_to(b"hello from v4", target).unwrap();

            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0u8; 64];
            let (len, from) = socket.recv_from(&mut buf).expect("v4 が届いていない");

            assert_eq!(&buf[..len], b"hello from v4");
            assert!(
                normalize(from).is_ipv4(),
                "v4 の送信元が正規化後も v4 にならない: {}",
                from
            );
        }
    }
}
