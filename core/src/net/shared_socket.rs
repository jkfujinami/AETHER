//! QUIC と STUN を1つの UDP ソケットに同居させる
//!
//! # なぜ必要か
//!
//! NAT は **(内部ip:port, 外部ip:port) の対応**を張る。ソケットが違えば
//! マッピングも別物になる。
//!
//! つまり**別ソケットで STUN して得た外部アドレスを広告しても繋がらない。**
//! 現行の `StunResolver::resolve()` は `UdpSocket::bind("0.0.0.0:0")` で
//! 独立ソケットを掘っており、この点で誤っている。
//!
//! 同じ理由で、hole punching のプローブも **QUIC が使うソケットから**
//! 撃たないと意味がない。開いた穴が QUIC の通り道でなければ無駄になる。
//!
//! # 多重分離
//!
//! [draft-seemann-quic-nat-traversal] が指摘する通り、QUIC ヘッダは
//! 他プロトコルと多重分離できるよう設計されている。
//!
//! ```text
//! QUIC long header : 先頭ビット = 1
//! QUIC short header: 先頭ビット = 0、第2ビット（固定ビット）= 1
//! STUN             : 先頭2ビット = 00  + magic cookie 0x2112A442
//! ```
//!
//! 先頭2ビットだけで衝突なく分けられる。magic cookie も見て二重に確認する。
//!
//! [draft-seemann-quic-nat-traversal]: https://datatracker.ietf.org/doc/html/draft-seemann-quic-nat-traversal

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::mpsc;

/// STUN メッセージの最小長（ヘッダ 20 バイト）
const STUN_HEADER_LEN: usize = 20;

/// STUN の magic cookie (RFC 5389)
const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// このデータグラムは STUN か
///
/// QUIC は先頭ビットが 1（long header）か、
/// 先頭が 0 でも第2ビット（固定ビット）が 1（short header）。
/// STUN は先頭2ビットが 00 なので衝突しない。
pub fn is_stun(data: &[u8]) -> bool {
    data.len() >= STUN_HEADER_LEN
        && data[0] & 0xC0 == 0x00
        && data[4..8] == STUN_MAGIC_COOKIE
}

/// 横取りしたデータグラム
#[derive(Debug, Clone)]
pub struct SideChannelDatagram {
    pub from: SocketAddr,
    pub data: Vec<u8>,
}

/// QUIC が使うソケットに相乗りするラッパ
///
/// `poll_recv` で STUN を抜き取り、残りだけを quinn へ渡す。
/// [`send_raw`](Self::send_raw) で**同じソケットから**任意のバイト列を撃てる。
///
/// # 誰かが `poll_recv` を回している必要がある
///
/// 横取りは `poll_recv` の中で起きるので、**このソケットで
/// `quinn::Endpoint` が動いていないと side channel には何も流れない。**
/// 本番では Endpoint のドライバが回すので問題ないが、
/// 単体で使う場合は [`pump`](Self::pump) を回すこと。
#[derive(Debug)]
pub struct SharedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    side_tx: mpsc::UnboundedSender<SideChannelDatagram>,
}

impl SharedSocket {
    /// quinn のソケットラッパを包む
    ///
    /// 戻り値の受信側に、横取りした STUN が流れてくる。
    pub fn new(
        inner: Arc<dyn AsyncUdpSocket>,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<SideChannelDatagram>) {
        let (side_tx, side_rx) = mpsc::unbounded_channel();
        (Arc::new(Self { inner, side_tx }), side_rx)
    }

    /// 標準ソケットから組み立てる
    pub fn from_std(
        socket: std::net::UdpSocket,
        runtime: &dyn quinn::Runtime,
    ) -> io::Result<(Arc<Self>, mpsc::UnboundedReceiver<SideChannelDatagram>)> {
        Ok(Self::new(runtime.wrap_udp_socket(socket)?))
    }

    /// QUIC と同じソケットから生のデータグラムを送る
    ///
    /// **STUN も punch プローブもこれを使うこと。**
    /// 別ソケットから撃つと NAT マッピングが別物になり、
    /// 得られた外部アドレスも開けた穴も QUIC には使えない。
    ///
    /// 送信バッファが埋まっている間は書き込み可能になるまで待つ。
    pub async fn send_raw(self: &Arc<Self>, dest: SocketAddr, data: &[u8]) -> io::Result<()> {
        let mut poller = self.clone().create_io_poller();

        loop {
            match self.try_send_raw(dest, data) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx)).await?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// 待たずに1回だけ試す
    ///
    /// 送信バッファが埋まっていれば `WouldBlock` を返す。
    pub fn try_send_raw(&self, dest: SocketAddr, data: &[u8]) -> io::Result<()> {
        self.inner.try_send(&Transmit {
            destination: self.map_destination(dest),
            ecn: None,
            contents: data,
            segment_size: None,
            src_ip: None,
        })
    }

    /// デュアルスタックソケットから IPv4 宛に送るための変換
    ///
    /// **v6 ソケットに素の IPv4 アドレスを渡すと送信に失敗する。**
    /// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) にしてやる必要がある。
    ///
    /// quinn は Endpoint の内部でこれをやっているが、
    /// `try_send` を直接叩く生送信はその経路を通らないので、ここで行う。
    /// これが無いと STUN も punch も v4 相手に一切届かない。
    fn map_destination(&self, dest: SocketAddr) -> SocketAddr {
        let socket_is_v6 = self.inner.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);

        match dest {
            SocketAddr::V4(v4) if socket_is_v6 => SocketAddr::new(
                std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()),
                v4.port(),
            ),
            other => other,
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// quinn の Endpoint を立てずにソケットを回す
    ///
    /// 横取りは `poll_recv` の中で起きるため、誰も回していないと
    /// side channel に何も流れない。Endpoint を立てない場面
    /// （起動前の外部アドレス発見など）ではこれを spawn しておく。
    ///
    /// QUIC パケットが来た場合は捨てる。Endpoint が動く前に届いたものは
    /// どのみち処理できない。
    pub async fn pump(self: Arc<Self>) {
        let mut buf = vec![0u8; 2048];
        let mut meta = [RecvMeta::default()];

        loop {
            let mut slices = [IoSliceMut::new(&mut buf)];
            let result = std::future::poll_fn(|cx| self.poll_recv(cx, &mut slices, &mut meta)).await;

            if result.is_err() {
                return;
            }
        }
    }
}

impl AsyncUdpSocket for SharedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let count = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => n,
                other => return other,
            };

            // STUN を抜き取り、残りを前へ詰める。
            // quinn には QUIC だけを見せる
            let mut kept = 0;
            for i in 0..count {
                let len = meta[i].len;
                let datagram = &bufs[i][..len];

                if is_stun(datagram) {
                    let _ = self.side_tx.send(SideChannelDatagram {
                        from: meta[i].addr,
                        data: datagram.to_vec(),
                    });
                    continue;
                }

                if kept != i {
                    // バッファは入れ替えず、内容をコピーして詰める
                    let (head, tail) = bufs.split_at_mut(i);
                    head[kept][..len].copy_from_slice(&tail[0][..len]);
                    meta[kept] = meta[i];
                }
                kept += 1;
            }

            // 全部 STUN だった場合、0 を返すと quinn が受信終了と誤解しうる。
            // もう一度 poll して QUIC が来るまで待つ
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stun_binding_request() -> Vec<u8> {
        let mut msg = vec![0u8; STUN_HEADER_LEN];
        msg[0] = 0x00; // Binding Request、先頭2ビットは 00
        msg[1] = 0x01;
        msg[2] = 0x00; // length = 0
        msg[3] = 0x00;
        msg[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
        msg
    }

    #[test]
    fn recognises_stun() {
        assert!(is_stun(&stun_binding_request()));
    }

    #[test]
    fn rejects_quic_long_header() {
        // long header は先頭ビットが 1
        let mut packet = vec![0u8; 64];
        packet[0] = 0xC0;
        packet[4..8].copy_from_slice(&STUN_MAGIC_COOKIE); // cookie が偶然一致しても
        assert!(!is_stun(&packet), "QUIC long header を STUN と誤認している");
    }

    #[test]
    fn rejects_quic_short_header() {
        // short header は先頭ビットが 0 だが固定ビット（第2ビット）が 1
        let mut packet = vec![0u8; 64];
        packet[0] = 0x40;
        packet[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
        assert!(!is_stun(&packet), "QUIC short header を STUN と誤認している");
    }

    #[test]
    fn rejects_without_magic_cookie() {
        let mut msg = stun_binding_request();
        msg[4] = 0xFF;
        assert!(!is_stun(&msg));
    }

    #[test]
    fn rejects_short_datagrams() {
        assert!(!is_stun(&[0u8; STUN_HEADER_LEN - 1]));
        assert!(!is_stun(&[]));
    }

    #[tokio::test]
    async fn stun_is_diverted_and_quic_passes_through() {
        use quinn::default_runtime;

        let runtime = default_runtime().expect("tokio runtime");
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();

        let (shared, mut side_rx) = SharedSocket::from_std(socket, &*runtime).unwrap();

        // 同じソケットから撃つ（NAT マッピングを共有するのが要点）
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(&stun_binding_request(), addr).unwrap();

        // quinn 側の受信ループを回す
        let pump = {
            let shared = shared.clone();
            tokio::spawn(async move {
                let mut bufs = [vec![0u8; 2048]];
                let mut meta = [RecvMeta::default()];
                std::future::poll_fn(|cx| {
                    let mut slices = [IoSliceMut::new(&mut bufs[0])];
                    shared.poll_recv(cx, &mut slices, &mut meta)
                })
                .await
            })
        };

        // STUN は横取りされて side channel に出る
        let diverted = tokio::time::timeout(std::time::Duration::from_secs(5), side_rx.recv())
            .await
            .expect("STUN が横取りされていない")
            .expect("side channel が閉じている");

        assert!(is_stun(&diverted.data));

        // QUIC 側にはまだ何も渡っていない（poll は保留のまま）
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), pump)
                .await
                .is_err(),
            "STUN を quinn へ渡してしまっている"
        );
    }

    #[tokio::test]
    async fn send_raw_reaches_ipv4_from_a_dual_stack_socket() {
        // v6 ソケットに素の IPv4 アドレスを渡すと送信に失敗する。
        // これが無いと STUN も punch も v4 相手に一切届かない
        use quinn::default_runtime;

        let runtime = default_runtime().unwrap();
        let dual = crate::net::addr::bind_dual_stack(0).unwrap();
        let dual_addr = dual.local_addr().unwrap();

        if !dual_addr.is_ipv6() {
            return; // v6 が使えない環境ではこの検査は不要
        }

        let (shared, _rx) = SharedSocket::from_std(dual, &*runtime).unwrap();

        // 素の IPv4 で待ち受ける相手
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let v4_target = receiver.local_addr().unwrap();
        assert!(v4_target.is_ipv4());

        shared.send_raw(v4_target, b"to ipv4").await.unwrap();

        let mut buf = [0u8; 64];
        let (len, _) = receiver
            .recv_from(&mut buf)
            .expect("IPv4 宛に届いていない（IPv4-mapped への変換漏れ）");
        assert_eq!(&buf[..len], b"to ipv4");
    }

    #[tokio::test]
    async fn send_raw_uses_the_same_socket() {
        use quinn::default_runtime;

        let runtime = default_runtime().expect("tokio runtime");
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let shared_addr = socket.local_addr().unwrap();

        let (shared, _side_rx) = SharedSocket::from_std(socket, &*runtime).unwrap();

        let observer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        observer
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();

        shared
            .send_raw(observer.local_addr().unwrap(), b"punch probe")
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let (len, from) = observer.recv_from(&mut buf).unwrap();

        assert_eq!(&buf[..len], b"punch probe");
        assert_eq!(
            from.port(),
            shared_addr.port(),
            "生パケットが QUIC と同じソケットから出ていない。\
             別ソケットだと NAT マッピングが別物になり、開けた穴が QUIC に使えない"
        );
    }
}
