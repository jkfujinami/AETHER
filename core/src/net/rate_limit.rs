//! 送り手の IP ごとの上り制限（ガードでの押し流し対策 / Part 23 の 12 章・Part 25 の P2）
//!
//! `MailboxPut` には PoW も認証も無く、帯域さえあれば網を埋められる。ガードは自分の
//! クライアントの IP をもともと知っているので、**一覧に載っていない送り手**
//! （クライアント・隠れた保持者）から受け取る量を IP ごとのトークンバケットで絞る。
//!
//! - 超えたら**捨てずに読むのを待たせる**（背圧）。捨てると正直な大きな上げが壊れる。
//!   待つのは接続ごと・ストリームごとで、受け付けのループは止めない。
//! - 数えるのは IP（IPv4 はアドレス、IPv6 は /64）だけ。ポートは見ない。
//! - 記録は手元のメモリだけ。IP とバイト数をディスクにもログにも出さない。
//!   数分使われない記録は捨てる。
//! - 値は各ガードの手元の判断で、網全体で揃える必要はない。
//!
//! 既存の [`crate::net::shaper`] は送信側の整形（カバートラフィックの間隔・大きさ）で
//! 目的が違うので使わない。

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::RwLock;
use tokio::time::Sleep;

use crate::net::relay_list::RelayDirectory;

/// IP の識別子（IPv4 はアドレス、IPv6 は上位 64 ビット）
pub type IpKey = [u8; 16];

/// 数分使われない IP の記録は捨てる
const IDLE_FORGET: Duration = Duration::from_secs(300);

/// 記録を掃除する最短間隔
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// 記録する IP の数の目安。超えたら満タンまで回復した記録（= 忘れて困らないもの）を先に捨てる
const MAX_TRACKED: usize = 65_536;

/// 一覧の IP 集合を作り直す間隔（毎回一覧を走査しない）
const LISTED_REFRESH: Duration = Duration::from_secs(5);

/// アドレスを数える単位にする（IPv4-mapped は IPv4 に戻す。IPv6 は /64）
pub fn ip_key(addr: SocketAddr) -> IpKey {
    let mut key = [0u8; 16];
    // IPv4 と IPv6 が衝突しないよう、種類を末尾に入れる
    match crate::net::addr::normalize(addr).ip() {
        IpAddr::V4(v4) => {
            key[..4].copy_from_slice(&v4.octets());
            key[15] = 4;
        }
        IpAddr::V6(v6) => {
            key[..8].copy_from_slice(&v6.octets()[..8]);
            key[15] = 6;
        }
    }
    key
}

/// 送り手の扱い
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderClass {
    /// 一覧に載っていない（クライアント・隠れた保持者 = 自分が入口）
    Guest,
    /// 一覧に載っているリレーの IP（自分が中間・出口の位置）
    Relay,
}

/// 送り手の IP が一覧のリレーのどれかの IP と同じか（純粋な判定）
pub fn classify(listed: &HashSet<IpKey>, remote: SocketAddr) -> SenderClass {
    if listed.contains(&ip_key(remote)) {
        SenderClass::Relay
    } else {
        SenderClass::Guest
    }
}

struct Bucket {
    /// 負なら借り（待たせる）
    tokens: f64,
    /// 最後に触った時刻
    last: Duration,
}

struct Inner {
    map: HashMap<IpKey, Bucket>,
    last_sweep: Duration,
}

/// IP ごとのトークンバケット（時刻は引数で受け取る = 試験で決定論的に動かせる）
pub struct RateLimiter {
    /// 1 秒あたりのバイト数
    rate: f64,
    /// 溜められる量
    burst: f64,
    inner: Mutex<Inner>,
}

impl RateLimiter {
    /// `rate` が 0 のときは作らない（呼び出し側が無制限として扱う）
    pub fn new(rate: u64, burst: u64) -> Self {
        Self {
            rate: rate as f64,
            burst: burst.max(1) as f64,
            inner: Mutex::new(Inner { map: HashMap::new(), last_sweep: Duration::ZERO }),
        }
    }

    fn refill(&self, b: &mut Bucket, now: Duration) {
        let dt = now.saturating_sub(b.last).as_secs_f64();
        b.tokens = (b.tokens + dt * self.rate).min(self.burst);
        b.last = now;
    }

    /// 読んだ `bytes` を数える。借りになることを許す（読み終えた分は戻せない）
    pub fn charge(&self, key: IpKey, bytes: usize, now: Duration) {
        let mut inner = self.inner.lock().unwrap();
        self.sweep(&mut inner, now);
        let burst = self.burst;
        let b = inner.map.entry(key).or_insert(Bucket { tokens: burst, last: now });
        self.refill(b, now);
        b.tokens -= bytes as f64;
    }

    /// 借りが消えるまでの待ち時間（無ければ 0）
    pub fn debt_wait(&self, key: IpKey, now: Duration) -> Duration {
        let mut inner = self.inner.lock().unwrap();
        match inner.map.get_mut(&key) {
            Some(b) => {
                self.refill(b, now);
                if b.tokens < 0.0 {
                    Duration::from_secs_f64(-b.tokens / self.rate)
                } else {
                    Duration::ZERO
                }
            }
            None => Duration::ZERO,
        }
    }

    /// 使われない記録を捨てる。数が増えすぎたら、満タンまで回復した記録も捨てる
    fn sweep(&self, inner: &mut Inner, now: Duration) {
        let over = inner.map.len() >= MAX_TRACKED;
        if !over && now.saturating_sub(inner.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        inner.last_sweep = now;
        let (rate, burst) = (self.rate, self.burst);
        inner.map.retain(|_, b| {
            let idle = now.saturating_sub(b.last);
            if idle >= IDLE_FORGET {
                return false;
            }
            // 満タンまで回復していれば、忘れても新規と同じ扱いになる
            !(over && b.tokens + idle.as_secs_f64() * rate >= burst)
        });
    }

    /// 記録している IP の数（試験用）
    pub fn tracked(&self) -> usize {
        self.inner.lock().unwrap().map.len()
    }
}

/// 一覧の IP 集合の写し（一定時間ごとに作り直す）
struct ListedCache {
    set: HashSet<IpKey>,
    built: Option<Instant>,
}

/// ガードの上り制限一式
pub struct UploadLimiter {
    guest: Option<RateLimiter>,
    relay: Option<RateLimiter>,
    listed: Mutex<ListedCache>,
    epoch: Instant,
}

impl UploadLimiter {
    /// 各 `(rate, burst)` の `rate` が 0 なら、その区分は無制限
    pub fn new(guest: (u64, u64), relay: (u64, u64)) -> Self {
        let make = |(rate, burst): (u64, u64)| (rate > 0).then(|| RateLimiter::new(rate, burst));
        Self {
            guest: make(guest),
            relay: make(relay),
            listed: Mutex::new(ListedCache { set: HashSet::new(), built: None }),
            epoch: Instant::now(),
        }
    }

    pub fn from_config(c: &crate::Config) -> Self {
        Self::new(
            (c.guest_upload_rate, c.guest_upload_burst),
            (c.relay_upload_rate, c.relay_upload_burst),
        )
    }

    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }

    /// 送り手が一覧のリレーの IP か。一覧の写しは数秒ごとにしか作り直さない
    pub async fn classify(&self, dir: &RwLock<RelayDirectory>, remote: SocketAddr) -> SenderClass {
        let stale = {
            let c = self.listed.lock().unwrap();
            c.built.is_none_or(|t| t.elapsed() >= LISTED_REFRESH)
        };
        if stale {
            let set: HashSet<IpKey> = {
                let dir = dir.read().await;
                dir.all().into_iter().map(|d| ip_key(d.addr)).collect()
            };
            let mut c = self.listed.lock().unwrap();
            c.set = set;
            c.built = Some(Instant::now());
        }
        classify(&self.listed.lock().unwrap().set, remote)
    }

    /// 受信ストリームを、送り手の区分に応じた上限つきの読み手で包む
    pub fn wrap<R>(self: &Arc<Self>, inner: R, class: SenderClass, remote: SocketAddr) -> Throttled<R> {
        let enabled = match class {
            SenderClass::Guest => self.guest.is_some(),
            SenderClass::Relay => self.relay.is_some(),
        };
        Throttled {
            inner,
            limiter: enabled.then(|| self.clone()),
            class,
            key: ip_key(remote),
            sleep: None,
        }
    }

    fn bucket(&self, class: SenderClass) -> Option<&RateLimiter> {
        match class {
            SenderClass::Guest => self.guest.as_ref(),
            SenderClass::Relay => self.relay.as_ref(),
        }
    }
}

/// 読んだ量を数え、借りがある間は次を読まずに待つ読み手（背圧）
///
/// 読まないあいだ QUIC の受信窓が埋まるので、送り手の側が止まる。
pub struct Throttled<R> {
    inner: R,
    limiter: Option<Arc<UploadLimiter>>,
    class: SenderClass,
    key: IpKey,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl<R: AsyncRead + Unpin> AsyncRead for Throttled<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        let Some(limiter) = this.limiter.clone() else {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        };
        let Some(bucket) = limiter.bucket(this.class) else {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        };

        // 借りがあるあいだは読まない。ほかのストリームが借りを増やしていることもあるので、
        // 起きるたびに測り直す
        loop {
            if let Some(s) = this.sleep.as_mut() {
                ready!(s.as_mut().poll(cx));
                this.sleep = None;
            }
            let wait = bucket.debt_wait(this.key, limiter.now());
            if wait.is_zero() {
                break;
            }
            this.sleep = Some(Box::pin(tokio::time::sleep(wait)));
        }

        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        let n = buf.filled().len() - before;
        if n > 0 {
            bucket.charge(this.key, n, limiter.now());
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    const MB: u64 = 1_000_000;

    fn secs(s: f64) -> Duration {
        Duration::from_secs_f64(s)
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn burst_passes_without_waiting_then_follows_the_rate() {
        let l = RateLimiter::new(MB, 4 * MB);
        let k = ip_key(addr("203.0.113.5:1000"));
        // 溜められる 4MB までは待たない
        l.charge(k, 4_000_000, secs(0.0));
        assert_eq!(l.debt_wait(k, secs(0.0)), Duration::ZERO);
        // さらに 2MB 読むと借りになり、1MB/s なら 2 秒で消える
        l.charge(k, 2_000_000, secs(0.0));
        let w = l.debt_wait(k, secs(0.0));
        assert!((w.as_secs_f64() - 2.0).abs() < 1e-6, "{:?}", w);
        // 時間に比例して減る
        let w = l.debt_wait(k, secs(1.5));
        assert!((w.as_secs_f64() - 0.5).abs() < 1e-6, "{:?}", w);
        assert_eq!(l.debt_wait(k, secs(2.0)), Duration::ZERO);
    }

    #[test]
    fn tokens_never_exceed_the_burst() {
        let l = RateLimiter::new(MB, 4 * MB);
        let k = ip_key(addr("203.0.113.5:1000"));
        l.charge(k, 1, secs(0.0));
        // 長く休んでも 4MB までしか溜まらない: 5MB 読めば 1MB の借り
        l.charge(k, 5_000_000, secs(1000.0));
        let w = l.debt_wait(k, secs(1000.0));
        assert!((w.as_secs_f64() - 1.0).abs() < 1e-6, "{:?}", w);
    }

    #[test]
    fn ipv6_counts_per_slash_64_and_ipv4_per_address() {
        assert_eq!(
            ip_key(addr("[2001:db8:1:2::1]:1000")),
            ip_key(addr("[2001:db8:1:2:ffff::9]:2000"))
        );
        assert_ne!(
            ip_key(addr("[2001:db8:1:2::1]:1000")),
            ip_key(addr("[2001:db8:1:3::1]:1000"))
        );
        // ポートは見ない
        assert_eq!(ip_key(addr("203.0.113.5:1")), ip_key(addr("203.0.113.5:2")));
        assert_ne!(ip_key(addr("203.0.113.5:1")), ip_key(addr("203.0.113.6:1")));
        // IPv4-mapped は IPv4 と同じ
        assert_eq!(ip_key(addr("[::ffff:203.0.113.5]:1")), ip_key(addr("203.0.113.5:9")));
    }

    #[test]
    fn separate_ips_have_separate_buckets() {
        let l = RateLimiter::new(MB, MB);
        let a = ip_key(addr("203.0.113.5:1"));
        let b = ip_key(addr("203.0.113.6:1"));
        l.charge(a, 3_000_000, secs(0.0));
        assert!(l.debt_wait(a, secs(0.0)) > Duration::ZERO);
        assert_eq!(l.debt_wait(b, secs(0.0)), Duration::ZERO);
    }

    #[test]
    fn classify_matches_ip_of_any_listed_relay_ignoring_port() {
        let listed: HashSet<IpKey> = [addr("198.51.100.7:9000"), addr("[2001:db8:5:6::1]:9000")]
            .into_iter()
            .map(ip_key)
            .collect();
        assert_eq!(classify(&listed, addr("198.51.100.7:55555")), SenderClass::Relay);
        assert_eq!(classify(&listed, addr("[::ffff:198.51.100.7]:1")), SenderClass::Relay);
        assert_eq!(classify(&listed, addr("[2001:db8:5:6:aaaa::2]:1")), SenderClass::Relay);
        assert_eq!(classify(&listed, addr("198.51.100.8:9000")), SenderClass::Guest);
        assert_eq!(classify(&listed, addr("[2001:db8:5:7::1]:9000")), SenderClass::Guest);
    }

    #[test]
    fn idle_records_are_forgotten() {
        let l = RateLimiter::new(MB, MB);
        let a = ip_key(addr("203.0.113.5:1"));
        let b = ip_key(addr("203.0.113.6:1"));
        l.charge(a, 10, secs(0.0));
        l.charge(b, 10, secs(0.0));
        assert_eq!(l.tracked(), 2);
        // 数分たって別の IP が来ると、掃除で古い記録が消える
        let c = ip_key(addr("203.0.113.7:1"));
        l.charge(c, 10, secs(400.0));
        assert_eq!(l.tracked(), 1);
        // 使われ続けている記録は残る
        l.charge(c, 10, secs(500.0));
        l.charge(c, 10, secs(700.0));
        assert_eq!(l.tracked(), 1);
    }

    #[test]
    fn full_buckets_are_dropped_when_too_many_are_tracked() {
        let l = RateLimiter::new(MB, MB);
        for i in 0..(MAX_TRACKED as u32) {
            let mut k = [0u8; 16];
            k[..4].copy_from_slice(&i.to_be_bytes());
            l.charge(k, 1, secs(0.0));
        }
        assert_eq!(l.tracked(), MAX_TRACKED);
        // 十分たてば全部満タンに戻っているので、次の記録で掃除される
        l.charge([9u8; 16], 1, secs(10.0));
        assert_eq!(l.tracked(), 1);
    }

    #[tokio::test]
    async fn zero_rate_means_unlimited() {
        let limiter = Arc::new(UploadLimiter::new((0, 0), (0, 0)));
        let data = vec![7u8; 3_000_000];
        let mut r = limiter.wrap(&data[..], SenderClass::Guest, addr("203.0.113.5:1"));
        let start = Instant::now();
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        assert_eq!(out.len(), data.len());
        assert!(start.elapsed() < Duration::from_millis(500));
    }

    #[tokio::test]
    async fn throttled_reader_waits_for_the_rate_but_loses_nothing() {
        // 200KB/s・溜められるのは 50KB。100KB 読むと、50KB 分を待つ
        let limiter = Arc::new(UploadLimiter::new((200_000, 50_000), (0, 0)));
        let data: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
        let mut r = limiter.wrap(&data[..], SenderClass::Guest, addr("203.0.113.5:1"));
        let start = Instant::now();
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data, "捨てずに全部届く");
        assert!(start.elapsed() >= Duration::from_millis(200), "{:?}", start.elapsed());
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn relay_class_uses_the_looser_limit() {
        let limiter = Arc::new(UploadLimiter::new((100_000, 10_000), (0, 0)));
        let data = vec![1u8; 500_000];
        // 同じ量でも、一覧に載っているリレーなら待たない
        let mut r = limiter.wrap(&data[..], SenderClass::Relay, addr("198.51.100.7:1"));
        let start = Instant::now();
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        assert_eq!(out.len(), data.len());
        assert!(start.elapsed() < Duration::from_millis(500));
    }
}
