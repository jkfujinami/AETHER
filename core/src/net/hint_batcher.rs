//! Hint のバッチ送信
//!
//! # なぜ必要か
//!
//! Hint 本体は 90 バイトしかないのに、UDP/IP/QUIC ヘッダが約48バイト、
//! ワイヤフレーミングが5バイト乗る。fanout 3 で送ると
//! **1 Hint あたり 429 バイトのうち 159 バイトがヘッダ**という比率になる。
//!
//! つまり Hint 本体を削る効果は頭打ちで（auth_tag の16バイト削減で +11.6% 止まり）、
//! **複数 Hint を1パケットにまとめる方が効く**（429 → 約290 B/件、1.48倍）。
//!
//! # 方式
//!
//! ピアごとに送信待ちキューを持ち、
//! - キューが [`MAX_BATCH_SIZE`] に達したら即座に、
//! - そうでなければ [`FLUSH_INTERVAL`] ごとに、
//!
//! まとめて送出する。
//!
//! Gossip の伝播はもともと非同期なので、
//! 1ホップあたり最大 [`FLUSH_INTERVAL`] の遅延が乗っても問題にならない。

use crate::protocol::hint::HintPacket;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::Mutex;

/// 1バッチに詰める Hint の上限。超えたら即フラッシュする
pub const MAX_BATCH_SIZE: usize = 64;

/// 定期フラッシュの間隔
///
/// 高レート時はこれを待たずに [`MAX_BATCH_SIZE`] で先にフラッシュされる。
/// 低レート時は Hint 1件あたり最大この時間だけ遅延する。
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(200);

/// ピア1つあたりの滞留上限
///
/// 到達不能なピアに積み続けてメモリを食い潰さないための安全弁。
const MAX_PENDING_PER_PEER: usize = MAX_BATCH_SIZE * 4;

#[derive(Default)]
pub struct HintBatcher {
    pending: Mutex<HashMap<SocketAddr, Vec<HintPacket>>>,
}

impl HintBatcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// 送信キューに積む
    ///
    /// バッチが満杯になった場合、そのピア宛の溜まった分を返す（即時送出用）。
    /// それ以外は `None` を返し、定期フラッシュに任せる。
    pub async fn enqueue(&self, peer: SocketAddr, hint: HintPacket) -> Option<Vec<HintPacket>> {
        let mut pending = self.pending.lock().await;
        let queue = pending.entry(peer).or_default();

        queue.push(hint);

        if queue.len() >= MAX_BATCH_SIZE {
            return Some(std::mem::take(queue));
        }

        // 到達不能なピアで無制限に膨らむのを防ぐ
        if queue.len() > MAX_PENDING_PER_PEER {
            queue.drain(..queue.len() - MAX_PENDING_PER_PEER);
        }

        None
    }

    /// 全ピア分の滞留を取り出す（定期フラッシュ用）
    pub async fn drain(&self) -> Vec<(SocketAddr, Vec<HintPacket>)> {
        let mut pending = self.pending.lock().await;
        pending
            .drain()
            .filter(|(_, hints)| !hints.is_empty())
            .collect()
    }

    /// 滞留中の総件数（デバッグ用）
    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.values().map(Vec::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> SocketAddr {
        format!("127.0.0.{}:9000", n).parse().unwrap()
    }

    fn hint(tag: u8) -> HintPacket {
        HintPacket::new([tag; 4], [tag; 12], vec![tag; 64], 5)
    }

    #[tokio::test]
    async fn accumulates_until_flush_interval() {
        let b = HintBatcher::new();

        for n in 0..10u8 {
            assert!(
                b.enqueue(peer(1), hint(n)).await.is_none(),
                "上限未満では即時送出しない"
            );
        }
        assert_eq!(b.pending_count().await, 10);

        let drained = b.drain().await;
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].1.len(), 10);
        assert_eq!(b.pending_count().await, 0, "drain 後は空になる");
    }

    #[tokio::test]
    async fn flushes_immediately_when_full() {
        let b = HintBatcher::new();

        for n in 0..(MAX_BATCH_SIZE - 1) {
            assert!(b.enqueue(peer(1), hint(n as u8)).await.is_none());
        }

        let flushed = b
            .enqueue(peer(1), hint(0xFF))
            .await
            .expect("上限到達で即時送出されるべき");
        assert_eq!(flushed.len(), MAX_BATCH_SIZE);
        assert_eq!(b.pending_count().await, 0);
    }

    #[tokio::test]
    async fn queues_are_per_peer() {
        let b = HintBatcher::new();
        b.enqueue(peer(1), hint(1)).await;
        b.enqueue(peer(2), hint(2)).await;
        b.enqueue(peer(2), hint(3)).await;

        let mut drained = b.drain().await;
        drained.sort_by_key(|(addr, _)| *addr);

        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].1.len(), 1);
        assert_eq!(drained[1].1.len(), 2);
    }

    #[tokio::test]
    async fn unreachable_peer_does_not_grow_unbounded() {
        let b = HintBatcher::new();

        // フラッシュ結果を捨て続ける = 送信に失敗し続ける状況
        for n in 0..(MAX_BATCH_SIZE * 10) {
            b.enqueue(peer(9), hint(n as u8)).await;
        }

        assert!(
            b.pending_count().await <= MAX_PENDING_PER_PEER,
            "到達不能なピア宛の滞留が上限を超えている"
        );
    }
}
