//! Gossip の重複排除キャッシュ（世代交代式 Bloom フィルタ）
//!
//! # なぜ Bloom フィルタなのか
//!
//! 素朴な LRU（`HashMap` + 件数上限）だと、受信レートが上限を超えた瞬間に
//! **TTL より前にエントリが排出され、実効的な重複排除窓が黙って縮む。**
//!
//! 一方 `HintPayload::is_fresh()` は ±15分のズレを許容している。
//! 窓がそれより短くなると、その差分の時間帯に
//! 「重複排除からは消えたが時刻検査は通る」Hint が生まれ、
//! 攻撃者は PoW を再計算せずに古い Hint を再投入して再フラッドできる。
//!
//! Bloom フィルタは**誤検知の方向が「見たことがある」側にしか倒れない**。
//! 容量を超えても誤検知率が上がるだけで、
//! 「見たものを見ていないと判定する」ことは原理的に起こらない。
//! つまりレートがどれだけ上がってもリプレイ窓は開かない。
//! 劣化するのは配送の取りこぼし率であって、安全性ではない。
//!
//! # 世代交代
//!
//! 2世代を保持し、TTL ごとに `current` を `previous` へ落として捨てる。
//! あるエントリの生存期間は TTL 〜 2×TTL となり、**最低でも TTL は保証される**。

use std::time::{Duration, Instant};

/// 保持対象の想定件数（1世代あたり）
///
/// 15分 × 約300 Hint/秒 を想定。これは 1Mbps のゴシップ帯域予算に対応する。
/// 超過しても壊れず、誤検知率が上がるだけ。
pub const DEFAULT_CAPACITY: usize = 300_000;

/// エントリの最低保持期間 (15分)
///
/// `protocol::hint::MAX_TIME_DRIFT_SECS` 以上でなければならない。
/// 下回るとリプレイ窓が開く。
pub const DEFAULT_TTL_SECS: u64 = 15 * 60;

/// 想定件数における誤検知率 (1/10,000)
///
/// 誤検知＝新規 Hint を既知と誤判定して落とす。
/// Gossip は複数経路で冗長に届くうえ、保持者による再放流 (設計書 18.3-A) も
/// 効くため、この程度の取りこぼしは吸収できる。
pub const DEFAULT_FP_RATE: f64 = 0.0001;

/// 重複排除窓が時刻ドリフト許容を下回るとリプレイ窓が開くため、
/// ビルド時に固定する。
const _: () = assert!(
    DEFAULT_TTL_SECS >= crate::protocol::hint::MAX_TIME_DRIFT_SECS,
    "SeenCache の TTL が MAX_TIME_DRIFT_SECS を下回ると、\
     その差の時間帯に古い Hint を再投入して再フラッドできてしまう"
);

/// 固定サイズの Bloom フィルタ
///
/// 入力は既に SHA-256 出力（`HintPacket::id()`）なので、
/// 追加のハッシュ計算は不要。先頭16バイトを2つの u64 として取り出し、
/// Kirsch-Mitzenmacher 法 `g_i = h1 + i*h2` で k 個のビット位置を導出する。
#[derive(Clone)]
struct BloomFilter {
    words: Vec<u64>,
    num_bits: usize,
    num_hashes: u32,
    inserted: usize,
}

impl BloomFilter {
    fn new(capacity: usize, fp_rate: f64) -> Self {
        let (num_bits, num_hashes) = Self::optimal_params(capacity, fp_rate);
        Self {
            words: vec![0u64; num_bits.div_ceil(64)],
            num_bits,
            num_hashes,
            inserted: 0,
        }
    }

    /// m = -n·ln(p) / (ln2)²,  k = (m/n)·ln2
    fn optimal_params(capacity: usize, fp_rate: f64) -> (usize, u32) {
        let n = capacity.max(1) as f64;
        let p = fp_rate.clamp(f64::MIN_POSITIVE, 0.5);

        let ln2 = std::f64::consts::LN_2;
        let bits = (-n * p.ln() / (ln2 * ln2)).ceil().max(64.0);
        let hashes = ((bits / n) * ln2).round().clamp(1.0, 32.0);

        (bits as usize, hashes as u32)
    }

    #[inline]
    fn split(id: &[u8; 32]) -> (u64, u64) {
        let h1 = u64::from_le_bytes(id[0..8].try_into().expect("32バイトから8バイト"));
        // h2 が偶数だと巡回が短くなるため奇数に寄せる
        let h2 = u64::from_le_bytes(id[8..16].try_into().expect("32バイトから8バイト")) | 1;
        (h1, h2)
    }

    #[inline]
    fn bit_index(&self, h1: u64, h2: u64, i: u32) -> usize {
        let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
        (combined % self.num_bits as u64) as usize
    }

    fn contains(&self, id: &[u8; 32]) -> bool {
        let (h1, h2) = Self::split(id);
        (0..self.num_hashes).all(|i| {
            let bit = self.bit_index(h1, h2, i);
            self.words[bit / 64] & (1u64 << (bit % 64)) != 0
        })
    }

    /// 挿入する。既に全ビットが立っていた場合は false（＝既知とみなす）
    fn insert(&mut self, id: &[u8; 32]) -> bool {
        let (h1, h2) = Self::split(id);
        let mut was_new = false;

        for i in 0..self.num_hashes {
            let bit = self.bit_index(h1, h2, i);
            let word = &mut self.words[bit / 64];
            let mask = 1u64 << (bit % 64);
            if *word & mask == 0 {
                *word |= mask;
                was_new = true;
            }
        }

        if was_new {
            self.inserted += 1;
        }
        was_new
    }

    fn clear(&mut self) {
        self.words.fill(0);
        self.inserted = 0;
    }

    fn memory_bytes(&self) -> usize {
        self.words.len() * 8
    }
}

pub struct SeenCache {
    current: BloomFilter,
    previous: BloomFilter,
    /// この間隔で世代交代する。生存期間は ttl 〜 2×ttl
    ttl: Duration,
    last_rotation: Instant,
    capacity: usize,
}

impl Default for SeenCache {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY, DEFAULT_TTL_SECS)
    }
}

impl SeenCache {
    pub fn new(capacity: usize, ttl_secs: u64) -> Self {
        Self::with_fp_rate(capacity, ttl_secs, DEFAULT_FP_RATE)
    }

    pub fn with_fp_rate(capacity: usize, ttl_secs: u64, fp_rate: f64) -> Self {
        Self::with_params(capacity, Duration::from_secs(ttl_secs), fp_rate)
    }

    pub fn with_params(capacity: usize, ttl: Duration, fp_rate: f64) -> Self {
        let filter = BloomFilter::new(capacity, fp_rate);
        Self {
            previous: filter.clone(),
            current: filter,
            ttl,
            last_rotation: Instant::now(),
            capacity,
        }
    }

    /// 既知かどうか
    pub fn contains(&mut self, id: &[u8; 32]) -> bool {
        self.rotate_if_due();
        self.current.contains(id) || self.previous.contains(id)
    }

    /// 登録する。既知だった場合は false（＝重複）を返す
    pub fn insert(&mut self, id: [u8; 32]) -> bool {
        self.rotate_if_due();

        if self.previous.contains(&id) {
            return false;
        }
        self.current.insert(&id)
    }

    /// 世代交代の判定（定期タスクから呼んでもよい。通常は自動）
    pub fn cleanup(&mut self) {
        self.rotate_if_due();
    }

    fn rotate_if_due(&mut self) {
        if self.last_rotation.elapsed() < self.ttl {
            return;
        }

        // current を previous へ落とし、current を空にする
        std::mem::swap(&mut self.current, &mut self.previous);
        self.current.clear();
        self.last_rotation = Instant::now();
    }

    /// 保持中の概算件数
    pub fn len(&self) -> usize {
        self.current.inserted + self.previous.inserted
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 想定容量に対する充填率
    ///
    /// 1.0 を超えると誤検知率が設計値を上回る（＝取りこぼしが増える）。
    /// 安全性は劣化しないが、容量の見直しを検討する指標になる。
    pub fn saturation(&self) -> f64 {
        self.current.inserted as f64 / self.capacity.max(1) as f64
    }

    /// 観測された投入レート (件/秒)
    ///
    /// Broadcast Veil では全 Hint が自分に届くので、
    /// これがそのままネットワーク全体の投稿レート＝匿名集合の大きさになる。
    /// **他の設計では得られない性質**で、遅延窓の逆算に使う。
    pub fn observed_rate(&self) -> f64 {
        let age = self.last_rotation.elapsed().as_secs_f64();
        if age < 1.0 {
            return 0.0;
        }
        self.current.inserted as f64 / age
    }

    /// 実消費メモリ（バイト）
    pub fn memory_bytes(&self) -> usize {
        self.current.memory_bytes() + self.previous.memory_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 実際の ID は SHA-256 出力なので、テストでもビットを散らしておく
    fn id(n: u32) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut x = u64::from(n).wrapping_add(0x9E37_79B9_7F4A_7C15);
        for chunk in out.chunks_mut(8) {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            chunk.copy_from_slice(&x.to_le_bytes());
        }
        out
    }

    #[test]
    fn insert_reports_duplicates() {
        let mut cache = SeenCache::default();
        assert!(cache.insert(id(1)), "初回は新規");
        assert!(!cache.insert(id(1)), "2回目は重複");
        assert!(cache.insert(id(2)));
    }

    #[test]
    fn over_capacity_never_forgets() {
        // 旧 LRU 実装では容量超過で古いエントリが TTL 前に落ちていた。
        // Bloom は誤検知が「既知」側にしか倒れないので、忘れることがない。
        let mut cache = SeenCache::new(1_000, DEFAULT_TTL_SECS);
        let first = id(0);
        cache.insert(first);

        for n in 1..20_000u32 {
            cache.insert(id(n));
        }

        assert!(
            cache.contains(&first),
            "容量を20倍超過しても、一度見たものを忘れてはならない"
        );
    }

    /// 生存期間が TTL 〜 2×TTL に収まることを実時間で確認する
    ///
    /// 最低保証が TTL を下回ると、時刻ドリフト検査との間にリプレイ窓が開く。
    #[test]
    fn entry_survives_at_least_one_ttl_then_expires() {
        let ttl = Duration::from_millis(100);
        let mut cache = SeenCache::with_params(1_000, ttl, DEFAULT_FP_RATE);
        cache.insert(id(7));

        // 1回目の世代交代後: previous に残っているので、まだ既知
        std::thread::sleep(ttl + Duration::from_millis(20));
        assert!(cache.contains(&id(7)), "TTL 経過直後はまだ忘れてはならない");

        // 2回目の世代交代後: 両世代から落ちる
        std::thread::sleep(ttl + Duration::from_millis(20));
        assert!(!cache.contains(&id(7)), "2×TTL 経過後は忘れてよい");
    }

    #[test]
    fn false_positive_rate_is_within_budget() {
        let capacity = 50_000;
        let mut cache = SeenCache::with_fp_rate(capacity, DEFAULT_TTL_SECS, DEFAULT_FP_RATE);

        for n in 0..capacity as u32 {
            cache.insert(id(n));
        }

        // 未挿入の ID で誤検知率を測る
        let probes = 200_000u32;
        let mut false_positives = 0;
        for n in 0..probes {
            if cache.contains(&id(1_000_000 + n)) {
                false_positives += 1;
            }
        }

        let rate = f64::from(false_positives) / f64::from(probes);
        println!(
            "誤検知率: {:.5}% (設計値 {:.4}%), メモリ {:.1} KB",
            rate * 100.0,
            DEFAULT_FP_RATE * 100.0,
            cache.memory_bytes() as f64 / 1024.0
        );

        assert!(
            rate < DEFAULT_FP_RATE * 3.0,
            "誤検知率 {:.5} が設計値 {:.5} を大きく超えている",
            rate,
            DEFAULT_FP_RATE
        );
    }

    #[test]
    fn memory_footprint_is_reasonable() {
        let cache = SeenCache::default();
        let mb = cache.memory_bytes() as f64 / 1_048_576.0;

        println!(
            "容量 {} 件 x 2世代 = {:.2} MB",
            DEFAULT_CAPACITY, mb
        );

        // 旧実装は 50,000 件で約 4.4MB だった
        assert!(mb < 4.0, "既定設定で {:.2} MB は大きすぎる", mb);
    }
}
