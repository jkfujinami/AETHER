//! Hint 放流タイミングの決定 (設計書 18.4.5 改訂)
//!
//! # 何を守るのか
//!
//! Onion によって Hint の初出点は**出口リレー**になるため、
//! Winny の「初出ノード = 一次放流者」は既に成立しない。
//! 時間分離が守っているのは別の相関である。
//!
//! ```text
//! ガードが見るもの : 「この IP が時刻 T まで D 秒間アップロードしていた」
//! 全ノードが見るもの: 「時刻 T+ε に Hint が現れた」
//! ```
//!
//! **Hint の出現時刻は Broadcast Veil で全員に見える。**
//! ε が小さく D が特徴的なら、出口リレーを取らなくても紐づく。
//!
//! # だから小さい送信には要らない
//!
//! この相関が成立するのは PUT が観測可能なエンベロープを作る場合だけ。
//! 定常の Gossip 中継トラフィックより十分小さい送信は、
//! **自分が常時流している雑音に沈む**ので追加の遅延に意味がない。
//!
//! チャット1通（数シャードで約10KB）は中継トラフィック 0.1 秒分。
//! 4GB のファイルは数時間分。この差がそのまま方針の差になる。
//!
//! # 遅延量の決め方
//!
//! 「数分〜数十分」のような根拠のない値ではなく、
//! **達成したい匿名集合の大きさから逆算する**。
//!
//! 幸い Broadcast Veil では**他の投稿レートがローカルで直接観測できる**
//! （全 Hint が自分に届くため）。これは他の設計では得られない性質。

use rand::Rng;
use std::time::Duration;

/// 定常中継トラフィックの何秒ぶんまでを「埋もれる」とみなすか
///
/// これ以下の送信は、自分が常時流している Gossip 中継の変動に紛れる。
const NOISE_WINDOW_SECS: f64 = 8.0;

/// 遅延窓をアップロード継続時間の何倍取るか
///
/// 窓がエンベロープ幅と同程度だと、他のアップロードのエンベロープと
/// 重ならず区別されてしまう。
const ENVELOPE_FACTOR: f64 = 10.0;

/// 待てる上限をアップロード所要時間の何倍にするか
///
/// 2時間かけて上げたファイルなら追加で数時間待つのは比例するが、
/// 4秒で送ったものに6時間待たせるのは比例しない。
const PATIENCE_FACTOR: f64 = 2.0;

/// 待てる上限の下限値
///
/// **ブートストラップ期の生命線。**
/// 網が空だと観測レートが 0 になり、匿名集合から逆算した窓は無限大になる。
/// そこで上限まで待たせると「誰もいない網で6時間待たされる」ことになり、
/// 人が増える前に離脱する。しかも**待っても匿名集合は生まれない**ので、
/// コストだけ払って利益がゼロという最悪の交換になっている。
const MIN_PATIENCE_SECS: f64 = 60.0;

/// これ未満の匿名集合しか得られないなら、待つ意味がない
///
/// エンベロープ条件は「他のアップロードのエンベロープと重ねる」ためのもので、
/// **重なる相手がいなければ窓を広げる意味もない**。
/// 空の網で 4GB を上げたときに 4.4 時間待たせても、得られる匿名集合はゼロのまま。
/// 利益が測定可能な水準に達しない限り、コストを払わせない。
const MIN_USEFUL_ANONYMITY_SET: f64 = 2.0;

/// 既定の目標匿名集合サイズ（この件数の他投稿に紛れる）
pub const DEFAULT_TARGET_ANONYMITY_SET: f64 = 100.0;

/// 遅延の上限
///
/// これ以上待っても実用性を損なうだけなので打ち切る。
/// 上限に張り付いている場合、その網は匿名集合が不足している。
pub const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(6 * 3600);

/// Gossip 中継に使う既定の帯域 (bytes/sec)
///
/// 設計書 18.3-E の 1 Mbps 予算に対応。
pub const DEFAULT_RELAY_THROUGHPUT_BPS: f64 = 125_000.0;

/// 放流方針のモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseMode {
    /// 遅延を一切かけない
    ///
    /// ネットワーク構築中に使う。匿名集合が存在しない段階では
    /// 時間分離は利益ゼロのコストでしかない。
    Disabled,
    /// 既定。**待てる範囲で待ち、届かない分は正直に報告する**
    ///
    /// 網が育つにつれて自動的に効きが強くなる。手動の切り替えは要らない。
    Adaptive,
    /// 目標匿名集合に届くまで上限いっぱい待つ
    ///
    /// 使用感より秘匿を優先する場合。大容量の公開向け。
    Strict,
}

/// 放流判断の内訳
///
/// **なぜその待ち時間になったのかを外から見えるようにする。**
/// 匿名性の強度が黙って変わるのが一番まずい。
#[derive(Debug, Clone, PartialEq)]
pub enum ReleaseStatus {
    /// 中継トラフィックに埋もれるので遅延不要
    BuriedInNoise { noise_floor_bytes: u64 },
    /// モードで無効化されている
    Disabled,
    /// 待ったが目標匿名集合には届かない
    Degraded {
        window: Duration,
        achieved_set: f64,
        target_set: f64,
    },
    /// 目標を満たしている
    Active {
        window: Duration,
        achieved_set: f64,
    },
}

/// 送信の特徴
#[derive(Debug, Clone, Copy)]
pub struct UploadProfile {
    /// 実際にネットワークへ出したバイト数（シャード込み）
    pub bytes: u64,
    /// 送出にかかった時間
    pub duration: Duration,
}

/// 放流タイミングの方針
#[derive(Debug, Clone)]
pub struct ReleasePolicy {
    /// 自分が定常的に中継している帯域 (bytes/sec)
    ///
    /// **中継していない（0）なら何も埋もれない。**
    /// 中継しないほど自分の送信が目立つ、という関係がそのまま出る。
    pub relay_throughput_bps: f64,
    /// 観測された Hint レート (件/秒)
    ///
    /// Broadcast Veil なので全 Hint が自分に届く。
    /// つまり匿名集合の大きさを直接測れる。
    pub observed_hint_rate: f64,
    /// 目標匿名集合サイズ
    pub target_anonymity_set: f64,
    /// 遅延の絶対上限
    pub max_delay: Duration,
    /// モード
    pub mode: ReleaseMode,
}

impl Default for ReleasePolicy {
    fn default() -> Self {
        Self {
            relay_throughput_bps: DEFAULT_RELAY_THROUGHPUT_BPS,
            observed_hint_rate: 0.0,
            target_anonymity_set: DEFAULT_TARGET_ANONYMITY_SET,
            max_delay: DEFAULT_MAX_DELAY,
            mode: ReleaseMode::Adaptive,
        }
    }
}

impl ReleasePolicy {
    /// ネットワーク構築中向け。遅延を一切かけない
    pub fn bootstrap() -> Self {
        Self {
            mode: ReleaseMode::Disabled,
            ..Default::default()
        }
    }
}

impl ReleasePolicy {
    /// 中継トラフィックに埋もれる送信サイズの上限
    pub fn noise_floor_bytes(&self) -> u64 {
        (self.relay_throughput_bps * NOISE_WINDOW_SECS).max(0.0) as u64
    }

    /// この送信を遅延させる必要があるか
    pub fn needs_delay(&self, upload: &UploadProfile) -> bool {
        upload.bytes > self.noise_floor_bytes()
    }

    /// この送信に対して待てる上限
    ///
    /// アップロード所要時間に比例させる。
    /// 4秒で送ったものに6時間待たせるのは比例しない。
    fn patience(&self, upload: &UploadProfile) -> f64 {
        (upload.duration.as_secs_f64() * PATIENCE_FACTOR)
            .max(MIN_PATIENCE_SECS)
            .min(self.max_delay.as_secs_f64())
    }

    /// 匿名集合とエンベロープから求まる「本来必要な」窓幅
    fn required_window(&self, upload: &UploadProfile) -> f64 {
        // 匿名集合から: W ≥ target / rate
        let anonymity_window = if self.observed_hint_rate > 0.0 {
            self.target_anonymity_set / self.observed_hint_rate
        } else {
            // 観測 0 = 紛れる相手がいない。いくら待っても集合は生まれない
            f64::INFINITY
        };

        // エンベロープから: W ≥ factor * D
        let envelope_window = upload.duration.as_secs_f64() * ENVELOPE_FACTOR;

        anonymity_window.max(envelope_window)
    }

    /// 遅延窓の幅
    ///
    /// 本来必要な幅を、**待てる上限で頭打ちにする**。
    /// 網が小さいほど必要幅は無限大に発散するが、
    /// そこで実際に待たせると「誰もいない網で待たされて離脱」になる。
    /// しかも待っても匿名集合は生まれないので、利益ゼロのコストでしかない。
    pub fn delay_window(&self, upload: &UploadProfile) -> Duration {
        if self.mode == ReleaseMode::Disabled || !self.needs_delay(upload) {
            return Duration::ZERO;
        }

        let required = self.required_window(upload);

        let cap = match self.mode {
            // 目標に届かなくても上限まで待つ
            ReleaseMode::Strict => self.max_delay.as_secs_f64(),
            // 送信規模に比例した範囲でだけ待つ
            ReleaseMode::Adaptive => self.patience(upload),
            ReleaseMode::Disabled => unreachable!("上で早期 return 済み"),
        };

        let window = required.min(cap).max(0.0);

        // 待って得られる匿名集合が測定可能な水準に達しないなら、
        // 待つのは利益ゼロのコストでしかない (Strict は明示的な選択なので例外)
        if self.mode == ReleaseMode::Adaptive
            && window * self.observed_hint_rate < MIN_USEFUL_ANONYMITY_SET
        {
            return Duration::ZERO;
        }

        Duration::from_secs_f64(window)
    }

    /// 判断の内訳
    ///
    /// 匿名性の強度が黙って変わるのが一番まずいので、
    /// 「なぜその待ち時間になったか」「目標に届いているか」を返す。
    pub fn status(&self, upload: &UploadProfile) -> ReleaseStatus {
        if self.mode == ReleaseMode::Disabled {
            return ReleaseStatus::Disabled;
        }
        if !self.needs_delay(upload) {
            return ReleaseStatus::BuriedInNoise {
                noise_floor_bytes: self.noise_floor_bytes(),
            };
        }

        let window = self.delay_window(upload);
        let achieved_set = window.as_secs_f64() * self.observed_hint_rate;

        if achieved_set >= self.target_anonymity_set {
            ReleaseStatus::Active {
                window,
                achieved_set,
            }
        } else {
            ReleaseStatus::Degraded {
                window,
                achieved_set,
                target_set: self.target_anonymity_set,
            }
        }
    }

    /// 実際に待つ時間を決める
    ///
    /// 窓内の一様乱数。固定遅延だと相関が平行移動するだけで壊れない。
    pub fn delay_for(&self, upload: &UploadProfile) -> Duration {
        let window = self.delay_window(upload);
        if window.is_zero() {
            return Duration::ZERO;
        }

        let secs = rand::thread_rng().gen_range(0.0..=window.as_secs_f64());
        Duration::from_secs_f64(secs)
    }

    /// 実際に得られる匿名集合の推定値
    ///
    /// 上限に張り付いて目標に届かない場合、その網は活動量が足りない。
    /// 運用者が把握できるよう表に出しておく。
    pub fn effective_anonymity_set(&self, upload: &UploadProfile) -> f64 {
        self.delay_window(upload).as_secs_f64() * self.observed_hint_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upload(bytes: u64, secs: f64) -> UploadProfile {
        UploadProfile {
            bytes,
            duration: Duration::from_secs_f64(secs),
        }
    }

    fn policy(hint_rate: f64) -> ReleasePolicy {
        ReleasePolicy {
            observed_hint_rate: hint_rate,
            ..Default::default()
        }
    }

    #[test]
    fn chat_sized_messages_are_not_delayed() {
        // チャット1通は中継トラフィックに埋もれるので、待たせる理由がない
        let p = policy(10.0);
        let chat = upload(10 * 1024, 0.1);

        assert!(!p.needs_delay(&chat));
        assert_eq!(p.delay_for(&chat), Duration::ZERO);
    }

    #[test]
    fn noise_floor_tracks_relay_throughput() {
        // 1 Mbps 中継なら約 1MB まで埋もれる
        let p = policy(10.0);
        assert_eq!(p.noise_floor_bytes(), 1_000_000);

        assert!(!p.needs_delay(&upload(999_999, 1.0)));
        assert!(p.needs_delay(&upload(1_000_001, 1.0)));
    }

    #[test]
    fn not_relaying_means_nothing_is_hidden() {
        // 中継していなければカバートラフィックが無く、何も埋もれない
        let p = ReleasePolicy {
            relay_throughput_bps: 0.0,
            ..policy(10.0)
        };

        assert_eq!(p.noise_floor_bytes(), 0);
        assert!(p.needs_delay(&upload(1, 0.01)), "中継しないなら小さくても目立つ");
    }

    #[test]
    fn window_scales_with_upload_size() {
        // 大きいほど長く待つ
        let p = policy(1000.0); // 匿名集合側は十分速く満たされる

        let small = p.delay_window(&upload(2_000_000, 10.0));
        let large = p.delay_window(&upload(4_000_000_000, 20_000.0));

        assert!(large > small, "大きいアップロードほど窓が広がるべき");
    }

    #[test]
    fn window_scales_inversely_with_network_activity() {
        // 閑散な網ほど長く待つ必要がある
        let busy = policy(100.0).delay_window(&upload(10_000_000, 1.0));
        let quiet = policy(1.0).delay_window(&upload(10_000_000, 1.0));

        assert!(quiet > busy, "投稿が少ない網ほど窓を広げる必要がある");
    }

    #[test]
    fn window_reaches_the_anonymity_target() {
        // 目標匿名集合 100件 / 観測 10件/秒 → 10秒あれば足りる
        let p = policy(10.0);
        let big = upload(10_000_000, 1.0);

        let window = p.delay_window(&big);
        assert!(
            (window.as_secs_f64() - 10.0).abs() < 0.01,
            "匿名集合の要求から逆算されていない: {:?}",
            window
        );
        assert!((p.effective_anonymity_set(&big) - 100.0).abs() < 0.1);
    }

    #[test]
    fn envelope_dominates_for_very_long_uploads() {
        // 送出に長時間かかる場合、匿名集合が足りていても
        // エンベロープ幅の方が支配的になる
        let p = ReleasePolicy {
            mode: ReleaseMode::Strict,
            ..policy(1_000_000.0) // 匿名集合は一瞬で満たされる
        };
        let long_upload = upload(4_000_000_000, 3600.0);

        let window = p.delay_window(&long_upload);
        assert!(
            window.as_secs_f64() >= 3600.0 * ENVELOPE_FACTOR - 1.0
                || window == p.max_delay,
            "エンベロープ幅が反映されていない: {:?}",
            window
        );
    }

    // ---- ブートストラップ期の挙動 ----
    //
    // 網が小さいほど「本来必要な窓」は無限大に発散する。
    // そこで実際に待たせると、まだ誰もいない段階で最大の苦痛を払わされ、
    // しかも待っても匿名集合は生まれない（利益ゼロのコスト）。
    // 人が増える前に離脱するので、網が育つ経路そのものを塞ぐ。

    #[test]
    fn empty_network_never_waits() {
        // 紛れる相手がゼロなら、どれだけ待っても匿名集合は生まれない。
        // 大容量でも待たせない（エンベロープ条件も重なる相手がいなければ無意味）
        let p = policy(0.0);

        for (bytes, secs) in [(2_000_000u64, 1.0f64), (4_000_000_000, 8_000.0)] {
            assert_eq!(
                p.delay_window(&upload(bytes, secs)),
                Duration::ZERO,
                "空の網で {} バイトの送信を待たせている",
                bytes
            );
        }
    }

    #[test]
    fn delay_starts_once_there_is_someone_to_hide_among() {
        // 利益が出る水準まで網が育ったら、自動で効き始める
        let big = upload(2_000_000, 1.0);

        assert_eq!(policy(0.0).delay_window(&big), Duration::ZERO);
        assert_eq!(policy(0.001).delay_window(&big), Duration::ZERO, "0.06件では待つ価値がない");
        assert!(policy(1.0).delay_window(&big) > Duration::ZERO, "60件紛れるなら待つ価値がある");
    }

    #[test]
    fn patience_is_proportional_to_upload_effort() {
        // 4秒で送ったものに6時間待たせるのは比例しない
        let p = policy(1.0);

        let quick = p.delay_window(&upload(2_000_000, 4.0));
        let slow = p.delay_window(&upload(4_000_000_000, 8_000.0));

        assert!(quick.as_secs_f64() <= MIN_PATIENCE_SECS + 1.0);
        assert!(
            slow > quick,
            "時間をかけて上げたものほど長く待てるはず"
        );
        assert!(
            slow.as_secs_f64() <= 8_000.0 * PATIENCE_FACTOR + 1.0,
            "アップロード所要時間に比例していない: {:?}",
            slow
        );
    }

    #[test]
    fn bootstrap_mode_never_delays() {
        let p = ReleasePolicy {
            observed_hint_rate: 0.0,
            ..ReleasePolicy::bootstrap()
        };

        assert_eq!(p.delay_window(&upload(4_000_000_000, 8_000.0)), Duration::ZERO);
        assert_eq!(p.status(&upload(4_000_000_000, 8_000.0)), ReleaseStatus::Disabled);
    }

    #[test]
    fn strict_mode_still_waits_when_the_network_is_thin() {
        // 使用感より秘匿を優先したい場合の逃げ道は残す
        let p = ReleasePolicy {
            mode: ReleaseMode::Strict,
            ..policy(0.0)
        };

        assert_eq!(p.delay_window(&upload(2_000_000, 1.0)), p.max_delay);
    }

    #[test]
    fn status_reports_degradation_instead_of_hiding_it() {
        // 匿名性の強度が黙って変わるのが一番まずい
        let p = policy(0.5);
        let big = upload(2_000_000, 1.0);

        match p.status(&big) {
            ReleaseStatus::Degraded { achieved_set, target_set, .. } => {
                assert!(achieved_set < target_set);
            }
            other => panic!("目標未達が報告されていない: {:?}", other),
        }
    }

    #[test]
    fn status_reports_success_when_the_network_is_healthy() {
        let p = policy(100.0);
        let big = upload(2_000_000, 1.0);

        assert!(matches!(p.status(&big), ReleaseStatus::Active { .. }));
    }

    #[test]
    fn status_explains_why_small_sends_are_not_delayed() {
        let p = policy(100.0);
        assert!(matches!(
            p.status(&upload(10_240, 0.1)),
            ReleaseStatus::BuriedInNoise { .. }
        ));
    }

    #[test]
    fn protection_strengthens_as_the_network_grows() {
        // 手動で切り替えなくても、網が育てば自動的に効きが強くなること
        let big = upload(2_000_000, 1.0);

        let sets: Vec<f64> = [0.0, 0.5, 1.0, 10.0, 100.0]
            .iter()
            .map(|r| policy(*r).effective_anonymity_set(&big))
            .collect();

        for pair in sets.windows(2) {
            assert!(pair[1] >= pair[0], "投稿が増えても匿名集合が伸びていない: {:?}", sets);
        }
        assert!(sets[0] < 1.0, "空の網では匿名集合ゼロ");
        assert!(sets[4] >= 100.0, "活発な網では目標に到達すべき");
    }

    #[test]
    fn window_is_capped() {
        let p = ReleasePolicy { mode: ReleaseMode::Strict, ..policy(0.000_001) };
        assert!(p.delay_window(&upload(10_000_000, 1.0)) <= p.max_delay);
    }

    #[test]
    fn delay_stays_within_the_window() {
        let p = policy(10.0);
        let big = upload(10_000_000, 1.0);
        let window = p.delay_window(&big);

        for _ in 0..200 {
            let d = p.delay_for(&big);
            assert!(d <= window, "遅延が窓を超えている: {:?} > {:?}", d, window);
        }
    }

    #[test]
    fn delay_is_actually_randomised() {
        // 固定遅延だと相関が平行移動するだけで壊れない
        let p = policy(1.0);
        let big = upload(10_000_000, 1.0);

        let samples: Vec<u64> = (0..50).map(|_| p.delay_for(&big).as_millis() as u64).collect();
        let unique: std::collections::HashSet<_> = samples.iter().collect();

        assert!(unique.len() > 40, "遅延がばらついていない");
    }

    #[test]
    fn reports_shortfall_in_anonymity_set() {
        // 上限に張り付いて目標に届かない状況を検出できること
        let p = policy(0.001); // 1000秒に1件しか投稿がない
        let big = upload(10_000_000, 1.0);

        assert!(
            p.effective_anonymity_set(&big) < p.target_anonymity_set,
            "目標未達を検出できていない"
        );
    }
}
