use crate::{Config, Result, AetherError};
use tokio::sync::mpsc;
use tokio::time::{self, Duration, Instant};
use quinn::SendStream;
use rand::Rng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
// use tokio::io::AsyncWriteExt; // Unused, SendStream implements AsyncWrite

/// シェーピング設定
#[derive(Debug, Clone)]
pub struct ShapingConfig {
    pub target_fps: u32,               // 目標FPS (例: 30)
    pub i_frame_interval_secs: f32,    // Iフレーム(大容量パケット)の間隔
    pub p_frame_avg_size: usize,       // Pフレーム(通常パケット)の平均サイズ
    pub p_frame_std_dev: usize,        // Pフレームサイズの標準偏差
    pub jitter_ms: u32,                //送信間隔の揺らぎ(ミリ秒)
    pub enable_cover_traffic: bool,    // カバートラフィックを送るか
}

impl From<&Config> for ShapingConfig {
    fn from(c: &Config) -> Self {
        Self {
            target_fps: c.target_fps,
            i_frame_interval_secs: 2.0, // 仮のデフォルト
            p_frame_avg_size: 500,
            p_frame_std_dev: 200,
            jitter_ms: 10, // 仮
            enable_cover_traffic: c.enable_cover_traffic,
        }
    }
}

/// シェーピング戦略のインターフェース
pub trait ShapingStrategy: Send + Sync {
    /// 次の送信までの待機時間を計算
    fn next_gap(&mut self) -> Duration;
    /// 次に送信すべきパケットサイズ（ダミーの場合）
    /// Noneを返せば今は送らない
    fn next_packet_size(&mut self, is_i_frame: bool) -> usize;
}

/// Zoom/Google Meet風のVBRモデル実装
pub struct VbrStrategy {
    config: ShapingConfig,
    rng: rand::rngs::StdRng,
}

impl VbrStrategy {
    pub fn new(config: ShapingConfig) -> Self {
        use rand::SeedableRng;
        Self {
            config,
            rng: rand::rngs::StdRng::from_entropy(),
        }
    }
}

impl ShapingStrategy for VbrStrategy {
    fn next_gap(&mut self) -> Duration {
        let base_interval = 1.0 / self.config.target_fps as f64;
        let jitter = self.rng.gen_range(0..=self.config.jitter_ms) as f64 / 1000.0;
        let gap = if self.rng.gen_bool(0.5) {
            base_interval + jitter
        } else {
            (base_interval - jitter).max(0.001)
        };
        Duration::from_secs_f64(gap)
    }

    fn next_packet_size(&mut self, is_i_frame: bool) -> usize {
        if is_i_frame {
            // Iフレーム: 5KB - 15KB
            self.rng.gen_range(5000..15000)
        } else {
            // Pフレーム: 正規分布に近い乱数 (簡易実装)
            let base = self.config.p_frame_avg_size as f64;
            let dev = self.config.p_frame_std_dev as f64;
            // Box-Muller transform for normal distribution approximation
            // Rust 2024ではgenが予約語になったため、r#genを使用するか明示的にメソッドを呼ぶ
            let u1: f64 = self.rng.r#gen();
            let u2: f64 = self.rng.r#gen();
            let z0 = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();

            let size = base + z0 * dev;
            size.max(0.0) as usize
        }
    }
}

/// トラフィックシェーパー本体
pub struct TrafficShaper {
    tx: mpsc::Sender<Vec<u8>>,
    shutdown: Arc<AtomicBool>,
}

impl TrafficShaper {
    /// シェーパーを開始し、入力用チャンネルを返す
    /// send_stream: QUICの送信ストリーム
    /// config: 設定
    pub fn spawn(mut send_stream: SendStream, config: ShapingConfig) -> Self {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100); // 送信待ちキュー
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        tokio::spawn(async move {
            let mut strategy = VbrStrategy::new(config.clone());
            let mut last_i_frame = Instant::now();

            loop {
                if shutdown_clone.load(Ordering::Relaxed) {
                    break;
                }

                // 1. 次の送信タイミングまで待機
                let gap = strategy.next_gap();
                time::sleep(gap).await;

                // 2. Iフレームタイミングか判定
                let now = Instant::now();
                let is_i_frame = now.duration_since(last_i_frame).as_secs_f32() >= config.i_frame_interval_secs;
                if is_i_frame {
                    last_i_frame = now;
                }

                // 3. 送信データがあるか確認
                let mut packet_data = Vec::new();
                let mut is_dummy = false;

                match rx.try_recv() {
                    Ok(real_data) => {
                        packet_data = real_data;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                         // 実データなし
                         if config.enable_cover_traffic {
                             is_dummy = true;
                             let size = strategy.next_packet_size(is_i_frame);
                             if size > 0 {
                                 packet_data = vec![0u8; size];
                                 rand::thread_rng().fill(&mut packet_data[..]);
                             }
                         }
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }

                if !packet_data.is_empty() {
                    // ワイヤーフォーマット: [Flags(1B)] + [Payload]
                    // Flags: 0x00 = Dummy, 0x01 = Real
                    let flag = if is_dummy { 0x00u8 } else { 0x01u8 };

                    // パケット構築
                    let mut final_payload = Vec::with_capacity(1 + packet_data.len());
                    final_payload.push(flag);
                    final_payload.extend_from_slice(&packet_data);

                    // SendStream implements AsyncWrite directly but needs trait import in scope?
                    // Actually quinn::SendStream implements tokio::io::AsyncWrite

                    if send_stream.write_all(&final_payload).await.is_err() {
                        break;
                    }
                }
            }

            let _ = send_stream.finish();
        });

        Self { tx, shutdown }
    }

    /// データを送信キューに入れる
    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        self.tx.send(data).await.map_err(|_| AetherError::Network(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
    }

    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}
