use crate::error::{Result, AetherError};
use crate::net::seen_cache::SeenCache;
use crate::protocol::hint::HintPacket;
use crate::Config;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

/// ローカル購読者向けのバッファ段数
const LOCAL_HINT_BUFFER: usize = 1024;

/// Hint の TTL 初期値
pub const DEFAULT_HINT_TTL: u8 = 5;

/// 1バッチに詰め込める Hint の上限
///
/// 受信側のメモリを守るための上限。送信側の詰め込み量は
/// [`crate::net::hint_batcher::MAX_BATCH_SIZE`] で決まる。
pub const MAX_HINTS_PER_BATCH: usize = 256;

/// Hint を受け取ったノードが取るべき行動
#[derive(Debug, PartialEq)]
pub enum HintAction {
    /// 新規かつ TTL が残っている。同梱のパケットを隣接ピアへ拡散する
    ///
    /// バイト列ではなく `HintPacket` を返すのは、複数 Hint をまとめて
    /// 1パケットで送る際の再シリアライズを避けるため。
    Relay(HintPacket),
    /// 既知 または TTL 切れ。ここで止める
    Drop,
}

pub struct GossipServer {
    seen: Arc<Mutex<SeenCache>>,
    /// 新規 Hint をローカル購読者へ配る口
    ///
    /// Broadcast Veil の前提そのもの。全ノードが全 Hint を受け取り、
    /// 自分宛てかどうかは **手元でだけ** 判定する。
    /// 「これは自分宛てか」をネットワークへ問い合わせた時点で
    /// 受信者匿名性は消える。
    local: broadcast::Sender<HintPacket>,
    /// 受信 Hint に要求する PoW 難易度（19.2.1）
    ///
    /// 全ノードが全 Hint を受け取る Broadcast Veil では、生成がタダだと
    /// 安価なフラッドが網全体の帯域を焼く。これで生成にコストを課す。
    pow_difficulty: u32,
}

impl GossipServer {
    pub fn new(config: &Config) -> Self {
        let (local, _) = broadcast::channel(LOCAL_HINT_BUFFER);
        Self {
            seen: Arc::new(Mutex::new(SeenCache::default())),
            local,
            pow_difficulty: config.pow_difficulty as u32,
        }
    }

    /// 新規に受け取った Hint を購読する
    ///
    /// 遅い購読者は取りこぼす（`RecvError::Lagged`）。
    /// ここで詰まらせると Gossip の拡散そのものが止まるため、
    /// 取りこぼしを許す側に倒している。
    pub fn subscribe(&self) -> broadcast::Receiver<HintPacket> {
        self.local.subscribe()
    }

    /// 受信 Hint に要求する PoW 難易度（backlog 保存前の検証に使う）
    pub fn pow_difficulty(&self) -> u32 {
        self.pow_difficulty
    }

    /// backlog 経由で届いた Hint をローカル購読者へ配る（**再拡散しない**）
    ///
    /// オフライン明けの追いつき用。live gossip と違い TTL 減算も転送もせず、
    /// 手元の受信者に見せるだけ。PoW と重複はここでも確認する
    /// （backlog 経路にゴミや二重配送を通さない）。戻り値は「新規に配ったか」。
    pub async fn deliver_local(&self, packet: HintPacket) -> bool {
        if !packet.verify_pow(self.pow_difficulty) {
            return false;
        }
        {
            let mut seen = self.seen.lock().await;
            if !seen.insert(packet.id()) {
                return false;
            }
        }
        let _ = self.local.send(packet);
        true
    }

    /// Hint パケットを処理する
    ///
    /// 1. デシリアライズ
    /// 2. 重複チェック（TTL 非依存の ID で行う）
    /// 3. TTL をデクリメント。使い切っていたら破棄
    /// 4. 更新後のバイト列を返す
    pub async fn handle_hint(&self, hint_payload: &[u8]) -> Result<HintAction> {
        let packet: HintPacket = bincode::deserialize(hint_payload)
            .map_err(|e| AetherError::Protocol(format!("Invalid HintPacket: {}", e)))?;

        Ok(self.handle_hint_packet(packet).await)
    }

    /// デシリアライズ済みの Hint を処理する（バッチ受信用）
    pub async fn handle_hint_packet(&self, mut packet: HintPacket) -> HintAction {
        // PoW 検証を **seen 判定より前** に行う。
        //
        // 無効な Hint を SeenCache に入れてしまうと、攻撃者が偽 Hint で
        // dedup 枠を食い潰せる。検証（1 SHA-256）を先に通した Hint だけを
        // dedup・拡散の対象にする。
        if !packet.verify_pow(self.pow_difficulty) {
            return HintAction::Drop;
        }

        // 重複チェック。ID は TTL を含まないため、
        // 中継で TTL が変化しても同一パケットとして認識できる
        {
            let mut seen = self.seen.lock().await;
            if !seen.insert(packet.id()) {
                return HintAction::Drop;
            }
        }

        // TTL を減らす **前に** ローカルへ配る。
        //
        // TTL は「これ以上転送するか」だけを決めるもので、
        // 自分宛てかどうかとは無関係。使い切った Hint を捨ててから
        // 配ると、網の端にいるノードは自分宛ての Hint を
        // 最後の1ホップだけ取りこぼすことになる。
        let _ = self.local.send(packet.clone());

        // TTL を減らす。使い切っていたらここで止める
        if !packet.decrement_ttl() {
            return HintAction::Drop;
        }

        HintAction::Relay(packet)
    }

    /// バッチで届いた Hint 群を処理し、拡散すべきものだけを返す
    pub async fn handle_hint_batch(&self, payload: &[u8]) -> Result<Vec<HintPacket>> {
        let packets: Vec<HintPacket> = bincode::deserialize(payload)
            .map_err(|e| AetherError::Protocol(format!("Invalid Hint batch: {}", e)))?;

        if packets.len() > MAX_HINTS_PER_BATCH {
            return Err(AetherError::Protocol(format!(
                "Hint batch too large: {} (max {})",
                packets.len(),
                MAX_HINTS_PER_BATCH
            )));
        }

        let mut relay = Vec::new();
        for packet in packets {
            if let HintAction::Relay(p) = self.handle_hint_packet(packet).await {
                relay.push(p);
            }
        }
        Ok(relay)
    }

    /// 期限切れエントリを掃除する（定期タスクから呼ぶ）
    pub async fn cleanup(&self) {
        self.seen.lock().await.cleanup();
    }

    /// 観測された Hint レート (件/秒)
    ///
    /// 匿名集合の大きさの直接の推定値。
    /// Hint 放流の遅延窓 (`mailbox::hint_release`) がこれを使う。
    pub async fn observed_hint_rate(&self) -> f64 {
        self.seen.lock().await.observed_rate()
    }

    /// 保持中のエントリ数（デバッグ用）
    pub async fn seen_count(&self) -> usize {
        self.seen.lock().await.len()
    }

    /// 既に見た Hint か（**挿入せずに**確認する。Dandelion のフェイルセーフ用 / 3-2）
    pub async fn has_seen(&self, id: &[u8; 32]) -> bool {
        self.seen.lock().await.contains(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(tag: u8, ttl: u8) -> Vec<u8> {
        let p = HintPacket::new([tag; 4], [0u8; 12], vec![tag; 48], ttl);
        bincode::serialize(&p).unwrap()
    }

    /// dedup / TTL ロジックを見るための、PoW 検証を無効化した（難易度0）サーバ
    fn server() -> GossipServer {
        GossipServer::new(&Config {
            pow_difficulty: 0,
            ..Config::default()
        })
    }

    #[tokio::test]
    async fn unsolved_hint_is_dropped_when_pow_required() {
        // PoW を要求する網では、未解決（pow_nonce=0）の Hint は seen に入る前に落とす
        let s = GossipServer::new(&Config {
            pow_difficulty: 12,
            ..Config::default()
        });

        let unsolved = HintPacket::new([5; 4], [0u8; 12], vec![5; 48], 5);
        assert_eq!(
            s.handle_hint_packet(unsolved.clone()).await,
            HintAction::Drop,
            "PoW 未解決の Hint は拡散させない"
        );

        // 同じ Hint を解けば通る（＝落としたのは PoW 不足のためで、内容のせいではない）
        let mut solved = unsolved;
        solved.seal_pow(12).unwrap();
        assert!(
            matches!(s.handle_hint_packet(solved).await, HintAction::Relay(_)),
            "解いた Hint は拡散される"
        );
    }

    #[tokio::test]
    async fn new_hint_is_relayed_with_decremented_ttl() {
        let s = server();
        match s.handle_hint(&packet(1, 5)).await.unwrap() {
            HintAction::Relay(out) => {
                assert_eq!(out.ttl, 4, "中継のたびに TTL が減らなければ無限に回る");
            }
            HintAction::Drop => panic!("新規 Hint は中継されるべき"),
        }
    }

    #[tokio::test]
    async fn subscriber_sees_every_new_hint() {
        // Broadcast Veil の前提。全 Hint が手元に来ないと
        // 「自分宛てか」をローカルで判定できない
        let s = server();
        let mut rx = s.subscribe();

        s.handle_hint(&packet(7, 5)).await.unwrap();

        assert_eq!(rx.recv().await.unwrap().blind_tag, [7u8; 4]);
    }

    #[tokio::test]
    async fn exhausted_ttl_still_reaches_the_subscriber() {
        // TTL は「これ以上転送するか」だけを決める。自分宛てかとは無関係。
        // ここで配るのをやめると、網の端のノードは
        // 自分宛ての Hint を最後の1ホップぶん取りこぼす
        let s = server();
        let mut rx = s.subscribe();

        assert_eq!(s.handle_hint(&packet(8, 0)).await.unwrap(), HintAction::Drop);

        assert_eq!(
            rx.recv().await.unwrap().blind_tag,
            [8u8; 4],
            "転送は止めても、受信者本人には届けなければならない"
        );
    }

    #[tokio::test]
    async fn duplicate_hint_is_not_delivered_twice() {
        // 拡散で同じ Hint が何周も戻ってくる。都度配ると
        // 購読者は同じ本文を何度も取りに行くことになる
        let s = server();
        let mut rx = s.subscribe();

        s.handle_hint(&packet(9, 5)).await.unwrap();
        s.handle_hint(&packet(9, 5)).await.unwrap();

        assert_eq!(rx.recv().await.unwrap().blind_tag, [9u8; 4]);
        assert!(rx.try_recv().is_err(), "重複が購読者まで漏れている");
    }

    #[tokio::test]
    async fn duplicate_hint_is_dropped() {
        let s = server();
        assert!(matches!(s.handle_hint(&packet(2, 5)).await.unwrap(), HintAction::Relay(_)));
        assert_eq!(s.handle_hint(&packet(2, 5)).await.unwrap(), HintAction::Drop);
    }

    #[tokio::test]
    async fn exhausted_ttl_is_dropped() {
        let s = server();
        assert_eq!(
            s.handle_hint(&packet(3, 0)).await.unwrap(),
            HintAction::Drop,
            "TTL 0 のパケットは拡散を止める"
        );
    }

    #[tokio::test]
    async fn relayed_copy_is_recognised_as_duplicate() {
        // 隣人 A から TTL=5 で受け取り、隣人 B からは同じ Hint が TTL=3 で回ってくる状況
        let s = server();
        assert!(matches!(s.handle_hint(&packet(4, 5)).await.unwrap(), HintAction::Relay(_)));
        assert_eq!(
            s.handle_hint(&packet(4, 3)).await.unwrap(),
            HintAction::Drop,
            "TTL が違うだけの同一 Hint を新規と誤認してはならない"
        );
    }

    #[tokio::test]
    async fn malformed_payload_is_an_error() {
        let s = server();
        assert!(s.handle_hint(b"not a hint").await.is_err());
    }
}
