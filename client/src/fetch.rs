//! 取得 ── 索引の検索・本体の取得
//!
//! どれも [`PullSession`](crate::pull::PullSession) の上で行う。要求は 3 ホップ回路で出し、
//! 返信は Inbound Tunnel で戻る。保持者に自分の IP は見えない。
//!
//! # 待ち方
//!
//! 「無い」という返事は来ない（不在を第三者に晒さないため保持者は黙る）。だから
//! 上限時間は要るが、**揃ったらすぐ返す**。決め打ちで上限まで待たない。
//! 複数の対象は**まとめて要求して並行に集める**（1 つずつ上限まで待たない）。

use crate::board::{Board, build_board};
use crate::client::AetherClient;
use crate::error::Result;
use crate::events;
use crate::pull::PullSession;
use crate::boards::BoardId;
use aether_core::mailbox::chunk::{self, Manifest, ManifestV2, StripeV2};
use aether_core::mailbox::index::IndexDescriptor;
use aether_core::mailbox::schrodinger::{K_REPLICAS, SchrodingerMailbox};
use aether_core::mailbox::sharding::{DATA_SHARDS, TOTAL_SHARDS};
use aether_core::mailbox::sharding_v2;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// 索引の返信を待つ上限（何も無いときはここまで待つ）
const SEARCH_WAIT: Duration = Duration::from_secs(8);
/// 索引の返信が途切れたら打ち切るまでの静けさ
///
/// 保持者は K 台いて、返信は少しずつずれて届く。最後の新着からこれだけ何も来なければ
/// 出揃ったとみなす。
const SEARCH_QUIET: Duration = Duration::from_millis(1500);
/// 本体・チャンクを待つ上限
const OBJECT_WAIT: Duration = Duration::from_secs(15);
/// 返信の到着を見に行く間隔
const POLL: Duration = Duration::from_millis(100);
/// 段 1（予備のシャードと 2 番目の担当へ広げる）までの待ち
///
/// 要求は回路・保持者・返信トンネルを通り、試験網の往復は数百 ms。その数倍待って
/// 揃わなければ、遅いか落ちた保持者に当たったとみなす。実網で測って詰める。
/// 早すぎると下りが減らず、遅すぎると取得が遅れる。
const HEDGE_1: Duration = Duration::from_secs(2);
/// 段 2（残りの担当すべてへ広げる）までの待ち
///
/// 段 1 でも揃わないのは、近い担当が軒並み不在という場合。上限 `OBJECT_WAIT`（15 秒）に
/// 余裕を残して最後の手を打てるよう、`HEDGE_1` の倍強にしている。
const HEDGE_2: Duration = Duration::from_secs(5);

/// 経過時間に応じて、この時点までに送るべき `(シャード index, 担当の順位)` の組を返す
///
/// 復元に要るのは `DATA_SHARDS` 個だけなので、まず最も近い担当へ必要な分だけ要求し、
/// 揃わなければ段階的に広げる（Part 23 の 8 章）。段は単調で、前の段の組は後にも含まれる。
/// 重複は無い。
fn hedge_plan(elapsed: Duration) -> Vec<(u8, usize)> {
    let mut plan = Vec::new();
    // 段 0: データシャードを一番近い担当へ
    for i in 0..DATA_SHARDS {
        plan.push((i as u8, 0));
    }
    if elapsed >= HEDGE_1 {
        // 段 1: 予備のシャードを一番近い担当へ、データシャードを 2 番目の担当へ
        for i in DATA_SHARDS..TOTAL_SHARDS {
            plan.push((i as u8, 0));
        }
        for i in 0..DATA_SHARDS {
            plan.push((i as u8, 1));
        }
    }
    if elapsed >= HEDGE_2 {
        // 段 2: まだ送っていない組すべて
        for rank in 0..K_REPLICAS {
            for i in 0..TOTAL_SHARDS {
                let want = (i as u8, rank);
                if !plan.contains(&want) {
                    plan.push(want);
                }
            }
        }
    }
    plan
}

/// 同時に要求しておくストライプの数（v2 の大きなファイル）
///
/// 返信は自分のノードの Mailbox に一旦入る。これは**他人から預かった中身と同じ保管庫**
/// （既定 100MB）なので、全ストライプを一斉に要求すると、返信が溢れて預かり物を追い出す。
/// 1 本が揃うたびに次の 1 本を要求する滑る窓にして、受け箱に溜まる量を
/// 最悪でも `4 × (16 + m) × 256KiB`（m=27 で約 43MB）に抑える。
const V2_STRIPES_IN_FLIGHT: usize = 4;
/// 1 ストライプの最初の要求から、揃うまで待つ上限
///
/// 1 ストライプは k+m 枚を別々の保持者から集める。段階的に広げる `HEDGE_1`（2 秒）の後に
/// パリティも全部要求した状態で、落ちた保持者を見切って待ち続けないための上限。
/// `OBJECT_WAIT`（15 秒）より長いのは、1 回の要求で 4MiB 分（16 枚）を回路と返信トンネルに流すため。
const V2_STRIPE_WAIT: Duration = Duration::from_secs(30);
/// 取得の進み具合を知らせる間隔
const V2_PROGRESS_EVERY: Duration = Duration::from_secs(1);

/// 滑る窓 ── 同時に要求中のストライプを `limit` 本までにして、1 本終わるたびに次を始める
struct StripeWindow {
    total: usize,
    limit: usize,
    next: usize,
    active: Vec<usize>,
    stopped: bool,
}

impl StripeWindow {
    fn new(total: usize, limit: usize) -> Self {
        Self { total, limit, next: 0, active: Vec::new(), stopped: false }
    }

    /// 窓に空きがあれば新しく始めるストライプを返す（順番どおり）
    fn start_more(&mut self) -> Vec<usize> {
        let mut started = Vec::new();
        while !self.stopped && self.active.len() < self.limit && self.next < self.total {
            self.active.push(self.next);
            started.push(self.next);
            self.next += 1;
        }
        started
    }

    /// そのストライプの要求を終える（揃った・見切った）
    fn finish(&mut self, stripe: usize) {
        self.active.retain(|&i| i != stripe);
    }

    /// これ以上新しいストライプを始めない（1 本でも取れなければ全体が失敗するため）
    fn stop_launching(&mut self) {
        self.stopped = true;
    }

    /// 要求中が無く、これ以上始めるものも無い
    fn is_finished(&self) -> bool {
        self.active.is_empty() && (self.stopped || self.next >= self.total)
    }

    /// 始めなかったストライプの数
    fn not_started(&self) -> usize {
        self.total - self.next
    }
}

/// ストライプ 1 本の取得状態
#[derive(Default)]
struct StripeState {
    /// データ k 個 → パリティ m 個の順。ハッシュが合って届いたものだけが入る
    got: Vec<Option<Vec<u8>>>,
    started: Option<tokio::time::Instant>,
    parity_requested: bool,
    done: bool,
}

impl StripeState {
    fn have(&self) -> usize {
        self.got.iter().filter(|s| s.is_some()).count()
    }
}

/// 返信 1 枚を振り分ける。表に載る**すべての位置**を埋める（同じ中身のチャンクは同じハッシュ）
///
/// 長さが `V2_SHARD_BYTES` でない返信と、表に無いハッシュの返信は捨てる。
/// 終わったストライプの位置は埋めない。何か 1 か所でも埋まれば true。
fn route_reply(
    routes: &HashMap<[u8; 32], Vec<(usize, usize)>>,
    states: &mut [StripeState],
    reply: &[u8],
) -> bool {
    if reply.len() != chunk::V2_SHARD_BYTES {
        return false;
    }
    let Some(positions) = routes.get(&chunk::shard_hash(reply)) else {
        return false;
    };
    let mut filled = false;
    for &(si, pos) in positions {
        let Some(st) = states.get_mut(si) else { continue };
        if st.done {
            continue;
        }
        if let Some(slot) = st.got.get_mut(pos)
            && slot.is_none()
        {
            *slot = Some(reply.to_vec());
            filled = true;
        }
    }
    filled
}

/// このストライプで今要求するシャードのハッシュ
///
/// まずデータ k 個、`with_parity` ならパリティ m 個も。届いた位置、すでに要求したハッシュ
/// （他のストライプや前の段で）は含めない ── 同じハッシュを二度要求しない。
fn stripe_requests(
    stripe: &StripeV2,
    state: &StripeState,
    requested: &HashSet<[u8; 32]>,
    with_parity: bool,
) -> Vec<[u8; 32]> {
    let k = stripe.data as usize;
    let end = if with_parity { stripe.shard_hashes.len() } else { k };
    let mut seen = HashSet::new();
    (0..end)
        .filter(|&pos| state.got.get(pos).is_some_and(Option::is_none))
        .map(|pos| stripe.shard_hashes[pos])
        .filter(|h| !requested.contains(h) && seen.insert(*h))
        .collect()
}

/// 取得した内容
#[derive(Debug, Clone, Serialize)]
pub struct Fetched {
    /// チャンク化されたファイルなら Manifest の名前
    pub name: Option<String>,
    pub bytes: Vec<u8>,
}

impl AetherClient {
    /// 板の索引を引いて、スレッドの並びとして返す
    pub async fn search(&self, board: &BoardId) -> Result<Board> {
        let (found, pow) = self.search_raw(board).await?;
        Ok(build_board(&found, &pow, aether_core::protocol::hint::current_timestamp()))
    }

    /// 索引の記述子をそのまま返す（掲示板の表示を呼び出し側で組む用）
    pub async fn search_raw(&self, board: &BoardId) -> Result<(Vec<IndexDescriptor>, Vec<u32>)> {
        let k_pub = board.key();
        let session = self.open_pull_session(HashMap::new()).await?;
        events::progress(&self.events, format!("板 #{} の索引を引いています...", board.fingerprint()));

        session.mailbox.query_index(&k_pub, &session.reply_to).await?;

        let mut seen = HashSet::new();
        let mut found = Vec::new();
        let mut pow = Vec::new();
        let until = tokio::time::Instant::now() + SEARCH_WAIT;
        let mut last_new: Option<tokio::time::Instant> = None;
        while tokio::time::Instant::now() < until {
            let raw = self.take_replies(&session.receive_tunnel_id).await?;
            if !raw.is_empty() {
                let decrypted = session.mailbox.decrypt_replies(&raw);
                for (d, bits) in session.mailbox.decode_index_replies(&decrypted, &k_pub) {
                    if seen.insert(d.content_ref) {
                        found.push(d);
                        pow.push(bits);
                        last_new = Some(tokio::time::Instant::now());
                    }
                }
            }
            if last_new.is_some_and(|t| t.elapsed() >= SEARCH_QUIET) {
                break;
            }
            tokio::time::sleep(POLL).await;
        }
        Ok((found, pow))
    }

    /// 検索で見つけた投稿・ファイルの本体を取得する
    ///
    /// 保持者が居ない・期限切れなら `None`。
    pub async fn get(&self, board: &BoardId, content_ref: [u8; 32]) -> Result<Option<Fetched>> {
        let k_pub = board.key();
        let session = self.open_pull_session(HashMap::new()).await?;
        events::progress(&self.events, format!("取得中 (ref {}...)", hex::encode(&content_ref[..8])));

        // Manifest（チャンク化）か単一 body かは、置いた側しか知らない。
        // **両方を同時に要求し、先に揃った方で決める**（片方のタイムアウトを待たない）
        let body_key = SchrodingerMailbox::body_mailbox_key(&content_ref);
        let first = self
            .fetch_objects(&session, &[(content_ref, content_ref), (body_key, content_ref)], &k_pub, OBJECT_WAIT, |got| {
                got.iter().any(Option::is_some)
            })
            .await?;

        if let Some(manifest) = first[0].as_deref().and_then(|b| ManifestV2::decode(b).ok()) {
            return self.fetch_file_v2(&session, manifest, &k_pub).await;
        }
        // 古い形式（v1 の Manifest）は読まない。互換を切った
        if first[0].as_deref().is_some_and(|b| Manifest::decode(b).is_ok()) {
            events::warning(&self.events, "古い形式のファイルです（読めません）");
            return Ok(None);
        }

        Ok(first
            .into_iter()
            .nth(1)
            .flatten()
            .map(|bytes| Fetched { name: None, bytes }))
    }

    /// v2 のファイルを取る。ストライプを `V2_STRIPES_IN_FLIGHT` 本ずつの窓で進める
    ///
    /// ストライプごとに、まずデータ k 個を要求し、`HEDGE_1` 経っても k 枚に届かなければ
    /// パリティも全部要求する。届いたシャードは Manifest のハッシュと照合し、合ったものだけ使う。
    /// 全体をメモリに持つ（最大 約 800MB。逐次ファイルへ書く形は将来）。
    async fn fetch_file_v2(
        &self,
        session: &PullSession,
        manifest: ManifestV2,
        k_pub: &[u8; 32],
    ) -> Result<Option<Fetched>> {
        let total = manifest.stripes.len();
        events::progress(
            &self.events,
            format!("{} を取得します ({} ストライプ / {} バイト)", manifest.name, total, manifest.size),
        );
        let routes = sharding_v2::shard_routes(&manifest.stripes);
        let mut states: Vec<StripeState> = manifest
            .stripes
            .iter()
            .map(|s| StripeState { got: vec![None; s.shard_hashes.len()], ..Default::default() })
            .collect();
        let mut plain: Vec<Vec<u8>> = vec![Vec::new(); total];
        let mut window = StripeWindow::new(total, V2_STRIPES_IN_FLIGHT);
        let mut requested: HashSet<[u8; 32]> = HashSet::new();
        let (mut finished, mut failed) = (0usize, 0usize);
        let mut last_progress = tokio::time::Instant::now();

        loop {
            for i in window.start_more() {
                states[i].started = Some(tokio::time::Instant::now());
                let wants = stripe_requests(&manifest.stripes[i], &states[i], &requested, false);
                self.request_v2(session, k_pub, &wants, &mut requested).await?;
            }
            if window.is_finished() {
                break;
            }

            let raw = self.take_replies(&session.receive_tunnel_id).await?;
            for reply in session.mailbox.decrypt_replies(&raw) {
                route_reply(&routes, &mut states, &reply);
            }

            for i in window.active.clone() {
                let stripe = &manifest.stripes[i];
                let elapsed = states[i].started.map(|t| t.elapsed()).unwrap_or_default();
                if states[i].have() >= stripe.data as usize {
                    let objects = sharding_v2::restore_stripe(stripe, &states[i].got)?;
                    let mut bytes = Vec::with_capacity(objects.len() * chunk::V2_CHUNK_PLAIN);
                    for object in &objects {
                        // v1 のチャンクと同じ開き方（収束暗号の [nonce][暗号文]）
                        let piece = session.mailbox.decrypt_mailbox_value(object, k_pub).map_err(|_| {
                            crate::error::ClientError::invalid("チャンクを開けませんでした（壊れたファイル）")
                        })?;
                        bytes.extend_from_slice(&piece);
                    }
                    plain[i] = bytes;
                    states[i].done = true;
                    states[i].got = Vec::new();
                    window.finish(i);
                    finished += 1;
                } else if elapsed >= V2_STRIPE_WAIT {
                    states[i].done = true;
                    states[i].got = Vec::new();
                    window.finish(i);
                    window.stop_launching();
                    failed += 1;
                } else if elapsed >= HEDGE_1 && !states[i].parity_requested {
                    states[i].parity_requested = true;
                    let wants = stripe_requests(stripe, &states[i], &requested, true);
                    self.request_v2(session, k_pub, &wants, &mut requested).await?;
                }
            }

            if last_progress.elapsed() >= V2_PROGRESS_EVERY {
                last_progress = tokio::time::Instant::now();
                events::progress(&self.events, format!("取得中 {}/{} ストライプ", finished, total));
            }
            tokio::time::sleep(POLL).await;
        }

        if failed > 0 {
            let untried = window.not_started();
            let detail = if untried > 0 { "（残りは試していません）" } else { "" };
            events::warning(
                &self.events,
                format!("{}/{} ストライプを取得できませんでした{}", failed, total, detail),
            );
            return Ok(None);
        }

        let mut bytes: Vec<u8> = plain.into_iter().flatten().collect();
        if (bytes.len() as u64) < manifest.size {
            return Err(crate::error::ClientError::invalid("ファイルの大きさが Manifest と合いません"));
        }
        bytes.truncate(manifest.size as usize);
        Ok(Some(Fetched { name: Some(manifest.name), bytes }))
    }

    /// シャードを要求して、要求済みの印を付ける。担当が 1 台も居なければエラー
    async fn request_v2(
        &self,
        session: &PullSession,
        k_pub: &[u8; 32],
        wants: &[[u8; 32]],
        requested: &mut HashSet<[u8; 32]>,
    ) -> Result<()> {
        if wants.is_empty() {
            return Ok(());
        }
        let sent = session.mailbox.request_shards_v2(k_pub, wants).await?;
        if sent == 0 {
            return Err(crate::error::ClientError::network("リレーの一覧が空です"));
        }
        requested.extend(wants.iter().copied());
        Ok(())
    }

    /// 単一 body の投稿をまとめて取得する（掲示板のスレを開くとき）
    ///
    /// 1 本の Pull セッションで全部を同時に要求する。取れなかったものは `None`。
    pub async fn get_bodies(
        &self,
        board: &BoardId,
        content_refs: &[[u8; 32]],
    ) -> Result<Vec<Option<Vec<u8>>>> {
        if content_refs.is_empty() {
            return Ok(Vec::new());
        }
        let k_pub = board.key();
        let session = self.open_pull_session(HashMap::new()).await?;
        let keys: Vec<([u8; 32], [u8; 32])> = content_refs
            .iter()
            .map(|r| (SchrodingerMailbox::body_mailbox_key(r), *r))
            .collect();
        self.fetch_objects(&session, &keys, &k_pub, OBJECT_WAIT, |got| {
            got.iter().all(Option::is_some)
        })
        .await
    }

    /// 複数のオブジェクトをまとめて要求し、並行に集める
    ///
    /// `done` が真になるか上限時間で返す。3 シャード揃ったものから復元する。
    /// `mailbox_keys` は `(置き場所, 照合する内容アドレス)` の組。中身のハッシュが
    /// 内容アドレスと一致したものだけを返す。
    async fn fetch_objects(
        &self,
        session: &PullSession,
        mailbox_keys: &[([u8; 32], [u8; 32])],
        secret: &[u8; 32],
        wait: Duration,
        done: impl Fn(&[Option<Vec<u8>>]) -> bool,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        let mut results: Vec<Option<Vec<u8>>> = vec![None; mailbox_keys.len()];
        // 送った (オブジェクト, index, 順位)。同じ組を二度送らない
        let mut sent: HashSet<(usize, u8, usize)> = HashSet::new();
        let started = tokio::time::Instant::now();

        // 段 0（すぐ）。担当が一台も居なければ、従来どおりここでエラーにする
        let first = self.send_hedge(session, mailbox_keys, secret, &results, &mut sent, Duration::ZERO).await?;
        if first == 0 {
            return Err(crate::error::ClientError::network("リレーの一覧が空です"));
        }

        let mut collected = Vec::new();
        let until = started + wait;
        while tokio::time::Instant::now() < until {
            let raw = self.take_replies(&session.receive_tunnel_id).await?;
            if !raw.is_empty() {
                collected.extend(session.mailbox.decrypt_replies(&raw));
                for ((key, content_ref), slot) in mailbox_keys.iter().zip(results.iter_mut()) {
                    // 中身を ref と照合する。板の読者なら誰でも封の通る偽シャードを作れる
                    if slot.is_none()
                        && let Some((plain, _)) =
                            session.mailbox.open_public(&collected, key, secret, content_ref)
                    {
                        *slot = Some(plain);
                    }
                }
                if done(&results) {
                    break;
                }
            }
            // 経過時間に応じて次の段へ。揃ったオブジェクトには送らない
            self.send_hedge(session, mailbox_keys, secret, &results, &mut sent, started.elapsed()).await?;
            tokio::time::sleep(POLL).await;
        }
        Ok(results)
    }

    /// `hedge_plan(elapsed)` のうち、まだ揃っていないオブジェクトに未送信の組を送る
    ///
    /// 送った本数を返す。
    async fn send_hedge(
        &self,
        session: &PullSession,
        mailbox_keys: &[([u8; 32], [u8; 32])],
        secret: &[u8; 32],
        results: &[Option<Vec<u8>>],
        sent: &mut HashSet<(usize, u8, usize)>,
        elapsed: Duration,
    ) -> Result<usize> {
        let plan = hedge_plan(elapsed);
        let mut total = 0;
        for (obj, ((key, _), slot)) in mailbox_keys.iter().zip(results).enumerate() {
            if slot.is_some() {
                continue;
            }
            let wants: Vec<(u8, usize)> =
                plan.iter().copied().filter(|&(i, r)| sent.insert((obj, i, r))).collect();
            if wants.is_empty() {
                continue;
            }
            total += session.mailbox.request_shards(key, secret, &wants).await?;
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_duplicates(plan: &[(u8, usize)]) -> bool {
        plan.iter().collect::<HashSet<_>>().len() == plan.len()
    }

    fn stripe_of(hashes: Vec<[u8; 32]>, k: u8) -> StripeV2 {
        StripeV2 { data: k, parity: hashes.len() as u8 - k, last_object_len: 1000, shard_hashes: hashes }
    }

    fn state_for(stripe: &StripeV2) -> StripeState {
        StripeState { got: vec![None; stripe.shard_hashes.len()], ..Default::default() }
    }

    #[test]
    fn window_never_exceeds_the_limit_and_slides() {
        let mut w = StripeWindow::new(10, V2_STRIPES_IN_FLIGHT);
        assert_eq!(w.start_more(), vec![0, 1, 2, 3], "最初は窓いっぱい");
        assert!(w.start_more().is_empty(), "空きが無ければ始めない");
        w.finish(1);
        assert_eq!(w.start_more(), vec![4], "1 本終われば次の 1 本");
        w.finish(0);
        w.finish(2);
        assert_eq!(w.start_more(), vec![5, 6]);
        assert!(w.active.len() <= V2_STRIPES_IN_FLIGHT);
        for i in [3, 4, 5, 6] {
            w.finish(i);
            let _ = w.start_more();
            assert!(w.active.len() <= V2_STRIPES_IN_FLIGHT);
        }
        assert!(!w.is_finished());
        for i in 7..10 {
            w.finish(i);
        }
        assert!(w.is_finished());
    }

    #[test]
    fn window_with_fewer_stripes_than_the_limit() {
        let mut w = StripeWindow::new(2, V2_STRIPES_IN_FLIGHT);
        assert_eq!(w.start_more(), vec![0, 1]);
        w.finish(0);
        w.finish(1);
        assert!(w.is_finished());
    }

    #[test]
    fn window_stops_launching_after_a_failure() {
        let mut w = StripeWindow::new(10, 2);
        assert_eq!(w.start_more(), vec![0, 1]);
        w.stop_launching();
        w.finish(0);
        assert!(w.start_more().is_empty());
        assert!(!w.is_finished(), "要求中のものが残っている");
        w.finish(1);
        assert!(w.is_finished());
        assert_eq!(w.not_started(), 8);
    }

    #[test]
    fn reply_fills_every_position_with_the_same_hash() {
        let shard = vec![7u8; chunk::V2_SHARD_BYTES];
        let h = chunk::shard_hash(&shard);
        let other = [9u8; 32];
        let stripes = vec![
            stripe_of(vec![h, other, [1u8; 32]], 2),
            stripe_of(vec![[2u8; 32], h, [3u8; 32]], 2),
        ];
        let routes = sharding_v2::shard_routes(&stripes);
        let mut states: Vec<StripeState> = stripes.iter().map(state_for).collect();
        assert!(route_reply(&routes, &mut states, &shard));
        assert_eq!(states[0].got[0].as_deref(), Some(&shard[..]));
        assert_eq!(states[1].got[1].as_deref(), Some(&shard[..]), "別のストライプの同じ中身も埋まる");
        assert_eq!(states[0].have() + states[1].have(), 2);
        // 同じ返信がもう一度来ても何も変わらない
        assert!(!route_reply(&routes, &mut states, &shard));
    }

    #[test]
    fn reply_with_wrong_length_or_unknown_hash_is_dropped() {
        let shard = vec![7u8; chunk::V2_SHARD_BYTES];
        let stripes = vec![stripe_of(vec![chunk::shard_hash(&shard), [1u8; 32]], 1)];
        let routes = sharding_v2::shard_routes(&stripes);
        let mut states: Vec<StripeState> = stripes.iter().map(state_for).collect();
        assert!(!route_reply(&routes, &mut states, &[0u8; 100]), "長さが違う");
        let mut forged = shard.clone();
        forged[0] ^= 1;
        assert!(!route_reply(&routes, &mut states, &forged), "表に無いハッシュ");
        assert_eq!(states[0].have(), 0);
        // 終わったストライプには入れない
        states[0].done = true;
        assert!(!route_reply(&routes, &mut states, &shard));
    }

    #[test]
    fn requests_ask_data_first_then_parity_without_duplicates() {
        let (a, b, p) = ([1u8; 32], [2u8; 32], [4u8; 32]);
        // データ k=3（a が 2 か所で重複）、パリティ 1
        let stripe = stripe_of(vec![a, b, a, p], 3);
        let mut state = state_for(&stripe);
        let mut requested = HashSet::new();
        let data = stripe_requests(&stripe, &state, &requested, false);
        assert_eq!(data, vec![a, b], "データだけ・重複は 1 回");
        requested.extend(data.iter().copied());
        let parity = stripe_requests(&stripe, &state, &requested, true);
        assert_eq!(parity, vec![p], "要求済みは除き、パリティを足す");
        // 届いた位置は要求しない
        state.got[1] = Some(vec![]);
        assert!(stripe_requests(&stripe, &state, &HashSet::new(), false).iter().all(|h| *h != b));
    }

    #[test]
    fn v2_pipeline_restores_a_file_from_partial_shards() {
        // 置く側の純粋な部分（レイアウトとストライプの組み立て）→ 取る側の振り分けと復元
        let size = (2 * 16 + 3) as u64 * chunk::V2_CHUNK_PLAIN as u64 - 1234;
        let shapes = chunk::v2_stripe_shapes(size).unwrap();
        assert_eq!(shapes.len(), 3, "2 本 + 短い 3 本目");
        let chunks = chunk::v2_chunk_count(size);
        let mut objects: Vec<Vec<u8>> = (0..chunks)
            .map(|i| {
                let len = if i + 1 == chunks { 4321 } else { chunk::V2_SHARD_BYTES };
                (0..len).map(|j| (i * 11 + j) as u8).collect()
            })
            .collect();
        let originals = objects.clone();
        let mut built = Vec::new();
        for (k, m) in &shapes {
            let part: Vec<Vec<u8>> = objects.drain(..*k).collect();
            built.push(sharding_v2::build_stripe(&part, *m).unwrap());
        }
        let stripes: Vec<StripeV2> = built.iter().map(|b| b.stripe.clone()).collect();
        let routes = sharding_v2::shard_routes(&stripes);
        let mut states: Vec<StripeState> = stripes.iter().map(state_for).collect();
        // 各ストライプのデータシャードを 1 枚ずつ欠いた状態で、返信として届ける
        for b in &built {
            for (pos, shard) in b.shards.iter().enumerate() {
                if pos == 1 {
                    continue;
                }
                route_reply(&routes, &mut states, shard);
            }
        }
        let mut restored = Vec::new();
        for (st, sp) in states.iter().zip(&stripes) {
            restored.extend(sharding_v2::restore_stripe(sp, &st.got).unwrap());
        }
        assert_eq!(restored, originals, "短い最後のシャードも含めて元に戻る");
    }

    #[test]
    fn hedge_plan_starts_with_data_shards_on_nearest_holder() {
        let plan = hedge_plan(Duration::ZERO);
        assert_eq!(plan, vec![(0, 0), (1, 0), (2, 0)], "段 0 は index 0,1,2 を順位 0 へ");
    }

    #[test]
    fn hedge_plan_stage1_adds_parity_and_second_holder() {
        let plan = hedge_plan(HEDGE_1);
        assert!(no_duplicates(&plan), "重複が無いこと");
        let got: HashSet<_> = plan.iter().copied().collect();
        let want: HashSet<_> =
            [(0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (0, 1), (1, 1), (2, 1)].into_iter().collect();
        assert_eq!(got, want, "段 0 と段 1 の組だけ");
    }

    #[test]
    fn hedge_plan_stage2_covers_every_shard_and_rank() {
        let plan = hedge_plan(HEDGE_2);
        assert!(no_duplicates(&plan), "重複が無いこと");
        assert_eq!(plan.len(), TOTAL_SHARDS * K_REPLICAS, "5 index x 5 順位の 25 組");
        for i in 0..TOTAL_SHARDS {
            for r in 0..K_REPLICAS {
                assert!(plan.contains(&(i as u8, r)), "({i}, {r}) が含まれること");
            }
        }
    }

    #[test]
    fn hedge_plan_is_monotonic() {
        let steps = [
            Duration::ZERO,
            HEDGE_1 - Duration::from_millis(1),
            HEDGE_1,
            HEDGE_2 - Duration::from_millis(1),
            HEDGE_2,
            OBJECT_WAIT,
        ];
        for pair in steps.windows(2) {
            let before = hedge_plan(pair[0]);
            let after = hedge_plan(pair[1]);
            assert!(before.iter().all(|w| after.contains(w)), "前の段の組は後の段にも含まれる");
        }
        assert_eq!(hedge_plan(HEDGE_1 - Duration::from_millis(1)).len(), DATA_SHARDS, "段 1 の直前はまだ段 0");
    }
}
