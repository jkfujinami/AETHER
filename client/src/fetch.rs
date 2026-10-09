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
use crate::index_pages::{INDEX_HEDGE, fill_known_roots, index_ask_count, search_days};
use aether_core::mailbox::index::{self, IndexDescriptor};
use aether_core::mailbox::schrodinger::{K_REPLICAS, SchrodingerMailbox};
use aether_core::mailbox::sharding::{DATA_SHARDS, TOTAL_SHARDS};
use aether_core::mailbox::sharding_v2;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

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
/// 追い越された要求を「失われた」とみなすまでの猶予
///
/// 返信は同じ返信トンネルをほぼ要求順に通るので、回線が遅いだけなら先の要求の返信は後の要求の
/// 返信より先に届く。後の要求の返信が届いたのに先の要求の返信がまだなら、保持者が黙ったか
/// 返信が落ちたと見てよい。3 秒は、保持者ごとの応答のばらつきと回路の揺れを見込んだ値
/// （回線の速さには依存しない。1 ストライプに 7 秒かかる回線でも、順に届く限り足さない）。
const V2_LATE: Duration = Duration::from_secs(3);
/// 何も届かない状態が続いたとき、要求を「失われた」とみなすまでの静けさ
///
/// 追い越しでは見つからない場合（全員が落ちた・最後の数枚）のため。このファイルの取得で最後に
/// 何かが届いてから、かつその要求を送ってから、どちらも `V2_IDLE` 経ったものだけを失われたとみなす。
/// 取得の始めは何も届いていないので、最初の返信が届くまでの往復（3 ホップの回路 + 保持者 +
/// 3 ホップの返信トンネル。実網で数秒）より十分長くする。短いと、遅い網では始めの要求が全部
/// 失われたとみなされ、データと同じ枚数のパリティを一斉に取ってしまう。
const V2_IDLE: Duration = Duration::from_secs(8);
/// ストライプを諦めるまでの待ち
///
/// そのストライプの k+m 位置をすべて要求し終え、k 枚に届かず、届いていない要求がすべて
/// 失われたとみなされてから、これだけ待って諦める。失われたとみなした要求の返信が遅れて届くことは
/// あるので、すぐには切らない。遅いが進んでいる転送は、失われたと見なされないので諦めない。
const V2_GIVE_UP: Duration = Duration::from_secs(30);
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
    done: bool,
}

impl StripeState {
    fn have(&self) -> usize {
        self.got.iter().filter(|s| s.is_some()).count()
    }
}

/// 送った要求 1 本（届くまで持つ）
struct InFlight {
    stripe: usize,
    pos: usize,
    /// 要求を送った順の通し番号
    seq: u64,
    sent: Instant,
    /// 失われたとみなした時刻。返信が後から届けば普通に使う（要求は届いた時点で消える）
    lost_at: Option<Instant>,
}

/// [`HedgeTracker`] が持つストライプ 1 本ぶん
struct StripeTrack {
    /// データの位置の数
    k: usize,
    requested: Vec<bool>,
    filled: Vec<bool>,
}

/// 失われた要求を見分けて、その分だけパリティを足す純粋な状態機械（時刻は引数で渡す）
///
/// 失われたかどうかは回線の速さではなく、次の 2 つだけで決める。
/// - **追い越し**: 届いていない要求より後の通し番号の要求が届き、その時刻から [`V2_LATE`] 過ぎた。
/// - **途切れ**: 最後に何かが届いてから [`V2_IDLE`]、かつその要求を送ってから [`V2_IDLE`] 過ぎた。
///
/// 失われた要求 1 本につき、同じストライプのまだ要求していないパリティの位置を 1 つだけ要求する
/// （1 本の要求につき 1 回まで。パリティが尽きたら足さない）。足したパリティの要求も要求なので、
/// 同じ規則で失われうる。ストライプを諦める条件は [`gave_up`](Self::gave_up)。
struct HedgeTracker {
    stripes: HashMap<usize, StripeTrack>,
    /// 届いていない要求（通し番号の昇順）
    pending: Vec<InFlight>,
    next_seq: u64,
    /// 届いた要求の（通し番号, 時刻）。まだ `V2_LATE` 経っていないもの
    recent_arrivals: VecDeque<(u64, Instant)>,
    /// `V2_LATE` 以上前に届いた要求の通し番号の最大。これより前の通し番号の未着は追い越された
    overtaken_below: Option<u64>,
    /// このファイルの取得で最後に何かが届いた時刻（始まりは取得の開始）
    last_arrival: Instant,
}

impl HedgeTracker {
    fn new(now: Instant) -> Self {
        Self {
            stripes: HashMap::new(),
            pending: Vec::new(),
            next_seq: 0,
            recent_arrivals: VecDeque::new(),
            overtaken_below: None,
            last_arrival: now,
        }
    }

    fn push(&mut self, stripe: usize, pos: usize, now: Instant) {
        self.pending.push(InFlight { stripe, pos, seq: self.next_seq, sent: now, lost_at: None });
        self.next_seq += 1;
    }

    /// ストライプを始める。データ k 位置すべてを要求したことにする
    ///
    /// `filled` は始める時点ですでに埋まっている位置（他のストライプの返信で埋まったもの）。
    /// その位置の要求も送るが、返信は [`route_reply`] が捨てるので届いた扱いにして待たない。
    fn start_stripe(&mut self, stripe: usize, k: usize, filled: &[bool], now: Instant) {
        let mut requested = vec![false; filled.len()];
        for pos in 0..k.min(filled.len()) {
            requested[pos] = true;
            if !filled[pos] {
                self.push(stripe, pos, now);
            }
        }
        self.stripes.insert(stripe, StripeTrack { k, requested, filled: filled.to_vec() });
    }

    /// 位置が埋まった。その位置への要求はすべて届いた扱いにする（同じハッシュの複数位置も、
    /// [`route_reply`] が返した位置ごとに呼ぶ）
    fn on_filled(&mut self, stripe: usize, pos: usize, now: Instant) {
        self.last_arrival = now;
        let Some(track) = self.stripes.get_mut(&stripe) else { return };
        if let Some(f) = track.filled.get_mut(pos) {
            *f = true;
        }
        let seqs: Vec<u64> =
            self.pending.iter().filter(|r| r.stripe == stripe && r.pos == pos).map(|r| r.seq).collect();
        self.pending.retain(|r| !(r.stripe == stripe && r.pos == pos));
        for seq in seqs {
            self.recent_arrivals.push_back((seq, now));
        }
    }

    /// ストライプを終える（揃った・諦めた）。そのストライプの未着はもう見ない
    ///
    /// 終える時点で失われたとみなされ、まだ届いていない要求の位置を返す（昇順・重複なし）。
    /// 保持者が去った・担当が入れ替わったシャードで、取り終えた人が置き直す対象（Part 25 の P11）。
    fn finish_stripe(&mut self, stripe: usize) -> Vec<usize> {
        self.stripes.remove(&stripe);
        let mut lost: Vec<usize> =
            self.pending.iter().filter(|r| r.stripe == stripe && r.lost_at.is_some()).map(|r| r.pos).collect();
        lost.sort_unstable();
        lost.dedup();
        self.pending.retain(|r| r.stripe != stripe);
        lost
    }

    /// 失われた要求を見つけ、足すパリティの（ストライプ, 位置）を返す。返した位置は要求したことになる
    fn poll(&mut self, now: Instant) -> Vec<(usize, usize)> {
        // V2_LATE 以上前に届いたものだけが「追い越した」証拠になる
        while let Some(&(seq, at)) = self.recent_arrivals.front() {
            if now.saturating_duration_since(at) < V2_LATE {
                break;
            }
            self.overtaken_below = Some(self.overtaken_below.map_or(seq, |m| m.max(seq)));
            self.recent_arrivals.pop_front();
        }
        let idle = now.saturating_duration_since(self.last_arrival) >= V2_IDLE;
        let mut hedges = Vec::new();
        let mut newly_lost = Vec::new();
        for r in &mut self.pending {
            if r.lost_at.is_some() {
                continue;
            }
            let overtaken = self.overtaken_below.is_some_and(|m| r.seq < m);
            let stalled = idle && now.saturating_duration_since(r.sent) >= V2_IDLE;
            if overtaken || stalled {
                r.lost_at = Some(now);
                newly_lost.push(r.stripe);
            }
        }
        for stripe in newly_lost {
            let Some(track) = self.stripes.get_mut(&stripe) else { continue };
            let next = (track.k..track.requested.len()).find(|&p| !track.requested[p] && !track.filled[p]);
            if let Some(pos) = next {
                track.requested[pos] = true;
                hedges.push((stripe, pos));
            }
        }
        for &(stripe, pos) in &hedges {
            self.push(stripe, pos, now);
        }
        hedges
    }

    /// このストライプを諦めるか
    ///
    /// 全位置を要求し終え（足せるパリティが無い）、届いていない要求がすべて失われたとみなされ、
    /// その最後の時刻から [`V2_GIVE_UP`] 経ったとき。k 枚に届いたかどうかは呼び出し側が先に見る。
    fn gave_up(&self, stripe: usize, now: Instant) -> bool {
        let Some(track) = self.stripes.get(&stripe) else { return false };
        if (track.k..track.requested.len()).any(|p| !track.requested[p] && !track.filled[p]) {
            return false;
        }
        let mut last_lost: Option<Instant> = None;
        for r in self.pending.iter().filter(|r| r.stripe == stripe) {
            let Some(at) = r.lost_at else { return false };
            last_lost = Some(last_lost.map_or(at, |l| l.max(at)));
        }
        last_lost.is_some_and(|l| now.saturating_duration_since(l) >= V2_GIVE_UP)
    }

    /// そのストライプの届いていない要求の数（試験用）
    #[cfg(test)]
    fn outstanding(&self, stripe: usize) -> usize {
        self.pending.iter().filter(|r| r.stripe == stripe).count()
    }
}

/// 置き直しに溜めるシャードの上限（1 枚 256KB。メモリを抑える。超えた分は延命だけ）
const MAX_REPAIR_SHARDS: usize = 256;
/// 延命・置き直しを送る時間の上限（取得の結果を長く待たせない。超えた分は次に取る人に任せる）
const KEEP_BUDGET: Duration = Duration::from_secs(30);
/// 延命を送る間に時間を見る単位
const TOUCH_BATCH: usize = 32;

/// 取り終えたストライプから集めた、ファイルを網に残すための手伝い（延命と置き直し）
#[derive(Default)]
struct KeepHelp {
    /// 延命を送るシャードのハッシュ（取らなかった位置）
    touch: Vec<[u8; 32]>,
    /// 置き直すシャード（ハッシュ → 中身）。Manifest のハッシュと合うと確かめたものだけ
    repairs: HashMap<[u8; 32], Vec<u8>>,
}

impl KeepHelp {
    /// 復元できたストライプ 1 本ぶんを足す
    ///
    /// `filled` は取った位置、`lost` は失われたとみなされた位置、`objects` は復元したチャンクの
    /// オブジェクト。失われた位置は延命でなく置き直し（作り直したシャードがハッシュと合わなければ置かない）。
    fn add_stripe(&mut self, stripe: &StripeV2, filled: &[bool], lost: &[usize], objects: &[Vec<u8>]) {
        for pos in sharding_v2::unfetched_positions(filled) {
            if !lost.contains(&pos)
                && let Some(h) = stripe.shard_hashes.get(pos)
            {
                self.touch.push(*h);
            }
        }
        if lost.is_empty() || self.repairs.len() >= MAX_REPAIR_SHARDS {
            return;
        }
        // 作り直せない（壊れた復元）なら置かない
        for (pos, shard) in sharding_v2::rebuild_shards(stripe, objects, lost).unwrap_or_default() {
            if self.repairs.len() < MAX_REPAIR_SHARDS {
                self.repairs.insert(stripe.shard_hashes[pos], shard);
            }
        }
    }
}

/// 返信 1 枚を振り分ける。表に載る**すべての位置**を埋める（同じ中身のチャンクは同じハッシュ）
///
/// 長さが `V2_SHARD_BYTES` でない返信と、表に無いハッシュの返信は捨てる。
/// 終わったストライプの位置は埋めない。埋まった（ストライプ, 位置）をすべて返す。
fn route_reply(
    routes: &HashMap<[u8; 32], Vec<(usize, usize)>>,
    states: &mut [StripeState],
    reply: &[u8],
) -> Vec<(usize, usize)> {
    let mut filled = Vec::new();
    if reply.len() != chunk::V2_SHARD_BYTES {
        return filled;
    }
    let Some(positions) = routes.get(&chunk::shard_hash(reply)) else {
        return filled;
    };
    for &(si, pos) in positions {
        let Some(st) = states.get_mut(si) else { continue };
        if st.done {
            continue;
        }
        if let Some(slot) = st.got.get_mut(pos)
            && slot.is_none()
        {
            *slot = Some(reply.to_vec());
            filled.push((si, pos));
        }
    }
    filled
}

/// ストライプの開始時に要求するシャードのハッシュ
///
/// **データ k 個の位置すべてを 1 位置 1 要求**で出す。
/// 同じハッシュでもまとめず、他のストライプの返信で埋まった位置も要求する ── ファイルの中に
/// 同じ中身のチャンク（ディスクイメージのゼロ領域など）があっても、取る量が置いた量
/// （切り上げた大きさ）より減らないようにするため（ガードに取った量から大きさを絞らせない）。
/// 遅れて届く重複した返信は [`route_reply`] が捨てる。パリティは [`HedgeTracker`] が足す。
fn stripe_requests(stripe: &StripeV2) -> Vec<[u8; 32]> {
    stripe.shard_hashes[..stripe.data as usize].to_vec()
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
    ///
    /// 今日から [`SEARCH_DAYS`] 日分のページを並行に引いて合わせる。各ページはまず近い担当
    /// 2 台に聞き、[`INDEX_HEDGE`] 経っても返事が無いページだけ残りの担当にも聞く
    /// （Part 25 の P13）。
    pub async fn search_raw(&self, board: &BoardId) -> Result<(Vec<IndexDescriptor>, Vec<u32>)> {
        let k_pub = board.key();
        let session = self.open_pull_session(HashMap::new()).await?;
        events::progress(&self.events, format!("板 #{} の索引を引いています...", board.fingerprint()));

        // ページごとの担当（近い順）、すでに聞いた台数、返事があったか
        struct Page {
            day: u32,
            targets: Vec<std::net::SocketAddr>,
            asked: usize,
            replied: bool,
        }
        let mut pages: HashMap<[u8; 32], Page> = HashMap::new();
        for day in search_days(aether_core::protocol::hint::current_timestamp()) {
            let targets = session.mailbox.index_page_targets(&k_pub, day).await;
            pages.insert(index::index_page_key(&k_pub, day), Page { day, targets, asked: 0, replied: false });
        }

        let mut seen = HashSet::new();
        let mut found = Vec::new();
        let mut pow = Vec::new();
        let start = tokio::time::Instant::now();
        let until = start + SEARCH_WAIT;
        // 静けさは、最後の新着か、残りの担当へ広げた時点の遅い方から測る
        // （広げた先の返事を待たずに打ち切らないため）
        let mut last_event: Option<tokio::time::Instant> = None;
        let mut hedged = false;
        while tokio::time::Instant::now() < until {
            let elapsed = start.elapsed();
            for page in pages.values_mut() {
                let want = index_ask_count(elapsed, page.replied, page.targets.len());
                if want > page.asked {
                    session
                        .mailbox
                        .query_index_page(&k_pub, page.day, &session.reply_to, &page.targets[page.asked..want])
                        .await?;
                    if page.asked > 0 {
                        hedged = true;
                    }
                    page.asked = want;
                }
            }
            if hedged && last_event.is_none_or(|t| t < start + INDEX_HEDGE) {
                last_event = Some(start + INDEX_HEDGE);
            }

            let raw = self.take_replies(&session.receive_tunnel_id).await?;
            if !raw.is_empty() {
                let decrypted = session.mailbox.decrypt_replies(&raw);
                for r in session.mailbox.decode_index_replies(&decrypted, &k_pub) {
                    let Some(page) = pages.get_mut(&r.page_key) else { continue };
                    page.replied = true;
                    // 根の記録は、レスで上げ直すために元のバイト列を覚えておく
                    if r.descriptor.parents.is_empty() {
                        self.remember_root(&k_pub, &r.descriptor.content_ref, &r.record, page.day);
                    }
                    if seen.insert(r.descriptor.content_ref) {
                        found.push(r.descriptor);
                        pow.push(r.pow_bits);
                        last_event = Some(tokio::time::Instant::now());
                    }
                }
            }
            if last_event.is_some_and(|t| t.elapsed() >= SEARCH_QUIET) {
                break;
            }
            tokio::time::sleep(POLL).await;
        }

        // 根のページを引いていないスレ（7 日より前に立ったもの）は、覚えている根で補う
        fill_known_roots(&mut found, &mut pow, &self.index_memory.lock().unwrap(), &k_pub);
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
            let (fetched, help) = self.fetch_file_v2(&session, manifest, &k_pub).await?;
            // 取ったファイルを先に返し、網に残す手伝い（延命・置き直し）は裏で送る。
            // 終わる前に `flush` を呼ぶ側（CLI）は、これを送り終えるまで待つ
            if let Some(help) = help {
                let events = self.events.clone();
                let handle = tokio::spawn(keep_files_alive(session, k_pub, help, events));
                self.pending_flush.lock().unwrap().push(handle);
            }
            return Ok(fetched);
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
    /// ストライプごとに、まずデータ k 個を要求し、失われた要求（[`HedgeTracker`]）1 本につき
    /// パリティを 1 つ足す。回線が遅いだけならパリティは要求しない。届いたシャードは Manifest のハッシュと照合し、合ったものだけ使う。
    /// 全体をメモリに持つ（最大 約 800MB。逐次ファイルへ書く形は将来）。
    async fn fetch_file_v2(
        &self,
        session: &PullSession,
        manifest: ManifestV2,
        k_pub: &[u8; 32],
    ) -> Result<(Option<Fetched>, Option<KeepHelp>)> {
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
        let mut tracker = HedgeTracker::new(Instant::now());
        let help_on = self.privacy().help_keep_files;
        let mut help = KeepHelp::default();
        let mut plain: Vec<Vec<u8>> = vec![Vec::new(); total];
        let mut window = StripeWindow::new(total, V2_STRIPES_IN_FLIGHT);
        let (mut finished, mut failed) = (0usize, 0usize);
        let mut last_progress = tokio::time::Instant::now();

        loop {
            for i in window.start_more() {
                let stripe = &manifest.stripes[i];
                let filled: Vec<bool> = states[i].got.iter().map(Option::is_some).collect();
                tracker.start_stripe(i, stripe.data as usize, &filled, Instant::now());
                self.request_v2(session, k_pub, &stripe_requests(stripe)).await?;
            }
            if window.is_finished() {
                break;
            }

            let raw = self.take_replies(&session.receive_tunnel_id).await?;
            for reply in session.mailbox.decrypt_replies(&raw) {
                let now = Instant::now();
                for (si, pos) in route_reply(&routes, &mut states, &reply) {
                    tracker.on_filled(si, pos, now);
                }
            }

            let mut gave_up = Vec::new();
            for i in window.active.clone() {
                let stripe = &manifest.stripes[i];
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
                    let filled: Vec<bool> = states[i].got.iter().map(Option::is_some).collect();
                    states[i].done = true;
                    states[i].got = Vec::new();
                    let lost = tracker.finish_stripe(i);
                    if help_on {
                        help.add_stripe(stripe, &filled, &lost, &objects);
                    }
                    window.finish(i);
                    finished += 1;
                }
            }

            // 失われた要求の分だけパリティを足す。諦めの判断は、足した後の状態で行う
            let now = Instant::now();
            let hedges = tracker.poll(now);
            for i in window.active.clone() {
                if tracker.gave_up(i, now) {
                    gave_up.push(i);
                }
            }
            for i in gave_up {
                states[i].done = true;
                states[i].got = Vec::new();
                tracker.finish_stripe(i);
                window.finish(i);
                window.stop_launching();
                failed += 1;
            }
            if !hedges.is_empty() {
                let wants: Vec<[u8; 32]> =
                    hedges.iter().map(|&(si, pos)| manifest.stripes[si].shard_hashes[pos]).collect();
                self.request_v2(session, k_pub, &wants).await?;
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
            return Ok((None, None));
        }

        let mut bytes: Vec<u8> = plain.into_iter().flatten().collect();
        if (bytes.len() as u64) < manifest.size {
            return Err(crate::error::ClientError::invalid("ファイルの大きさが Manifest と合いません"));
        }
        bytes.truncate(manifest.size as usize);
        Ok((Some(Fetched { name: Some(manifest.name), bytes }), help_on.then_some(help)))
    }

    /// シャードを要求する。担当が 1 台も居なければエラー
    async fn request_v2(
        &self,
        session: &PullSession,
        k_pub: &[u8; 32],
        wants: &[[u8; 32]],
    ) -> Result<()> {
        if wants.is_empty() {
            return Ok(());
        }
        let sent = session.mailbox.request_shards_v2(k_pub, wants).await?;
        if sent == 0 {
            return Err(crate::error::ClientError::network("リレーの一覧が空です"));
        }
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

/// 取り終えたファイルを網に残すのを手伝う ── 取らなかった位置へ延命、失われた位置は置き直す
///
/// 取った回路と同じ session から、置き場所と同じ保持者の受け口へ送る。保持者は取った人の IP を
/// 知らない。結果を長く待たせないよう、`KEEP_BUDGET` までで切る（残りは次に取る人に任せる）。
/// 失敗しても取得の結果には影響しない。取ったファイルを返した後に裏で走る（[`AetherClient::get`]）。
async fn keep_files_alive(session: PullSession, k_pub: [u8; 32], help: KeepHelp, events: crate::events::EventSender) {
    let deadline = Instant::now() + KEEP_BUDGET;
    let mut touch = help.touch;
    touch.sort_unstable();
    touch.dedup();
    let mut touched = 0;
    for batch in touch.chunks(TOUCH_BATCH) {
        if Instant::now() >= deadline {
            break;
        }
        touched += session.mailbox.touch_shards_v2(&k_pub, batch).await;
    }
    let mut repaired = 0;
    for shard in help.repairs.values() {
        if Instant::now() >= deadline {
            break;
        }
        if session.mailbox.put_shard_v2(&k_pub, shard).await.is_ok() {
            repaired += 1;
        }
    }
    if touched > 0 || repaired > 0 {
        events::progress(&events, format!("修復 {} 枚・延命 {} 枚", repaired, touched));
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
        assert_eq!(route_reply(&routes, &mut states, &shard), vec![(0, 0), (1, 1)]);
        assert_eq!(states[0].got[0].as_deref(), Some(&shard[..]));
        assert_eq!(states[1].got[1].as_deref(), Some(&shard[..]), "別のストライプの同じ中身も埋まる");
        assert_eq!(states[0].have() + states[1].have(), 2);
        // 同じ返信がもう一度来ても何も変わらない
        assert!(route_reply(&routes, &mut states, &shard).is_empty());
    }

    #[test]
    fn reply_with_wrong_length_or_unknown_hash_is_dropped() {
        let shard = vec![7u8; chunk::V2_SHARD_BYTES];
        let stripes = vec![stripe_of(vec![chunk::shard_hash(&shard), [1u8; 32]], 1)];
        let routes = sharding_v2::shard_routes(&stripes);
        let mut states: Vec<StripeState> = stripes.iter().map(state_for).collect();
        assert!(route_reply(&routes, &mut states, &[0u8; 100]).is_empty(), "長さが違う");
        let mut forged = shard.clone();
        forged[0] ^= 1;
        assert!(route_reply(&routes, &mut states, &forged).is_empty(), "表に無いハッシュ");
        assert_eq!(states[0].have(), 0);
        // 終わったストライプには入れない
        states[0].done = true;
        assert!(route_reply(&routes, &mut states, &shard).is_empty());
    }

    #[test]
    fn start_requests_every_data_position_even_if_same_hash_or_filled() {
        let (a, b, p, q) = ([1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32]);
        // データ k=3（a が 2 か所で同じ中身）、パリティ 2
        let stripe = stripe_of(vec![a, b, a, p, q], 3);
        assert_eq!(stripe_requests(&stripe), vec![a, b, a], "同じハッシュでも位置ごとに 1 要求（データ k 位置ぶん）");
    }

    fn at(base: Instant, secs: f64) -> Instant {
        base + Duration::from_secs_f64(secs)
    }

    /// 4 データ + 3 パリティのストライプ 1 本（番号 0）を t=0 に始めた追跡
    fn tracker_with_one_stripe() -> (HedgeTracker, Instant) {
        let base = Instant::now();
        let mut t = HedgeTracker::new(base);
        t.start_stripe(0, 4, &[false; 7], base);
        (t, base)
    }

    #[test]
    fn slow_line_that_delivers_in_order_requests_no_parity() {
        let (mut t, base) = tracker_with_one_stripe();
        // 2 秒おきに要求順に届く（1 ストライプに 7 秒かかる回線）。毎秒見ても足さない
        for tick in 0..=30 {
            let now = at(base, tick as f64);
            if tick % 2 == 1 && tick <= 7 {
                t.on_filled(0, (tick / 2) as usize, now);
            }
            assert!(t.poll(now).is_empty(), "t = {}", tick);
        }
    }

    #[test]
    fn finishing_a_stripe_reports_the_lost_positions_only() {
        let (mut t, base) = tracker_with_one_stripe();
        for (secs, pos) in [(1.0, 0usize), (2.0, 1), (3.0, 3)] {
            t.on_filled(0, pos, at(base, secs));
        }
        assert_eq!(t.poll(at(base, 6.0)), vec![(0, 4)]);
        t.on_filled(0, 4, at(base, 6.5));
        assert_eq!(t.finish_stripe(0), vec![2], "位置 2 は失われたとみなされ、届かなかった");

        // 失われたとみなす前に終えたストライプと、遅れて届いた位置は含めない
        let (mut t, base) = tracker_with_one_stripe();
        for (secs, pos) in [(1.0, 0usize), (2.0, 1), (3.0, 3)] {
            t.on_filled(0, pos, at(base, secs));
        }
        assert!(t.finish_stripe(0).is_empty(), "まだ失われたとみなしていない");
        let (mut t, base) = tracker_with_one_stripe();
        for (secs, pos) in [(1.0, 0usize), (2.0, 1), (3.0, 3)] {
            t.on_filled(0, pos, at(base, secs));
        }
        t.poll(at(base, 6.0));
        t.on_filled(0, 2, at(base, 7.0));
        assert!(t.finish_stripe(0).is_empty(), "遅れて届いた位置は失われていない");
    }

    fn keep_stripe() -> (StripeV2, Vec<Vec<u8>>) {
        let mut objects: Vec<Vec<u8>> = (0..4)
            .map(|i| (0..chunk::V2_SHARD_BYTES).map(|j| (i * 11 + j * 3 + 1) as u8).collect())
            .collect();
        objects[3].truncate(chunk::V2_SEAL_OVERHEAD + 50);
        (sharding_v2::build_stripe(&objects, 3).unwrap().stripe, objects)
    }

    #[test]
    fn keep_help_touches_unfetched_and_repairs_lost() {
        let (stripe, objects) = keep_stripe();
        // 取ったのは位置 0, 1, 3, 4。位置 2 は失われ、5・6 は取らなかった
        let filled = [true, true, false, true, true, false, false];
        let mut help = KeepHelp::default();
        help.add_stripe(&stripe, &filled, &[2], &objects);
        assert_eq!(help.touch, vec![stripe.shard_hashes[5], stripe.shard_hashes[6]], "失われた位置には延命でなく置き直し");
        assert_eq!(help.repairs.len(), 1);
        let shard = &help.repairs[&stripe.shard_hashes[2]];
        assert_eq!(chunk::shard_hash(shard), stripe.shard_hashes[2], "置き直すのは Manifest のハッシュと合うシャード");
    }

    #[test]
    fn keep_help_does_not_repair_with_a_wrong_rebuild() {
        let (stripe, mut objects) = keep_stripe();
        objects[0][5] ^= 0x55; // 壊れた復元からは、パリティが合わない
        let mut help = KeepHelp::default();
        help.add_stripe(&stripe, &[true, true, true, true, false, false, true], &[4, 5], &objects);
        assert!(help.repairs.is_empty(), "ハッシュが合わないものは置かない");
        assert!(help.touch.is_empty(), "失われた位置は延命にも回さない");
    }

    #[test]
    fn keep_help_caps_the_repairs_it_holds() {
        let (stripe, objects) = keep_stripe();
        let mut help = KeepHelp::default();
        for i in 0..MAX_REPAIR_SHARDS + 10 {
            help.repairs.insert([(i % 251) as u8, (i / 251) as u8, 9, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], vec![0]);
        }
        let n = help.repairs.len();
        help.add_stripe(&stripe, &[true; 7], &[0], &objects);
        assert!(n >= MAX_REPAIR_SHARDS);
        assert_eq!(help.repairs.len(), n, "上限を超えたら足さない");
    }

    #[test]
    fn one_missing_request_overtaken_adds_exactly_one_parity_after_late() {
        let (mut t, base) = tracker_with_one_stripe();
        for (secs, pos) in [(1.0, 0usize), (2.0, 1), (3.0, 3)] {
            t.on_filled(0, pos, at(base, secs));
            assert!(t.poll(at(base, secs)).is_empty());
        }
        // 位置 3 が届いたのは 3 秒。V2_LATE 経つ前は足さない
        assert!(t.poll(at(base, 5.9)).is_empty());
        assert_eq!(t.poll(at(base, 6.0)), vec![(0, 4)], "位置 2 が失われた → パリティ 1 つだけ");
        assert!(t.poll(at(base, 6.1)).is_empty(), "同じ要求では 2 回足さない");
        assert_eq!(t.outstanding(0), 2, "失われたとみなしても要求は残る + 足したパリティ");
        // 失われたとみなした位置の返信が後から届けば普通に使われる
        t.on_filled(0, 2, at(base, 7.0));
        assert_eq!(t.outstanding(0), 1);
    }

    #[test]
    fn nothing_arriving_adds_parity_for_each_missing_request_capped_by_parity() {
        let (mut t, base) = tracker_with_one_stripe();
        let idle = V2_IDLE.as_secs_f64();
        assert!(t.poll(at(base, idle - 0.1)).is_empty());
        // 4 本が途切れで失われ、パリティは 3 つしかないので 3 つで頭打ち
        assert_eq!(t.poll(at(base, idle)), vec![(0, 4), (0, 5), (0, 6)]);
        // 足したパリティも V2_IDLE 届かなければ失われるが、もう足せない
        assert!(t.poll(at(base, 2.0 * idle)).is_empty());
        assert!(t.poll(at(base, 100.0)).is_empty());
    }

    #[test]
    fn stripe_is_given_up_only_after_parity_is_exhausted_and_all_lost_for_give_up() {
        let (mut t, base) = tracker_with_one_stripe();
        let idle = V2_IDLE.as_secs_f64();
        t.poll(at(base, idle)); // データ 4 本が失われ、パリティを 3 つ要求（これも未着）
        assert!(!t.gave_up(0, at(base, idle + 60.0)), "足したパリティがまだ失われたとみなされていない");
        t.poll(at(base, 2.0 * idle)); // パリティの要求も失われたとみなされる
        assert!(!t.gave_up(0, at(base, 2.0 * idle) + V2_GIVE_UP - Duration::from_millis(1)));
        assert!(t.gave_up(0, at(base, 2.0 * idle) + V2_GIVE_UP));
    }

    #[test]
    fn stripe_with_parity_left_is_not_given_up() {
        let (mut t, base) = tracker_with_one_stripe();
        // 位置 0 だけ届き、残りのデータ 3 本が追い越されて失われる → パリティ 3 つを要求（尽きる）
        // ここでは 1 本だけ失われる例: パリティが残っているうちは何秒経っても諦めない
        for (secs, pos) in [(1.0, 0usize), (1.0, 1), (1.0, 3)] {
            t.on_filled(0, pos, at(base, secs));
        }
        assert_eq!(t.poll(at(base, 4.0)), vec![(0, 4)]);
        assert!(!t.gave_up(0, at(base, 1000.0)), "足したパリティの要求が失われたとみなされるまでは諦めない");
    }

    #[test]
    fn slow_but_progressing_transfer_is_never_given_up() {
        let base = Instant::now();
        let mut t = HedgeTracker::new(base);
        t.start_stripe(0, 16, &[false; 20], base);
        for tick in 0..=60 {
            let now = at(base, tick as f64);
            if tick % 2 == 0 && tick / 2 < 16 {
                t.on_filled(0, (tick / 2) as usize, now);
            }
            assert!(t.poll(now).is_empty(), "t = {}", tick);
            assert!(!t.gave_up(0, now), "t = {}", tick);
        }
    }

    #[test]
    fn one_reply_fills_every_position_with_the_same_hash() {
        let shard = vec![7u8; chunk::V2_SHARD_BYTES];
        let h = chunk::shard_hash(&shard);
        let stripes = vec![stripe_of(vec![h, [1u8; 32], h, [2u8; 32]], 3)];
        let routes = sharding_v2::shard_routes(&stripes);
        let mut states: Vec<StripeState> = stripes.iter().map(state_for).collect();
        let base = Instant::now();
        let mut t = HedgeTracker::new(base);
        t.start_stripe(0, 3, &[false; 4], base);
        assert_eq!(t.outstanding(0), 3);
        for (si, pos) in route_reply(&routes, &mut states, &shard) {
            t.on_filled(si, pos, at(base, 1.0));
        }
        assert_eq!(t.outstanding(0), 1, "同じハッシュの 2 位置の要求はどちらも届いた扱い");
    }

    #[test]
    fn requests_for_already_filled_positions_are_not_waited_for() {
        let base = Instant::now();
        let mut t = HedgeTracker::new(base);
        t.start_stripe(0, 2, &[true, false, false], base);
        assert_eq!(t.outstanding(0), 1);
    }

    #[test]
    fn v2_pipeline_restores_a_file_from_partial_shards() {
        // 置く側の純粋な部分（レイアウトとストライプの組み立て）→ 取る側の振り分けと復元
        let chunks = 2 * 16 + 3;
        let shapes = chunk::v2_stripe_shapes(chunks).unwrap();
        assert_eq!(shapes.len(), 3, "2 本 + 短い 3 本目");
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
