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
use aether_core::mailbox::chunk::Manifest;
use aether_core::mailbox::index::IndexDescriptor;
use aether_core::mailbox::schrodinger::{K_REPLICAS, SchrodingerMailbox};
use aether_core::mailbox::sharding::{DATA_SHARDS, TOTAL_SHARDS};
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

        if let Some(manifest) = first[0].as_deref().and_then(|b| Manifest::decode(b).ok()) {
            let total = manifest.chunk_refs.len();
            events::progress(
                &self.events,
                format!("{} を取得します ({} チャンク / {} バイト)", manifest.name, total, manifest.size),
            );
            let chunks = self
                .fetch_objects(
                    &session,
                    &manifest.chunk_refs.iter().map(|r| (*r, *r)).collect::<Vec<_>>(),
                    &k_pub,
                    OBJECT_WAIT,
                    |got| {
                    got.iter().all(Option::is_some)
                })
                .await?;
            let missing = chunks.iter().filter(|c| c.is_none()).count();
            if missing > 0 {
                events::warning(
                    &self.events,
                    format!("{}/{} チャンクを取得できませんでした（保持者が居ない）", missing, total),
                );
                return Ok(None);
            }
            return Ok(Some(Fetched {
                name: Some(manifest.name),
                bytes: chunks.into_iter().flatten().flatten().collect(),
            }));
        }

        Ok(first
            .into_iter()
            .nth(1)
            .flatten()
            .map(|bytes| Fetched { name: None, bytes }))
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
