//! 取得 ── 索引の検索・本体の取得・プレキー束の取得
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
use crate::error::{ClientError, Result};
use crate::events;
use crate::pull::PullSession;
use aether_core::crypto::identity::NodeId;
use crate::boards::BoardId;
use aether_core::mailbox::chunk::Manifest;
use aether_core::mailbox::index::IndexDescriptor;
use aether_core::mailbox::schrodinger::SchrodingerMailbox;
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
/// プレキー束を待つ上限
const PREKEY_WAIT: Duration = Duration::from_secs(10);
/// 返信の到着を見に行く間隔
const POLL: Duration = Duration::from_millis(100);

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
            .fetch_objects(&session, &[content_ref, body_key], &k_pub, OBJECT_WAIT, |got| {
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
                .fetch_objects(&session, &manifest.chunk_refs, &k_pub, OBJECT_WAIT, |got| {
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
        let keys: Vec<[u8; 32]> = content_refs
            .iter()
            .map(SchrodingerMailbox::body_mailbox_key)
            .collect();
        self.fetch_objects(&session, &keys, &k_pub, OBJECT_WAIT, |got| {
            got.iter().all(Option::is_some)
        })
        .await
    }

    /// 相手のプレキー束を網から取得する（X3DH 初回接触）
    pub(crate) async fn fetch_prekey_bundle(
        &self,
        target: &NodeId,
    ) -> Result<aether_core::crypto::x3dh::PreKeyBundle> {
        let session = self.open_pull_session(HashMap::new()).await?;
        session.mailbox.request_prekey_bundle(target).await?;

        let mut collected = Vec::new();
        let until = tokio::time::Instant::now() + PREKEY_WAIT;
        while tokio::time::Instant::now() < until {
            let raw = self.take_replies(&session.receive_tunnel_id).await?;
            if !raw.is_empty() {
                collected.extend(session.mailbox.decrypt_replies(&raw));
                if let Some(bundle) = session.mailbox.reassemble_prekey_bundle(&collected, target)? {
                    return Ok(bundle);
                }
            }
            tokio::time::sleep(POLL).await;
        }
        Err(ClientError::network(format!(
            "プレキー束を取得できません（相手 {} が公開していない／オフライン）",
            target
        )))
    }

    /// 複数のオブジェクトをまとめて要求し、並行に集める
    ///
    /// `done` が真になるか上限時間で返す。3 シャード揃ったものから復元する。
    async fn fetch_objects(
        &self,
        session: &PullSession,
        mailbox_keys: &[[u8; 32]],
        secret: &[u8; 32],
        wait: Duration,
        done: impl Fn(&[Option<Vec<u8>>]) -> bool,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        for key in mailbox_keys {
            session.mailbox.request_object(key, secret).await?;
        }

        let mut results: Vec<Option<Vec<u8>>> = vec![None; mailbox_keys.len()];
        let mut collected = Vec::new();
        let until = tokio::time::Instant::now() + wait;
        while tokio::time::Instant::now() < until {
            let raw = self.take_replies(&session.receive_tunnel_id).await?;
            if !raw.is_empty() {
                collected.extend(session.mailbox.decrypt_replies(&raw));
                for (key, slot) in mailbox_keys.iter().zip(results.iter_mut()) {
                    if slot.is_none()
                        && let Ok(Some(obj)) = session.mailbox.reassemble(&collected, key, secret)
                    {
                        *slot = Some(obj);
                    }
                }
                if done(&results) {
                    break;
                }
            }
            tokio::time::sleep(POLL).await;
        }
        Ok(results)
    }
}
