//! 掲示板（2ch 風）── 板・スレ一覧・レス番号・`>>n` アンカー・名無しさん・スレ内 ID
//!
//! - **板 = 乱数 ID**（[`crate::boards`]）。ID を知る人だけが読める（公式の板は誰でも）。
//! - **スレ = 索引の根の投稿。** レスはその子孫。番号は時刻順に手元で振る。
//! - **アンカー `>>n`** は投稿時に参照先の ref（`>>@<ref 先頭>`）へ書き換えて保存し、
//!   表示時に手元の番号へ戻す。読む人ごとに取れたレスの集合が違っても、指す先はずれない。
//! - **ID はスレ内だけで同じ、スレをまたぐと別物。** 端末の秘密とスレの識別子から
//!   導出した署名鍵で書き込みに署名し、その公開鍵の短縮を ID として見せる。
//!   他人は同じ ID を騙れない（署名が通らない）。
//!
//! # スレごとの秘密・日替わり ID
//!
//! 以前は端末に 1 つの秘密（bbs.key）から全スレの ID 鍵を導いていた。押収で
//! その 1 つを読まれると、全スレの自分の ID を計算し直せて、署名でどの投稿も
//! 「この端末が書いた」と証明できてしまう（過去の全投稿の作者性が一括で割れる）。
//!
//! 今はスレごとに**ランダムな**秘密を作り、`(thread → secret)` を暗号化して保存する。
//! ID の署名鍵はさらに**日替わり**（`H(domain ‖ thread_secret ‖ day)`）にする。
//! 同じスレ・同じ日なら同じ ID、日をまたぐと変わる（2ch の「トリップ」と同じ発想）。
//! これで押収されても、割れるのは「そのスレを最近使ったこと」までで、
//! 過去の投稿すべての作者性が一括で証明されることはない。
//!
//! [`BBS_THREAD_SECRET_TTL`] を過ぎて書き込みの無いスレの秘密は掃除する。
//! 消えた後にまた書けば新しい ID になる。

use crate::board::build_board;
use crate::boards::BoardId;
use crate::client::AetherClient;
use crate::error::{ClientError, Result};
use crate::keys::KeyFiles;
use crate::send::PublicPost;
use aether_core::crypto::identity::{Identity, NodeId};
use aether_core::mailbox::index::IndexDescriptor;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// 書き込みの封筒の先頭（CLI などの素の本文と区別する）
const ENVELOPE_MAGIC: &[u8; 6] = b"AEBBS1";
/// ID 鍵の導出に混ぜるタグ
const ID_KEY_DOMAIN: &[u8] = b"aether_bbs_thread_id_v1";
/// 署名に混ぜるタグ
const SIG_DOMAIN: &[u8] = b"aether_bbs_post_v1";
/// 保存時のアンカーの形（`>>@` + ref の先頭 16 hex）
const STORED_ANCHOR: &str = ">>@";
const ANCHOR_REF_HEX: usize = 16;

/// 1 レスの本文の上限（文字）。長文はチャンク化されて「スレを開く」で取れなくなる
pub const MAX_BODY_CHARS: usize = 4000;

/// これだけ書き込みが無いスレの秘密は消す（押収時に割れる範囲を狭める）
///
/// 消えた後にまた書けば、新しい秘密から新しい ID が始まる。
pub const BBS_THREAD_SECRET_TTL: u64 = 7 * 86_400;

/// 1 日の秒数（ID を日替わりにする単位）
const DAY_SECS: u64 = 86_400;

/// 名前欄（名無しさんだけ）
pub const ANONYMOUS_NAME: &str = "名無しさん";

/// 書き込みの封筒
#[derive(Serialize, Deserialize)]
struct Envelope {
    /// スレの識別子（スレ立て時に乱数、レスはそれを写す）。ID の導出に使う
    thread: [u8; 32],
    body: String,
    id_pub: [u8; 32],
    sig: Vec<u8>,
}

/// スレ一覧の 1 行
#[derive(Debug, Clone, Serialize)]
pub struct ThreadSummary {
    /// スレを開く・書き込むときに使う（hex）
    pub root_ref: String,
    pub title: String,
    pub res_count: usize,
    /// 最後の書き込み (UNIX 秒)
    pub last_post: u64,
    /// 勢い（累積 PoW）
    pub heat: u32,
}

/// スレを開いた結果
#[derive(Debug, Clone, Serialize)]
pub struct ThreadView {
    pub root_ref: String,
    pub title: String,
    pub posts: Vec<Res>,
    /// 書き込むときにそのまま返してもらう文脈
    pub reply: ReplyContext,
}

/// レス 1 件
#[derive(Debug, Clone, Serialize)]
pub struct Res {
    /// レス番号（1 始まり、時刻順）
    pub no: usize,
    pub content_ref: String,
    pub name: String,
    /// スレ内 ID（署名が通らない・素の本文なら `None`）
    pub id: Option<String>,
    pub timestamp: u64,
    /// 本文。アンカーは番号に解決済み
    pub body: Vec<Segment>,
    /// 本文を取れなかった（保持者が居ない）
    pub missing: bool,
}

/// 本文の断片
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Segment {
    Text { text: String },
    /// `>>n`。指す先がこのスレに無ければ `no = None`
    Anchor { no: Option<usize> },
}

/// 書き込みの文脈（スレを開いたときに渡され、書き込み時に返してもらう）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyContext {
    pub root_ref: String,
    /// スレの識別子（hex）
    pub thread: String,
    /// レス番号 n の ref は `refs[n - 1]`（hex）
    pub refs: Vec<String>,
}

/// スレごとの秘密 1 件（`bbs_threads.bin` に保存する）
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThreadSecretEntry {
    secret: [u8; 32],
    /// 最後に書き込んだ時刻 (UNIX 秒)。[`BBS_THREAD_SECRET_TTL`] を過ぎたら掃除する
    last_used: u64,
}

/// 保存形式（スレの識別子 → 秘密）
#[derive(Debug, Default, Serialize, Deserialize)]
struct ThreadSecrets {
    threads: HashMap<[u8; 32], ThreadSecretEntry>,
}

impl KeyFiles {
    /// 廃止した「端末単位の掲示板秘密」（読んだら消す）
    ///
    /// これ 1 つから全スレの ID を導いていたため、押収されると全投稿の作者性が
    /// 一括で割れた。読み直す必要は無い（ID の導出方式ごと変えたため）ので、
    /// 見つけたら消すだけでよい。
    fn legacy_bbs_key_path(&self) -> std::path::PathBuf {
        self.data_dir().join("bbs.key")
    }

    fn bbs_threads_path(&self) -> std::path::PathBuf {
        self.data_dir().join("bbs_threads.bin")
    }

    fn load_thread_secrets(&self) -> Result<ThreadSecrets> {
        let _ = std::fs::remove_file(self.legacy_bbs_key_path());
        match self.read_secure(&self.bbs_threads_path())? {
            Some(bytes) => Ok(bincode::deserialize(&bytes).unwrap_or_default()),
            None => Ok(ThreadSecrets::default()),
        }
    }

    fn save_thread_secrets(&self, secrets: &ThreadSecrets) -> Result<()> {
        let bytes = bincode::serialize(secrets)
            .map_err(|e| ClientError::invalid(format!("スレの秘密を保存できません: {}", e)))?;
        self.write_secure(&self.bbs_threads_path(), &bytes)
    }

    /// スレの ID 鍵の元になる秘密を得る（無ければランダムに作る）
    ///
    /// 呼ぶたびに `last_used` を更新して延命する。同時に、
    /// [`BBS_THREAD_SECRET_TTL`] を過ぎて書き込みの無い他スレの秘密を掃除する
    /// （書き込み時・読み込み時どちらでも掃除されるよう、ここで一括して行う）。
    fn thread_secret(&self, thread: &[u8; 32]) -> Result<[u8; 32]> {
        let now = aether_core::protocol::hint::current_timestamp();
        let mut secrets = self.load_thread_secrets()?;
        secrets
            .threads
            .retain(|_, e| now.saturating_sub(e.last_used) < BBS_THREAD_SECRET_TTL);

        let secret = match secrets.threads.get_mut(thread) {
            Some(entry) => {
                entry.last_used = now;
                entry.secret
            }
            None => {
                let secret: [u8; 32] = rand::random();
                secrets.threads.insert(*thread, ThreadSecretEntry { secret, last_used: now });
                secret
            }
        };
        self.save_thread_secrets(&secrets)?;
        Ok(secret)
    }
}

/// スレ内 ID の署名鍵（スレの秘密 × 日）
///
/// 日をまたぐと変わる（2ch のトリップと同じ発想）。`day` は
/// `UNIX 秒 / 86400`。読む側は署名の検証しかしない（[`open`]）ので、
/// この導出が必要なのは書き込む本人だけ。
fn thread_key(secret: &[u8; 32], day: u64) -> Identity {
    let seed: [u8; 32] = Sha256::new()
        .chain_update(ID_KEY_DOMAIN)
        .chain_update(secret)
        .chain_update(day.to_le_bytes())
        .finalize()
        .into();
    Identity::from_bytes(&seed).expect("32 バイトの種")
}

/// 現在の「日」（UNIX 秒 / 86400）
fn current_day() -> u64 {
    aether_core::protocol::hint::current_timestamp() / DAY_SECS
}

fn signing_message(thread: &[u8; 32], body: &str) -> Vec<u8> {
    let mut m = SIG_DOMAIN.to_vec();
    m.extend_from_slice(thread);
    m.extend_from_slice(body.as_bytes());
    m
}

/// 公開鍵から 2ch 風の 8 文字 ID を作る
fn display_id(id_pub: &[u8; 32]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let h = Sha256::digest(id_pub);
    h.iter()
        .take(8)
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

fn seal(secret: &[u8; 32], thread: [u8; 32], body: String) -> Vec<u8> {
    let key = thread_key(secret, current_day());
    let sig = key.sign(&signing_message(&thread, &body));
    let env = Envelope {
        thread,
        body,
        id_pub: *key.public_id().as_bytes(),
        sig,
    };
    let mut out = ENVELOPE_MAGIC.to_vec();
    out.extend_from_slice(&bincode::serialize(&env).expect("封筒は直列化できる"));
    out
}

/// 本文を開く。封筒なら (スレ識別子, 本文, ID)、素の本文なら (None, 本文, None)
fn open(bytes: &[u8]) -> (Option<[u8; 32]>, String, Option<String>) {
    if let Some(rest) = bytes.strip_prefix(ENVELOPE_MAGIC.as_slice())
        && let Ok(env) = bincode::deserialize::<Envelope>(rest)
    {
        let valid = aether_core::crypto::identity::verify_signature(
            &NodeId(env.id_pub),
            &signing_message(&env.thread, &env.body),
            &env.sig,
        )
        .is_ok();
        let id = valid.then(|| display_id(&env.id_pub));
        return (Some(env.thread), env.body, id);
    }
    (None, String::from_utf8_lossy(bytes).into_owned(), None)
}

/// 書き込み時：`>>n` を参照先の ref に書き換え、指した ref（親）を返す
fn anchors_to_refs(body: &str, refs: &[String]) -> (String, Vec<String>) {
    let mut out = String::with_capacity(body.len());
    let mut parents = Vec::new();
    let mut rest = body;
    while let Some(pos) = rest.find(">>") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 2..];
        let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        match digits.parse::<usize>().ok().and_then(|n| refs.get(n.wrapping_sub(1))) {
            Some(r) if !digits.is_empty() => {
                out.push_str(STORED_ANCHOR);
                out.push_str(&r[..ANCHOR_REF_HEX.min(r.len())]);
                if !parents.contains(r) {
                    parents.push(r.clone());
                }
                rest = &after[digits.len()..];
            }
            _ => {
                out.push_str(">>");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    (out, parents)
}

/// 表示時：保存形のアンカー（と素の `>>n`）を番号へ解決して断片に分ける
fn render_body(body: &str, refs: &[String]) -> Vec<Segment> {
    let mut segs = Vec::new();
    let mut text = String::new();
    let mut rest = body;
    while let Some(pos) = rest.find(">>") {
        text.push_str(&rest[..pos]);
        let after = &rest[pos + 2..];
        if let Some(stored) = after.strip_prefix('@') {
            let prefix: String = stored.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            if !prefix.is_empty() {
                let no = refs.iter().position(|r| r.starts_with(&prefix)).map(|i| i + 1);
                flush_text(&mut segs, &mut text);
                segs.push(Segment::Anchor { no });
                rest = &stored[prefix.len()..];
                continue;
            }
        }
        // 素の本文（CLI など）の `>>n` は手元の番号とみなす
        let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(n) = digits.parse::<usize>() {
            flush_text(&mut segs, &mut text);
            segs.push(Segment::Anchor {
                no: (1..=refs.len()).contains(&n).then_some(n),
            });
            rest = &after[digits.len()..];
            continue;
        }
        text.push_str(">>");
        rest = after;
    }
    text.push_str(rest);
    flush_text(&mut segs, &mut text);
    segs
}

fn check_body(body: &str) -> Result<()> {
    if body.trim().is_empty() {
        return Err(ClientError::invalid("本文を入れてください"));
    }
    if body.chars().count() > MAX_BODY_CHARS {
        return Err(ClientError::invalid(format!("本文が長すぎます（{} 文字まで）", MAX_BODY_CHARS)));
    }
    Ok(())
}

fn flush_text(segs: &mut Vec<Segment>, text: &mut String) {
    if !text.is_empty() {
        segs.push(Segment::Text {
            text: std::mem::take(text),
        });
    }
}

/// スレ（根とその子孫）を時刻順に並べる
fn thread_members<'a>(found: &'a [IndexDescriptor], root: &[u8; 32]) -> Vec<&'a IndexDescriptor> {
    let board = build_board(found, &vec![0; found.len()], 0);
    let root_hex = hex::encode(root);
    let Some(thread) = board
        .threads
        .iter()
        .find(|t| t.posts.first().is_some_and(|p| p.content_ref == root_hex))
    else {
        return Vec::new();
    };
    let by_ref: HashMap<String, &IndexDescriptor> =
        found.iter().map(|d| (hex::encode(d.content_ref), d)).collect();
    let mut members: Vec<&IndexDescriptor> = thread
        .posts
        .iter()
        .filter_map(|p| by_ref.get(&p.content_ref).copied())
        .collect();
    // 2ch はスレ内を時刻順に並べる。>>1 は必ず根
    members.sort_by_key(|d| (d.content_ref != *root, d.timestamp, d.content_ref));
    members
}

impl AetherClient {
    /// 板（キーワード）のスレ一覧を勢い順で返す
    pub async fn bbs_threads(&self, board: &BoardId) -> Result<Vec<ThreadSummary>> {
        let (found, pow) = self.search_raw(board).await?;
        let view = build_board(&found, &pow, aether_core::protocol::hint::current_timestamp());
        Ok(view
            .threads
            .into_iter()
            .filter_map(|t| {
                let root = t.posts.first()?.clone();
                Some(ThreadSummary {
                    root_ref: root.content_ref,
                    title: root.name,
                    res_count: t.posts.len(),
                    last_post: t.posts.iter().map(|p| p.timestamp).max().unwrap_or(0),
                    heat: t.heat,
                })
            })
            .collect())
    }

    /// スレを開く（レスの本文をまとめて取得し、番号・ID・アンカーを解決する）
    pub async fn bbs_open_thread(&self, board: &BoardId, root_ref: &str) -> Result<ThreadView> {
        let root = crate::parse_hex32(root_ref, "スレの ref")?;
        let (found, _) = self.search_raw(board).await?;
        let members = thread_members(&found, &root);
        if members.is_empty() {
            return Err(ClientError::network("スレが見つかりません（dat 落ちか、保持者に届いていません）"));
        }

        let refs: Vec<String> = members.iter().map(|d| hex::encode(d.content_ref)).collect();
        let content_refs: Vec<[u8; 32]> = members.iter().map(|d| d.content_ref).collect();
        let bodies = self.get_bodies(board, &content_refs).await?;

        let mut thread_id: Option<[u8; 32]> = None;
        let posts = members
            .iter()
            .zip(bodies)
            .enumerate()
            .map(|(i, (d, body))| {
                let (thread, text, id) = match &body {
                    Some(b) => open(b),
                    None => (None, String::new(), None),
                };
                if i == 0 {
                    thread_id = thread;
                }
                // 別スレの識別子で署名された書き込みの ID は見せない（ID の持ち込み防止）
                let id = if thread.is_some() && thread == thread_id { id } else { None };
                Res {
                    no: i + 1,
                    content_ref: refs[i].clone(),
                    name: ANONYMOUS_NAME.to_string(),
                    id,
                    timestamp: d.timestamp,
                    body: render_body(&text, &refs),
                    missing: body.is_none(),
                }
            })
            .collect();

        // 素の本文で立ったスレは根の ref をスレ識別子にする
        let thread = thread_id.unwrap_or(root);
        Ok(ThreadView {
            root_ref: root_ref.to_string(),
            title: members[0].name.clone(),
            posts,
            reply: ReplyContext {
                root_ref: root_ref.to_string(),
                thread: hex::encode(thread),
                refs,
            },
        })
    }

    /// スレを立てる。返り値は立てたスレ（>>1 だけ）
    ///
    /// **網から読み直さず、手元の内容で返す。** 索引が 3 ホップを通って保持者に届く前に
    /// 読み直すと「見つからない」になる。他人の書き込みは後で開き直して取り込む。
    pub async fn bbs_new_thread(&self, board: &BoardId, title: &str, body: &str) -> Result<ThreadView> {
        let title = title.trim();
        if title.is_empty() {
            return Err(ClientError::invalid("スレタイを入れてください"));
        }
        check_body(body)?;
        let thread: [u8; 32] = rand::random();
        let secret = self.keys.thread_secret(&thread)?;
        let report = self
            .publish(PublicPost {
                board: *board,
                content: seal(&secret, thread, body.to_string()),
                name: title.to_string(),
                parents: Vec::new(),
            })
            .await?;
        let root_ref = report
            .content_ref
            .ok_or_else(|| ClientError::invalid("スレの ref を得られませんでした"))?;

        let refs = vec![root_ref.clone()];
        let first = own_res(1, &root_ref, &secret, body, &refs);
        Ok(ThreadView {
            root_ref: root_ref.clone(),
            title: title.to_string(),
            posts: vec![first],
            reply: ReplyContext {
                root_ref,
                thread: hex::encode(thread),
                refs,
            },
        })
    }

    /// スレに書き込む。本文の `>>n` はそのレスへの返信になる
    ///
    /// 返り値は自分のレス（手元の番号 = 今見えているレス数 + 1）。
    /// 呼び出し側は `ctx.refs` にその ref を足してから次の書き込みに使う。
    pub async fn bbs_reply(&self, board: &BoardId, ctx: &ReplyContext, body: &str) -> Result<Res> {
        check_body(body)?;
        let thread = crate::parse_hex32(&ctx.thread, "スレの識別子")?;
        let (stored, mut parents) = anchors_to_refs(body, &ctx.refs);
        // アンカーが無ければ >>1 の子にする（スレに属させる）
        if parents.is_empty() {
            parents.push(ctx.root_ref.clone());
        }
        let parents = parents
            .iter()
            .map(|r| crate::parse_hex32(r, "返信先の ref"))
            .collect::<Result<Vec<_>>>()?;

        let secret = self.keys.thread_secret(&thread)?;
        let report = self
            .publish(PublicPost {
                board: *board,
                content: seal(&secret, thread, stored.clone()),
                name: String::new(),
                parents,
            })
            .await?;
        let content_ref = report
            .content_ref
            .ok_or_else(|| ClientError::invalid("書き込みの ref を得られませんでした"))?;

        let mut refs = ctx.refs.clone();
        refs.push(content_ref.clone());
        Ok(own_res(refs.len(), &content_ref, &secret, &stored, &refs))
    }
}

/// 自分の書き込みを、網から読み直さずにレスとして組み立てる
fn own_res(
    no: usize,
    content_ref: &str,
    secret: &[u8; 32],
    stored_body: &str,
    refs: &[String],
) -> Res {
    Res {
        no,
        content_ref: content_ref.to_string(),
        name: ANONYMOUS_NAME.to_string(),
        id: Some(display_id(thread_key(secret, current_day()).public_id().as_bytes())),
        timestamp: aether_core::protocol::hint::current_timestamp(),
        body: render_body(stored_body, refs),
        missing: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs(n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("{:x}{}", i, "a".repeat(63))).collect()
    }

    #[test]
    fn anchors_survive_the_roundtrip() {
        let r = refs(3);
        let (stored, parents) = anchors_to_refs(">>2 それな\n>>9 は無い", &r);
        assert_eq!(parents, vec![r[1].clone()]);
        assert!(stored.contains(STORED_ANCHOR));
        assert_eq!(
            render_body(&stored, &r),
            vec![
                Segment::Anchor { no: Some(2) },
                Segment::Text { text: " それな\n".into() },
                Segment::Anchor { no: None },
                Segment::Text { text: " は無い".into() },
            ]
        );
    }

    #[test]
    fn id_is_stable_within_a_day_and_differs_across_bodies() {
        // 同じスレの秘密・同じ日なら、本文が違っても ID は同じ
        let secret = [1u8; 32];
        let thread = [10u8; 32];
        let id = |body: &str| open(&seal(&secret, thread, body.into())).2.unwrap();
        assert_eq!(id("a"), id("b"), "同じ日・同じスレでは同じ ID");
        assert_eq!(id("a").len(), 8);
    }

    #[test]
    fn id_differs_across_threads() {
        // 実際にはスレごとに別の乱数秘密を持つ（[`KeyFiles::thread_secret`]）ので、
        // 秘密が違えば同じ日でも別の ID になる
        let (secret1, secret2) = ([1u8; 32], [2u8; 32]);
        let thread = [10u8; 32];
        let id1 = open(&seal(&secret1, thread, "a".into())).2.unwrap();
        let id2 = open(&seal(&secret2, thread, "a".into())).2.unwrap();
        assert_ne!(id1, id2, "別スレ（別の秘密）では別の ID");
    }

    #[test]
    fn id_changes_across_days() {
        // 日をまたぐと ID が変わる（2ch のトリップと同じ発想）
        let secret = [7u8; 32];
        let today = display_id(thread_key(&secret, 100).public_id().as_bytes());
        let tomorrow = display_id(thread_key(&secret, 101).public_id().as_bytes());
        assert_ne!(today, tomorrow, "日が変わっても ID が同じ");
    }

    #[test]
    fn forged_signature_shows_no_id() {
        let mut sealed = seal(&[1u8; 32], [10u8; 32], "本物".into());
        // 本文だけ書き換える（署名はそのまま）
        let mut env: Envelope = bincode::deserialize(&sealed[ENVELOPE_MAGIC.len()..]).unwrap();
        env.body = "偽物".into();
        sealed = ENVELOPE_MAGIC.to_vec();
        sealed.extend(bincode::serialize(&env).unwrap());
        let (_, body, id) = open(&sealed);
        assert_eq!(body, "偽物");
        assert!(id.is_none(), "署名の通らない書き込みに ID を付けた");
    }

    #[test]
    fn own_res_shows_the_same_id_others_will_see() {
        // 手元で組み立てたレスの ID と、網から読んだ人が計算する ID が一致すること
        let (secret, thread) = ([3u8; 32], [4u8; 32]);
        let seen_by_others = open(&seal(&secret, thread, "x".into())).2.unwrap();
        let mine = own_res(1, "ab", &secret, "x", &["ab".into()]);
        assert_eq!(mine.id.unwrap(), seen_by_others);
    }

    #[test]
    fn plain_bodies_have_no_id() {
        let (thread, body, id) = open("CLI からの投稿 >>1".as_bytes());
        assert!(thread.is_none() && id.is_none());
        assert_eq!(body, "CLI からの投稿 >>1");
    }

    fn keys(passphrase: Option<&str>) -> (tempfile::TempDir, KeyFiles) {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFiles::new(dir.path(), passphrase.map(str::to_owned));
        (dir, keys)
    }

    #[test]
    fn thread_secret_is_stable_across_calls() {
        let (_dir, keys) = keys(None);
        let thread = [1u8; 32];
        let a = keys.thread_secret(&thread).unwrap();
        let b = keys.thread_secret(&thread).unwrap();
        assert_eq!(a, b, "同じスレなら同じ秘密が返る");
    }

    #[test]
    fn thread_secret_differs_per_thread() {
        let (_dir, keys) = keys(None);
        let a = keys.thread_secret(&[1u8; 32]).unwrap();
        let b = keys.thread_secret(&[2u8; 32]).unwrap();
        assert_ne!(a, b, "スレが違えば別の秘密");
    }

    #[test]
    fn thread_secret_is_forgotten_after_the_ttl() {
        let (_dir, keys) = keys(None);
        let thread = [9u8; 32];
        let original = keys.thread_secret(&thread).unwrap();

        // 7 日間書き込みが無かったことにする
        let mut secrets = keys.load_thread_secrets().unwrap();
        secrets.threads.get_mut(&thread).unwrap().last_used -= BBS_THREAD_SECRET_TTL + 1;
        keys.save_thread_secrets(&secrets).unwrap();

        let after = keys.thread_secret(&thread).unwrap();
        assert_ne!(original, after, "TTL を過ぎたら秘密が入れ替わり、ID も変わる");
    }

    #[test]
    fn thread_secrets_are_encrypted_with_a_passphrase() {
        let (_dir, keys) = keys(Some("hunter2"));
        keys.thread_secret(&[1u8; 32]).unwrap();

        let raw = std::fs::read(keys.bbs_threads_path()).unwrap();
        assert!(raw.starts_with(b"AESF"), "パスフレーズ設定時は平文で保存されている");

        // パスフレーズ無しでは読めない
        let locked = KeyFiles::new(keys.data_dir(), None);
        assert!(locked.load_thread_secrets().is_err());
    }

    #[test]
    fn legacy_bbs_key_is_removed_on_load() {
        let (_dir, keys) = keys(None);
        std::fs::write(keys.legacy_bbs_key_path(), b"old terminal-wide secret").unwrap();

        keys.thread_secret(&[1u8; 32]).unwrap();

        assert!(!keys.legacy_bbs_key_path().exists(), "廃止した端末単位の秘密を消していない");
    }
}
