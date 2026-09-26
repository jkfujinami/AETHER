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
//! 押収で端末の秘密（bbs.key）を読まれると「このスレのこの ID はこの端末」と再計算できる。
//! ID を持つ以上避けられないので、パスフレーズで暗号化して置く。

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

impl KeyFiles {
    fn bbs_key_path(&self) -> std::path::PathBuf {
        self.data_dir().join("bbs.key")
    }

    /// 掲示板 ID の元になる端末の秘密（無ければ作る）
    fn load_or_create_bbs_secret(&self) -> Result<[u8; 32]> {
        let path = self.bbs_key_path();
        let key = if path.exists() {
            self.read_key(&path)?
        } else {
            let k = Identity::generate();
            self.write_key(&path, &k)?;
            k
        };
        Ok(key.to_bytes())
    }
}

/// スレ内 ID の署名鍵（端末の秘密 × スレ）
fn thread_key(secret: &[u8; 32], thread: &[u8; 32]) -> Identity {
    let seed: [u8; 32] = Sha256::new()
        .chain_update(ID_KEY_DOMAIN)
        .chain_update(secret)
        .chain_update(thread)
        .finalize()
        .into();
    Identity::from_bytes(&seed).expect("32 バイトの種")
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
    let key = thread_key(secret, &thread);
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
        let secret = self.keys.load_or_create_bbs_secret()?;
        let thread: [u8; 32] = rand::random();
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
        let first = own_res(1, &root_ref, &secret, &thread, body, &refs);
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

        let secret = self.keys.load_or_create_bbs_secret()?;
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
        Ok(own_res(refs.len(), &content_ref, &secret, &thread, &stored, &refs))
    }
}

/// 自分の書き込みを、網から読み直さずにレスとして組み立てる
fn own_res(
    no: usize,
    content_ref: &str,
    secret: &[u8; 32],
    thread: &[u8; 32],
    stored_body: &str,
    refs: &[String],
) -> Res {
    Res {
        no,
        content_ref: content_ref.to_string(),
        name: ANONYMOUS_NAME.to_string(),
        id: Some(display_id(thread_key(secret, thread).public_id().as_bytes())),
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
    fn id_is_stable_in_a_thread_and_differs_across_threads() {
        let secret = [1u8; 32];
        let (t1, t2) = ([10u8; 32], [20u8; 32]);
        let id = |t: [u8; 32], body: &str| open(&seal(&secret, t, body.into())).2.unwrap();
        assert_eq!(id(t1, "a"), id(t1, "b"), "同じスレでは同じ ID");
        assert_ne!(id(t1, "a"), id(t2, "a"), "別スレでは別の ID");
        assert_eq!(id(t1, "a").len(), 8);
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
        let mine = own_res(1, "ab", &secret, &thread, "x", &["ab".into()]);
        assert_eq!(mine.id.unwrap(), seen_by_others);
    }

    #[test]
    fn plain_bodies_have_no_id() {
        let (thread, body, id) = open("CLI からの投稿 >>1".as_bytes());
        assert!(thread.is_none() && id.is_none());
        assert_eq!(body, "CLI からの投稿 >>1");
    }
}
