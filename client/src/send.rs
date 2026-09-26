//! 送信 ── 私信（前方秘匿）と公開投稿（本文・ファイル・掲示板レス）
//!
//! # 本体と Hint は別の回路で出す（回路分離 / 19.2.4）
//!
//! 同じ出口だと、その出口を取られた時点で「本体を置いた者と Hint を流した者は同一」が
//! 確定し、時間分離の意味が相殺される。ガードは同じだが、ガードは中身を読めない。

use crate::circuit::Circuit;
use crate::boards::BoardId;
use crate::client::{AetherClient, board_target};
use crate::error::{ClientError, Result};
use crate::events::{self, ClientEvent, SendState};
use aether_core::crypto::identity::NodeId;
use aether_core::mailbox::hint_release::{self, ReleaseStatus, UploadProfile};
use aether_core::mailbox::index::IndexDescriptor;
use aether_core::mailbox::schrodinger::SchrodingerMailbox;
use aether_core::net::gossip::GossipClient;
use aether_core::protocol::hint::{HintPacket, current_timestamp};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 送信後、QUIC が書き出し終えるまで接続を閉じずに待つ時間
///
/// onion パケットは入口へ書いた直後で、まだ送出しきっていない。ここで RelayClient を
/// drop すると接続が閉じて書いたシャードが失われる。
const FLUSH_WAIT: Duration = Duration::from_secs(2);

/// 公開投稿の内容
#[derive(Debug, Clone)]
pub struct PublicPost {
    /// 書き込む板
    pub board: BoardId,
    pub content: Vec<u8>,
    /// 索引に載せる見出し（ファイル名 / スレッドの題）
    pub name: String,
    /// 返信先の投稿（content_ref）。空なら新規スレッド
    pub parents: Vec<[u8; 32]>,
}

/// 送信の結果
#[derive(Debug, Clone, Serialize)]
pub struct SendReport {
    /// 本体の出口（hex NodeId）
    pub body_exit: String,
    /// Hint の出口（チャンク化した公開ファイルは Hint を流さないので `None`）
    pub hint_exit: Option<String>,
    /// 実際に網へ出したバイト数（シャード・複製込み）
    pub bytes: u64,
    /// 公開投稿の参照（`get` / 返信に使う, hex）
    pub content_ref: Option<String>,
    /// チャンク数（チャンク化した場合）
    pub chunks: Option<usize>,
}

impl AetherClient {
    /// 私信を送る
    ///
    /// `secret` を省くと相手の NodeId から鍵を合意する。初回は相手のプレキー束を取って
    /// X3DH で前方秘匿のセッションを立て、以後はラチェットで封じる。
    pub async fn send_private(
        &self,
        to: NodeId,
        secret: Option<[u8; 32]>,
        message: &[u8],
    ) -> Result<SendReport> {
        self.send_private_inner(to, secret, message, None).await
    }

    /// 送信の進み具合を [`ClientEvent::SendStatus`](crate::ClientEvent::SendStatus) で流す版
    ///
    /// `ticket` は呼び出し側が付ける番号（トーク画面の吹き出しと対応させる）。
    pub async fn send_private_tracked(
        &self,
        to: NodeId,
        secret: Option<[u8; 32]>,
        message: &[u8],
        ticket: u64,
    ) -> Result<SendReport> {
        self.send_private_inner(to, secret, message, Some(ticket)).await
    }

    async fn send_private_inner(
        &self,
        to: NodeId,
        secret: Option<[u8; 32]>,
        message: &[u8],
        ticket: Option<u64>,
    ) -> Result<SendReport> {
        use aether_core::crypto::session::Session;
        use aether_core::crypto::x3dh;

        let identity = self.keys.load_identity()?;
        let me = identity.public_id();
        let shared_secret = match secret {
            Some(s) => s,
            None => identity.agree(&to)?,
        };

        // 認識（blind_tag / mailbox 位置）は agree 秘密、本文はラチェット（分離）
        let ks = self.keystore()?;
        let (mut session, initial) = match ks.load(&to)? {
            Some(s) => (s, None),
            None => {
                events::progress(
                    &self.events,
                    format!("初回接触: {} のプレキー束を取得して X3DH 鍵合意します", to),
                );
                let bundle = self.fetch_prekey_bundle(&to).await?;
                let (sk, init) = x3dh::initiate(&identity, &to, &bundle)?;
                events::progress(&self.events, "X3DH 成立（前方秘匿＋耐量子ハイブリッド）");
                (Session::bootstrap(&sk, &me, &to), Some(init))
            }
        };
        let sealed = session.seal(message, &[])?;
        // フレーム: 初回は [0x01][InitialMessage][sealed]、継続は [0x00][sealed]
        let body = match &initial {
            Some(init) => x3dh::frame_initial(init, &sealed)?,
            None => x3dh::frame_continuation(&sealed),
        };

        let (body_c, hint_c) = self.body_and_hint_circuits().await?;
        let report_exits = (hex_id(&body_c.exit.node_id), hex_id(&hint_c.exit.node_id));
        let mailbox = self.sending_mailbox(body_c, hint_c, to, shared_secret);

        let (hint, _key, profile) = mailbox.place_ratchet_body(&to, &body).await?;
        // 置けたらラチェットを進めて保存（置けないまま進めると相手と食い違う）
        ks.save(&to, &session)?;
        events::progress(&self.events, format!("本体を配置しました ({} バイト送出)", profile.bytes));
        self.send_status(ticket, SendState::Placed);

        self.release_hint(&mailbox, &hint, &profile, ticket).await?;
        self.flush_in_background(mailbox);

        Ok(SendReport {
            body_exit: report_exits.0,
            hint_exit: Some(report_exits.1),
            bytes: profile.bytes,
            content_ref: None,
            chunks: None,
        })
    }

    /// 公開キーワードで投稿する（本文・ファイル・掲示板のレス）
    ///
    /// 大きな内容はチャンク化して content-address で置き、Hint は流さない（pull 専用）。
    /// どちらも索引に記述子を載せるので、キーワードで検索できる。
    pub async fn publish(&self, post: PublicPost) -> Result<SendReport> {
        use aether_core::mailbox::chunk;

        let k_pub = post.board.key();
        let target = board_target(&k_pub);

        let (body_c, hint_c) = self.body_and_hint_circuits().await?;
        let body_exit = hex_id(&body_c.exit.node_id);
        let hint_exit = hex_id(&hint_c.exit.node_id);
        let mailbox = self.sending_mailbox(body_c, hint_c, target, k_pub);

        let report = if chunk::needs_chunking(post.content.len()) {
            let content_ref = mailbox.place_chunked(&k_pub, &post.name, &post.content).await?;
            let chunks = post.content.len().div_ceil(chunk::CHUNK_SIZE);
            events::progress(
                &self.events,
                format!("{} チャンクに分割して配置しました ({} バイト)", chunks, post.content.len()),
            );
            let descriptor = IndexDescriptor {
                content_ref,
                name: post.name.clone(),
                size: post.content.len() as u64,
                timestamp: current_timestamp(),
                chunked: true,
                parents: post.parents.clone(),
            };
            mailbox.publish_descriptor(&k_pub, &descriptor).await?;
            events::progress(&self.events, "索引に記述子を公開しました");
            SendReport {
                body_exit,
                hint_exit: None,
                bytes: post.content.len() as u64,
                content_ref: Some(hex::encode(content_ref)),
                chunks: Some(chunks),
            }
        } else {
            let (hint, _key, profile) = mailbox.place_body_profiled(&target, &post.content).await?;
            events::progress(&self.events, format!("本体を配置しました ({} バイト送出)", profile.bytes));

            self.release_hint(&mailbox, &hint, &profile, None).await?;

            let (content_ref, _) = mailbox
                .decrypt_hint(&hint)
                .ok_or_else(|| ClientError::invalid("自分の Hint を開けません"))?;
            let descriptor = IndexDescriptor {
                content_ref,
                name: post.name.clone(),
                size: profile.bytes,
                timestamp: current_timestamp(),
                chunked: false,
                parents: post.parents.clone(),
            };
            mailbox.publish_descriptor(&k_pub, &descriptor).await?;
            events::progress(&self.events, "索引に記述子を公開しました");
            SendReport {
                body_exit,
                hint_exit: Some(hint_exit),
                bytes: profile.bytes,
                content_ref: Some(hex::encode(content_ref)),
                chunks: None,
            }
        };

        self.flush_in_background(mailbox);
        Ok(report)
    }

    /// 本体用と Hint 用の回路（出口を分ける）
    async fn body_and_hint_circuits(&self) -> Result<(Circuit, Circuit)> {
        let body = self.build_circuit(&[]).await?;
        let hint = match self.build_circuit(&[body.exit.node_id]).await {
            Ok(c) => c,
            Err(_) => {
                events::warning(
                    &self.events,
                    "他に使える出口が無いため、本体と Hint が同じ出口を通ります（相関リスク）",
                );
                self.build_circuit(&[]).await?
            }
        };
        events::progress(
            &self.events,
            format!(
                "3 ホップ回路: 本体の出口 {} ／ Hint の出口 {}",
                body.exit.addr, hint.exit.addr
            ),
        );
        Ok((body, hint))
    }

    /// 回路を書き出し終えるまで裏で保ってから閉じる
    ///
    /// 呼び出し元は待たずに次へ進める。プロセスを終える前は [`flush`](Self::flush) を呼ぶこと。
    fn flush_in_background(&self, mailbox: SchrodingerMailbox) {
        let handle = tokio::spawn(async move {
            tokio::time::sleep(FLUSH_WAIT).await;
            drop(mailbox);
        });
        self.pending_flush.lock().unwrap().push(handle);
    }

    /// 送信した回路が書き出し終えるまで待つ（CLI など、すぐ終了するときに呼ぶ）
    pub async fn flush(&self) {
        let handles: Vec<_> = std::mem::take(&mut *self.pending_flush.lock().unwrap());
        for h in handles {
            let _ = h.await;
        }
    }

    fn sending_mailbox(
        &self,
        body: Circuit,
        hint: Circuit,
        target: NodeId,
        secret: [u8; 32],
    ) -> SchrodingerMailbox {
        let contacts = HashMap::from([(target, secret)]);
        SchrodingerMailbox::with_directory(
            Arc::new(body.client),
            Arc::new(GossipClient::new(hint.client)),
            Arc::new(Mutex::new(contacts)),
            self.node.directory(),
        )
        // 放流網が要求する PoW を Hint に解かせる（受信側の検証と一致させる）
        .with_pow_difficulty(self.node.gossip().pow_difficulty())
    }

    /// 網の活動量から決まる遅延を置いてから Hint を放流する（時間分離 / 18.4.5）
    async fn release_hint(
        &self,
        mailbox: &SchrodingerMailbox,
        hint: &HintPacket,
        profile: &UploadProfile,
        ticket: Option<u64>,
    ) -> Result<()> {
        let policy = mailbox.release_policy(
            self.node.gossip().observed_hint_rate().await,
            hint_release::DEFAULT_RELAY_THROUGHPUT_BPS,
        );
        match policy.status(profile) {
            ReleaseStatus::BuriedInNoise { .. } => {
                events::progress(&self.events, "Hint を即時放流します（中継トラフィックに埋もれる大きさ）")
            }
            other => events::progress(&self.events, format!("Hint 放流: {:?}", other)),
        }

        let delay = policy.delay_for(profile);
        if !delay.is_zero() {
            events::progress(&self.events, format!("{:?} 待機してから放流します", delay));
            self.send_status(ticket, SendState::Delayed { seconds: delay.as_secs().max(1) });
            tokio::time::sleep(delay).await;
        }
        mailbox.broadcast_hint(hint).await?;
        events::progress(&self.events, "Hint を放流しました");
        self.send_status(ticket, SendState::Sent);
        Ok(())
    }

    fn send_status(&self, ticket: Option<u64>, status: SendState) {
        if let Some(ticket) = ticket {
            let _ = self.events.send(ClientEvent::SendStatus { ticket, status });
        }
    }
}

pub(crate) fn hex_id(id: &NodeId) -> String {
    hex::encode(id.as_bytes())
}
