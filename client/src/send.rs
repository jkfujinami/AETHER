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
    /// 私信の発言 ID（hex, [`crate::talks::TalkEnvelope`]）
    pub message_id: Option<String>,
}

impl AetherClient {
    /// 私信を送る
    ///
    /// `secret` を省くと相手の NodeId から鍵を合意する。初回は相手の友だちコードの招待で
    /// X3DH の前方秘匿のセッションを立て（[`AetherClient::accept_friend_code`]）、以後はラチェットで封じる。
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
        let shared_secret = match secret {
            Some(s) => s,
            None => identity.agree(&to)?,
        };

        // 認識（blind_tag / mailbox 位置）は agree 秘密、本文はラチェット（分離）
        let ks = self.keystore()?;
        let mut session = match ks.load(&to)? {
            Some(s) => s,
            None => {
                // 初回接触は、相手から受け取った友だちコードの招待で始める（網からは何も取らない）
                let invite = ks.load_peer_invite(&to)?.ok_or_else(|| {
                    ClientError::invalid(
                        "この相手とはまだ会話を始められません。相手の友だちコードを追加するか、相手から先に送ってもらってください",
                    )
                })?;
                let now = aether_core::protocol::hint::current_timestamp();
                if now >= invite.expires_at {
                    return Err(ClientError::invalid(
                        "相手の友だちコードの期限が切れています（新しいコードをもらって追加し直してください）",
                    ));
                }
                let (sk, init) = x3dh::initiate(&identity, &to, &invite, now)?;
                events::progress(&self.events, "初回接触: 友だちコードの招待で鍵を合意しました（前方秘匿＋耐量子ハイブリッド）");
                Session::initiator(&sk, &invite.signed_prekey, init)
            }
        };
        let new_conversation = !ks.contains(&to);
        // Hint（宛先の認識・本体の置き場所）の秘密。会話が立っていれば日ごとの鍵チェーン、
        // 初回接触の間は静的な DH（相手はまだ SK を持っていない）
        let hint_secret = session
            .hint_secret_for_send(aether_core::protocol::hint::current_timestamp())
            .unwrap_or(shared_secret);
        // 本文は発言の DAG の形で包む（親 = 書いた時点で見ていた会話の先端 / crate::talks）
        let parents = if self.privacy().save_talk_history {
            self.keys.talk_heads(&to).unwrap_or_else(|e| {
                events::warning(&self.events, format!("トーク履歴を読めないので、親を付けずに送ります: {}", e));
                Vec::new()
            })
        } else {
            Vec::new()
        };
        let envelope = crate::talks::TalkEnvelope::new(parents, message.to_vec());
        let sealed = session.seal(&envelope.encode(), &[])?;
        // **封じたらすぐ保存する。** 置く途中で失敗してから保存せずにやり直すと、同じ
        // メッセージ鍵（＝同じ鍵と nonce）で別の平文を封じることになる。途中まで置いた
        // シャードが残っていれば、二つの暗号文から平文の差が漏れる。受け取る側は
        // 飛んだ番号を取りこぼしとして扱えるので、進めすぎても会話は壊れない
        ks.save(&to, &session)?;
        if new_conversation {
            // 招待は使い捨て。会話が立ったので要らない（押収されたときに残すものを減らす）
            if let Err(e) = ks.remove_peer_invite(&to) {
                events::warning(&self.events, format!("使い終えた友だちコードを消せません: {}", e));
            }
            // 相手の返事は Hint 鍵チェーンで届く。受信中なら認識できるよう知らせる
            self.subscriptions_changed();
        }

        // フレーム: 相手から返事が来るまでは初回メッセージを添える [0x01][InitialMessage][sealed]。
        // 最初の 1 通を取りこぼされても、後の 1 通で相手はセッションを立てられる。
        // 返事が来てからは継続 [0x00][sealed]
        let body = match &session.pending_initial {
            Some(init) => x3dh::frame_initial(init, &sealed)?,
            None => x3dh::frame_continuation(&sealed),
        };

        let (body_c, hint_c) = self.body_and_hint_circuits().await?;
        let report_exits = (hex_id(&body_c.exit.node_id), hex_id(&hint_c.exit.node_id));
        let mailbox = self.sending_mailbox(body_c, hint_c, to, hint_secret);

        let (hint, _key, profile) = mailbox.place_ratchet_body(&to, &body).await?;
        events::progress(&self.events, format!("本体を配置しました ({} バイト送出)", profile.bytes));
        self.send_status(ticket, SendState::Placed);

        self.release_hint(&mailbox, &hint, &profile, ticket).await?;
        self.flush_in_background(mailbox);

        // 送り終えた発言だけを履歴に残す（届いていない発言を親にすると、相手の側で
        // 「欠けがある」と出続ける）
        if self.privacy().save_talk_history
            && let Err(e) = self.keys.append_talk_message(&to, envelope.to_message(true))
        {
            events::warning(&self.events, format!("トーク履歴の保存に失敗しました: {}", e));
        }

        Ok(SendReport {
            body_exit: report_exits.0,
            hint_exit: Some(report_exits.1),
            bytes: profile.bytes,
            content_ref: None,
            chunks: None,
            message_id: Some(hex::encode(envelope.id)),
        })
    }

    /// 公開キーワードで投稿する（本文・ファイル・掲示板のレス）
    ///
    /// 大きな内容はチャンク化して content-address で置き、Hint は流さない（pull 専用）。
    /// どちらも索引に記述子を載せるので、キーワードで検索できる。
    pub async fn publish(&self, post: PublicPost) -> Result<SendReport> {
        self.publish_inner(post, None, false).await
    }

    /// 大きなファイルの記述子を出すまでの進み具合を
    /// [`ClientEvent::SendStatus`](crate::ClientEvent::SendStatus) で流す版
    ///
    /// 小さな投稿の流れ（Hint の放流）は [`publish`](Self::publish) と変わらず、`ticket` は使わない。
    pub async fn publish_tracked(&self, post: PublicPost, ticket: u64) -> Result<SendReport> {
        self.publish_inner(post, Some(ticket), false).await
    }

    /// 添付ファイルを置く。**大きさによらず常に v2（チャンク化）で置く**
    ///
    /// 記述子の `chunked = true` がファイルの印になる（掲示板は本文を取りに行かず、
    /// 名前と大きさだけを見せる）。小さなファイルも最小 1MiB への切り上げが効く。
    /// `ticket` があれば [`ClientEvent::SendStatus`](crate::ClientEvent::SendStatus) を流す。
    pub async fn publish_file(
        &self,
        board: &BoardId,
        name: &str,
        content: Vec<u8>,
        parents: Vec<[u8; 32]>,
        ticket: Option<u64>,
    ) -> Result<SendReport> {
        if content.is_empty() {
            return Err(ClientError::invalid("空のファイルは添付できません"));
        }
        let post = PublicPost {
            board: *board,
            content,
            name: name.to_string(),
            parents,
        };
        self.publish_inner(post, ticket, true).await
    }

    /// `as_file` なら、小さくても v2 のファイルとして置く
    async fn publish_inner(&self, post: PublicPost, ticket: Option<u64>, as_file: bool) -> Result<SendReport> {
        use aether_core::mailbox::chunk;

        let k_pub = post.board.key();
        let target = board_target(&k_pub);

        // 大きなファイルは、Manifest が 1 オブジェクトに収まる大きさまで。回路を組む前に、何も送らず断る
        // （切り上げた後のチャンク数で数える。頭打ちは上限なので、切り上げで断る範囲は変わらない）
        let pad = self.privacy().pad_file_size;
        let as_v2 = as_file || chunk::needs_chunking(post.content.len());
        if as_v2 {
            let fits = chunk::v2_layout_chunks(post.name.len(), post.content.len() as u64, pad)
                .and_then(|chunks| chunk::manifest_v2_sealed_len(post.name.len(), chunks))
                .is_ok_and(|n| n <= chunk::SINGLE_BODY_LIMIT);
            if !fits {
                let max = chunk::max_file_size_v2(post.name.len());
                return Err(ClientError::invalid(format!(
                    "ファイルが大きすぎます（上限 約 {} MB）",
                    max / 1_000_000
                )));
            }
        }

        let (body_c, hint_c) = self.body_and_hint_circuits().await?;
        let body_exit = hex_id(&body_c.exit.node_id);
        let hint_exit = hex_id(&hint_c.exit.node_id);
        let mailbox = self.sending_mailbox(body_c, hint_c, target, k_pub);

        let report = if as_v2 {
            let (content_ref, profile) = mailbox.place_file_v2(&k_pub, &post.name, &post.content, pad).await?;
            // 利用者に見せるのは本当のチャンク数（埋め草は含めない）
            let chunks = chunk::v2_chunk_count(post.content.len() as u64);
            events::progress(
                &self.events,
                format!(
                    "{} チャンクに分割して配置しました ({} バイト、{} バイト送出)",
                    chunks,
                    post.content.len(),
                    profile.bytes
                ),
            );
            self.send_status(ticket, SendState::Placed);
            // 上げ終わった時刻と記述子が出る時刻を結びつけさせないため、窓の中でばらけて待つ。
            // Hint は出さない（大きなファイルは pull 専用）。待つのは索引に出すことだけ
            self.wait_before_descriptor(&mailbox, &profile, ticket).await;
            // 待った分だけ時刻が進むので、記述子の時刻は出す直前に取る
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
            self.send_status(ticket, SendState::Sent);
            SendReport {
                body_exit,
                hint_exit: None,
                bytes: post.content.len() as u64,
                content_ref: Some(hex::encode(content_ref)),
                chunks: Some(chunks),
                message_id: None,
            }
        } else {
            // 内容アドレスで置く（取得側が中身を ref と照合できる）
            let (hint, content_ref, profile) = mailbox.place_public_body(&k_pub, &post.content).await?;
            events::progress(&self.events, format!("本体を配置しました ({} バイト送出)", profile.bytes));

            self.release_hint(&mailbox, &hint, &profile, None).await?;
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
                message_id: None,
            }
        };

        self.flush_in_background(mailbox);
        Ok(report)
    }

    /// 本体用と Hint 用の回路（出口を分ける）
    ///
    /// **どちらも一周の疎通確認を通したものを使う。** 入口へ書けた時点で送信は成功扱いに
    /// なるので、中間や出口が落ちていると本体や Hint が黙って消える（送り手には見えない）。
    async fn body_and_hint_circuits(&self) -> Result<(Circuit, Circuit)> {
        let body = self.take_probed_circuit(&[]).await?.circuit;
        let hint = match self.take_probed_circuit(&[body.exit.node_id]).await {
            Ok(c) => c.circuit,
            Err(_) => {
                events::warning(
                    &self.events,
                    "他に使える出口が無いため、本体と Hint が同じ出口を通ります（相関リスク）",
                );
                self.take_probed_circuit(&[]).await?.circuit
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

    /// 放流方針。中継の量は、自分で測った値が仮定より**少ないときだけ**それを使う
    ///
    /// 実測は遅延を長くする向きにしか効かせない。誰でも自分の回路を自分のリレーに通して
    /// 実測を膨らませられ、膨らめば「中継の雑音に埋もれる」と判定されて遅延が縮む。
    /// その雑音は流した本人には差し引けるので、隠れ蓑にならない。
    /// 手元で測って手元で使うだけで、網には出さない。
    async fn current_release_policy(&self, mailbox: &SchrodingerMailbox) -> hint_release::ReleasePolicy {
        mailbox.release_policy(
            self.node.gossip().observed_hint_rate().await,
            relay_noise_estimate(self.node.observed_relay_throughput()),
        )
    }

    /// 網の活動量から決まる遅延を置いてから Hint を放流する（時間分離 / 18.4.5）
    async fn release_hint(
        &self,
        mailbox: &SchrodingerMailbox,
        hint: &HintPacket,
        profile: &UploadProfile,
        ticket: Option<u64>,
    ) -> Result<()> {
        let policy = self.current_release_policy(mailbox).await;
        match policy.status(profile) {
            ReleaseStatus::BuriedInNoise { .. } => {
                events::progress(&self.events, "Hint を即時放流します（中継トラフィックに埋もれる大きさ）")
            }
            other => events::progress(&self.events, format!("Hint 放流: {:?}", other)),
        }

        // 切り替えで無効なら待たない（PrivacyOptions::delay_release）
        let delay = release_wait(&policy, profile, self.privacy().delay_release);
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

    /// 大きなファイルの記述子を索引に出す前に、放流の窓の中で待つ
    ///
    /// 小さな投稿と同じ方針（網が空なら待たない、`delay_release` が偽なら待たない）。
    /// 8MiB 以上は窓に下限が付く（`hint_release::LARGE_MIN_WINDOW`）。
    async fn wait_before_descriptor(
        &self,
        mailbox: &SchrodingerMailbox,
        profile: &UploadProfile,
        ticket: Option<u64>,
    ) {
        let policy = self.current_release_policy(mailbox).await;
        let delay = release_wait(&policy, profile, self.privacy().delay_release);
        if delay.is_zero() {
            return;
        }
        events::progress(&self.events, format!("{:?} 待機してから記述子を公開します", delay));
        self.send_status(ticket, SendState::Delayed { seconds: delay.as_secs().max(1) });
        tokio::time::sleep(delay).await;
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

/// 放流の判定に使う中継の雑音の量（バイト/秒）。実測は仮定より少ないときだけ使う
///
/// [`AetherClient::current_release_policy`] の理由のとおり、実測で遅延が縮むことはない。
pub(crate) fn relay_noise_estimate(measured: Option<f64>) -> f64 {
    let assumed = hint_release::DEFAULT_RELAY_THROUGHPUT_BPS;
    measured.map_or(assumed, |m| m.min(assumed))
}

/// 放流の窓の幅。`delay_release` が偽なら 0（純粋な関数）
pub(crate) fn release_window(
    policy: &hint_release::ReleasePolicy,
    profile: &UploadProfile,
    delay_release: bool,
) -> Duration {
    if delay_release {
        policy.delay_window(profile)
    } else {
        Duration::ZERO
    }
}

/// 実際に待つ時間。窓の中の一様乱数
pub(crate) fn release_wait(
    policy: &hint_release::ReleasePolicy,
    profile: &UploadProfile,
    delay_release: bool,
) -> Duration {
    if release_window(policy, profile, delay_release).is_zero() {
        Duration::ZERO
    } else {
        policy.delay_for(profile)
    }
}

#[cfg(test)]
mod release_wait_tests {
    use super::*;
    use aether_core::mailbox::hint_release::{LARGE_MIN_WINDOW, LARGE_UPLOAD_BYTES, ReleasePolicy};

    fn policy(rate: f64) -> ReleasePolicy {
        ReleasePolicy { observed_hint_rate: rate, ..ReleasePolicy::default() }
    }

    fn upload(bytes: u64) -> UploadProfile {
        UploadProfile { bytes, duration: Duration::from_secs(10) }
    }

    #[test]
    fn measured_relay_noise_can_only_lengthen_delays() {
        let assumed = hint_release::DEFAULT_RELAY_THROUGHPUT_BPS;
        assert_eq!(relay_noise_estimate(None), assumed);
        assert_eq!(relay_noise_estimate(Some(assumed / 4.0)), assumed / 4.0, "静かなリレーは実測を使う");
        assert_eq!(relay_noise_estimate(Some(assumed * 100.0)), assumed, "膨らませた実測は仮定で頭打ち");
    }

    #[test]
    fn large_boundary_decides_the_one_hour_floor() {
        let p = policy(1.0);
        assert!(release_window(&p, &upload(LARGE_UPLOAD_BYTES), true) >= LARGE_MIN_WINDOW);
        assert!(release_window(&p, &upload(LARGE_UPLOAD_BYTES - 1), true) < LARGE_MIN_WINDOW);
    }

    #[test]
    fn empty_network_does_not_wait() {
        let p = policy(0.0);
        let big = upload(LARGE_UPLOAD_BYTES * 10);
        assert_eq!(release_window(&p, &big, true), Duration::ZERO);
        assert_eq!(release_wait(&p, &big, true), Duration::ZERO);
    }

    #[test]
    fn disabled_delay_does_not_wait() {
        let p = policy(10.0);
        let big = upload(LARGE_UPLOAD_BYTES * 10);
        assert_eq!(release_window(&p, &big, false), Duration::ZERO);
        assert_eq!(release_wait(&p, &big, false), Duration::ZERO);
    }

    #[test]
    fn wait_stays_inside_the_window() {
        let p = policy(1.0);
        let big = upload(LARGE_UPLOAD_BYTES);
        let w = release_window(&p, &big, true);
        for _ in 0..100 {
            assert!(release_wait(&p, &big, true) <= w);
        }
    }
}
