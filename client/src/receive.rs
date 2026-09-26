//! 受信 ── 自分宛ての Hint を拾い、本体を Inbound Tunnel 経由で取り寄せて開く
//!
//! Hint はディレクトリ上のリレーにしか流れないので、**受信は常駐（リレー）モード専用**。
//! 本体は Mailbox から直接返させない（要求者の IP が保持者に割れる）。
//! [`PullSession`](crate::pull::PullSession) の返信トンネルで受け取る。

use crate::boards::BoardId;
use crate::client::{AetherClient, board_target};
use crate::error::{ClientError, Result};
use crate::events::{self, ClientEvent, MessageSource};
use crate::pull::PullSession;
use aether_core::crypto::identity::{Identity, NodeId};
use aether_core::crypto::x3dh::PreKeySecrets;
use aether_core::mailbox::schrodinger::SchrodingerMailbox;
use aether_core::storage::keystore::KeyStore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 受信トンネルを張り替える間隔
///
/// ガードとの接続が切れる（ガードの再起動など）と、そのトンネルには二度と届かない。
/// 定期的に張り替えて、黙って受信が止まったままになるのを防ぐ。
const SESSION_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// 張り替え後も古いトンネルを読み続ける時間（取り寄せ中の本体が古い方へ返ってくる）
const SESSION_GRACE: Duration = Duration::from_secs(3 * 60);
/// 起動直後、最初のトンネルが張れるまで粘る時間
const FIRST_SESSION_WAIT: Duration = Duration::from_secs(60);
/// シャードが揃わないまま待つ上限（揃わない＝保持者が落ちた）
const PENDING_TIMEOUT: Duration = Duration::from_secs(120);
/// 公開コンテンツを保持者として維持する間隔（18.3-A,C）
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(600);
/// プレキー束を再公開する間隔（保持者の入れ替わり・TTL に抗う）
const PREKEY_REPUBLISH_INTERVAL: Duration = Duration::from_secs(600);

/// 受信したい相手
#[derive(Debug, Clone)]
pub struct Contact {
    pub node_id: NodeId,
    /// 事前共有秘密。`None` なら NodeId から鍵を合意する
    pub secret: Option<[u8; 32]>,
}

/// 受信に使う秘密ごとの出どころ
#[derive(Clone)]
enum Origin {
    Private(NodeId),
    Public(String),
}

/// 受信中の購読（友だちの追加で後から増える）
#[derive(Default)]
pub(crate) struct Subscriptions {
    secrets: HashMap<NodeId, [u8; 32]>,
    origins: HashMap<[u8; 32], Origin>,
}

/// 受信ループと共有する状態
pub(crate) struct Receiver {
    subs: std::sync::Mutex<Subscriptions>,
    /// 購読が変わった。次の周回でトンネルを張り替える（新しい秘密で Hint を拾うため）
    changed: std::sync::atomic::AtomicBool,
}

/// 張ったトンネル 1 本
struct LiveSession {
    mailbox: Arc<SchrodingerMailbox>,
    receive_tunnel_id: [u8; 32],
    opened: Instant,
}

/// 取り寄せ中の本体
struct PendingBody {
    secret: [u8; 32],
    /// mailbox_key の素。再放流 (18.3-A) に要る
    nonce: [u8; 32],
    shards: Vec<Vec<u8>>,
    since: Instant,
}

impl AetherClient {
    /// 私信の連絡先と板の購読を始める
    ///
    /// 受信したメッセージは [`ClientEvent::Received`] で流れる。
    pub async fn start_receiving(
        self: &Arc<Self>,
        contacts: Vec<Contact>,
        boards: Vec<(BoardId, String)>,
    ) -> Result<()> {
        if !self.relay_mode {
            return Err(ClientError::invalid(
                "受信には常駐（リレー）モードが必要です（Hint はリレーにしか流れません）",
            ));
        }
        let identity = self.keys.load_identity()?;
        self.ensure_prekeys()?;

        let mut subs = Subscriptions::default();
        for c in contacts {
            add_private(&mut subs, &identity, &c)?;
        }
        for (board, label) in boards {
            let k_pub = board.key();
            subs.secrets.insert(board_target(&k_pub), k_pub);
            subs.origins.insert(k_pub, Origin::Public(label));
        }

        let receiver = Arc::new(Receiver {
            subs: std::sync::Mutex::new(subs),
            changed: std::sync::atomic::AtomicBool::new(false),
        });
        {
            let mut slot = self.receiver.lock().unwrap();
            if slot.is_some() {
                return Err(ClientError::invalid("既に受信しています"));
            }
            *slot = Some(receiver.clone());
        }

        let this = self.clone();
        let events_tx = self.events.clone();
        tokio::spawn(async move {
            if let Err(e) = this.receive_loop(identity, receiver).await {
                events::warning(&events_tx, format!("受信を継続できません: {}", e));
            }
        });
        Ok(())
    }

    /// 受信中に私信の相手を増やす（友だち追加）
    ///
    /// 受信していなければ何もしない。次の周回で受信トンネルを張り替えて反映する。
    pub fn add_contact(&self, contact: Contact) -> Result<()> {
        let Some(receiver) = self.receiver.lock().unwrap().clone() else {
            return Ok(());
        };
        let identity = self.keys.load_identity()?;
        add_private(&mut receiver.subs.lock().unwrap(), &identity, &contact)?;
        receiver
            .changed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// 自分のプレキー束を網へ公開し続ける（誰からでも初回接触を受けられるように）
    pub fn start_prekey_publisher(self: &Arc<Self>) -> Result<()> {
        self.ensure_prekeys()?;
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                match this.publish_prekeys_once().await {
                    Ok(()) => events::progress(&this.events, "プレキー束を公開しました"),
                    Err(e) => events::warning(&this.events, format!("プレキー公開に失敗: {}", e)),
                }
                tokio::time::sleep(PREKEY_REPUBLISH_INTERVAL).await;
            }
        });
        Ok(())
    }

    async fn publish_prekeys_once(&self) -> Result<()> {
        use aether_core::net::gossip::GossipClient;
        use aether_core::net::relay::RelayClient;

        let bundle = self
            .keystore()?
            .load_prekeys()?
            .map(|(b, _)| b)
            .ok_or_else(|| ClientError::invalid("プレキーが未生成です"))?;

        let circuit = self.build_circuit(&[]).await?;
        let mailbox = SchrodingerMailbox::with_directory(
            Arc::new(circuit.client),
            Arc::new(GossipClient::new(RelayClient::new()?)),
            Arc::new(std::sync::Mutex::new(HashMap::new())),
            self.node.directory(),
        );
        mailbox.publish_prekey_bundle(&bundle).await?;
        // 書いた直後に接続を閉じるとシャードが失われる
        tokio::time::sleep(Duration::from_secs(2)).await;
        Ok(())
    }

    async fn open_receive_session(&self, secrets: &HashMap<NodeId, [u8; 32]>) -> Result<LiveSession> {
        let PullSession {
            mailbox,
            receive_tunnel_id,
            gateway,
            ..
        } = self.open_pull_session(secrets.clone()).await?;
        events::progress(&self.events, format!("受信トンネルを張りました (gateway {})", gateway));
        Ok(LiveSession {
            mailbox: Arc::new(mailbox),
            receive_tunnel_id,
            opened: Instant::now(),
        })
    }

    async fn receive_loop(self: Arc<Self>, identity: Identity, receiver: Arc<Receiver>) -> Result<()> {
        use std::sync::atomic::Ordering;

        let me = identity.public_id();
        let keystore = self.keystore()?;
        let prekeys = keystore.load_prekeys()?.map(|(_, s)| s);
        let secrets_now = || receiver.subs.lock().unwrap().secrets.clone();

        // 最初のトンネル。リレー一覧の収束を待ちつつ粘る
        let deadline = Instant::now() + FIRST_SESSION_WAIT;
        let first = loop {
            match self.open_receive_session(&secrets_now()).await {
                Ok(s) => break s,
                Err(e) if Instant::now() > deadline => return Err(e),
                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        };
        // 先頭が現行。後ろは猶予中の古いトンネル
        let mut sessions: Vec<LiveSession> = vec![first];

        let mut hints = self.node.gossip().subscribe();
        // シャードは順不同・重複で届く。mailbox_key ごとに束ね、異なる 3 枚が揃うまで貯める
        let mut pending: HashMap<[u8; 32], PendingBody> = HashMap::new();

        loop {
            tokio::select! {
                hint = hints.recv() => match hint {
                    Ok(hint) => {
                        let current = &sessions[0].mailbox;
                        // 自分宛てでなければ何も起きない（手元だけで判定）。自分宛てなら取り寄せを出す
                        if let Ok(Some(key)) = current.process_hint(&hint).await
                            && let Some((nonce, secret)) = current.decrypt_hint(&hint)
                        {
                            events::progress(&self.events, "自分宛ての Hint を検出。本体を取り寄せます");
                            pending.entry(key).or_insert_with(|| PendingBody {
                                secret,
                                nonce,
                                shards: Vec::new(),
                                since: Instant::now(),
                            });
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        events::warning(&self.events, format!("Hint を {} 件取りこぼしました", n));
                    }
                    Err(_) => return Ok(()),
                },
                _ = tokio::time::sleep(Duration::from_millis(200)) => {}
            }

            // --- トンネルの張り替え（定期、または友だちが増えたとき）---
            if sessions[0].opened.elapsed() > SESSION_LIFETIME
                || receiver.changed.swap(false, Ordering::SeqCst)
            {
                match self.open_receive_session(&secrets_now()).await {
                    Ok(s) => sessions.insert(0, s),
                    Err(e) => events::warning(&self.events, format!("受信トンネルの張り替えに失敗: {}", e)),
                }
            }
            sessions.truncate(1 + sessions[1..]
                .iter()
                .take_while(|s| s.opened.elapsed() < SESSION_LIFETIME + SESSION_GRACE)
                .count());

            // --- 届いた返信を集める ---
            let mut decrypted = Vec::new();
            for s in &sessions {
                let raw = self.take_replies(&s.receive_tunnel_id).await?;
                if !raw.is_empty() {
                    decrypted.extend(s.mailbox.decrypt_replies(&raw));
                }
            }
            pending.retain(|_, p| p.since.elapsed() < PENDING_TIMEOUT);
            if decrypted.is_empty() {
                continue;
            }

            let current = sessions[0].mailbox.clone();
            let origins = receiver.subs.lock().unwrap().origins.clone();
            let mut done = Vec::new();
            for (mailbox_key, p) in pending.iter_mut() {
                // 封が別メッセージ・偽造を弾くので、素通しで足していい
                p.shards.extend(decrypted.iter().cloned());
                let Some(origin) = origins.get(&p.secret).cloned() else { continue };

                let opened = match &origin {
                    // 公開コンテンツ：静的 K_pub で復号
                    Origin::Public(_) => current
                        .reassemble(&p.shards, mailbox_key, &p.secret)
                        .ok()
                        .flatten(),
                    // 私信：生本体を復元し、フレームを開く（前方秘匿）
                    Origin::Private(contact) => match current.reassemble_raw(&p.shards, mailbox_key, &p.secret) {
                        Ok(Some(body)) => {
                            open_private_body(&keystore, &identity, prekeys.as_ref(), &me, contact, &body)?
                        }
                        _ => None,
                    },
                };
                let Some(msg) = opened else { continue };

                let source = match &origin {
                    Origin::Private(id) => MessageSource::Contact {
                        node_id: hex::encode(id.as_bytes()),
                    },
                    Origin::Public(k) => MessageSource::Board { label: k.clone() },
                };
                let _ = self.events.send(ClientEvent::Received {
                    source,
                    text: String::from_utf8_lossy(&msg).into_owned(),
                });

                // 公開コンテンツなら、受け取った者が保持者になる (18.3-C) ＋ Hint を再放流 (18.3-A)
                if matches!(origin, Origin::Public(_)) {
                    self.spawn_reseed(current.clone(), *mailbox_key, p.secret, p.nonce, p.shards.clone());
                }
                done.push(*mailbox_key);
            }
            for key in done {
                pending.remove(&key);
            }
        }
    }

    fn spawn_reseed(
        &self,
        mailbox: Arc<SchrodingerMailbox>,
        mailbox_key: [u8; 32],
        secret: [u8; 32],
        nonce: [u8; 32],
        sealed: Vec<Vec<u8>>,
    ) {
        let events_tx = self.events.clone();
        tokio::spawn(async move {
            match mailbox.reseed(&mailbox_key, &secret, &sealed).await {
                Ok(n) => events::progress(&events_tx, format!("公開コンテンツを保持者として再シード ({} shard)", n)),
                Err(e) => events::warning(&events_tx, format!("再シードに失敗: {}", e)),
            }
            let _ = mailbox.republish(&secret, &nonce).await;
            // 以降も定期的に維持する（人気なほど保持者が多い）
            loop {
                tokio::time::sleep(REPUBLISH_INTERVAL).await;
                let _ = mailbox.reseed(&mailbox_key, &secret, &sealed).await;
                let _ = mailbox.republish(&secret, &nonce).await;
            }
        });
    }
}

fn add_private(subs: &mut Subscriptions, identity: &Identity, c: &Contact) -> Result<()> {
    let secret = match c.secret {
        Some(s) => s,
        None => identity.agree(&c.node_id)?,
    };
    subs.secrets.insert(c.node_id, secret);
    subs.origins.insert(secret, Origin::Private(c.node_id));
    Ok(())
}

/// 受信した私信フレームを開く（X3DH 初回接触 or 継続ラチェット）
///
/// 初回接触なら自分のプレキー秘密で respond して `SK` を復元しセッションを立てる。
/// 継続なら保存済みセッションで開く。開けたらラチェットを進めて保存する。
fn open_private_body(
    keystore: &KeyStore,
    identity: &Identity,
    prekeys: Option<&PreKeySecrets>,
    me: &NodeId,
    contact: &NodeId,
    body: &[u8],
) -> Result<Option<Vec<u8>>> {
    use aether_core::crypto::session::Session;
    use aether_core::crypto::x3dh;

    let Ok((initial, sealed)) = x3dh::parse_frame(body) else {
        return Ok(None); // 壊れたフレームは黙って捨てる
    };

    let mut session = match initial {
        Some(init) => {
            // 認識で特定した連絡先と、init の差出人が一致すること
            if init.initiator_node_id != *contact {
                return Ok(None);
            }
            let Some(secrets) = prekeys else { return Ok(None) };
            match x3dh::respond(identity, secrets, &init) {
                Ok(sk) => Session::bootstrap(&sk, me, contact),
                Err(_) => return Ok(None),
            }
        }
        None => match keystore.load(contact)? {
            Some(s) => s,
            None => return Ok(None), // 初回を取りこぼした
        },
    };

    match session.open(sealed, &[]) {
        Ok(pt) => {
            keystore.save(contact, &session)?;
            Ok(Some(pt))
        }
        Err(_) => Ok(None),
    }
}
