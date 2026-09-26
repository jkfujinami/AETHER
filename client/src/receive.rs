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
use aether_core::net::tunnel::TunnelEndpoint;
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
/// シャードが揃わないまま待つ上限（揃わない＝保持者が落ちた）。取りに行った時点から数える
const PENDING_TIMEOUT: Duration = Duration::from_secs(120);
/// 公開コンテンツを保持者として置き直す間隔（18.3-C）
///
/// 保持者は取得のたびに TTL（既定 1 週間）を延ばすので、置き直しは保持者の入れ替わりに
/// 抗うためのもの。取得した投稿 1 件ごとに 25 本の onion PUT が出るので、頻繁にはしない。
///
/// Hint の再放流（18.3-A）はしない。発見は索引（pull）が担い、再放流すると取得した人の数
/// だけ同じ投稿の Hint が網全体に流れ続ける。
const RESEED_INTERVAL: Duration = Duration::from_secs(6 * 3600);
/// 起動後、最初にプレキー束を置くまでの最大の遅れ
///
/// 束の置き場所は NodeId から誰でも計算できるので、その保持者は「いつ置き直されたか」を
/// 見られる。以前は 10 分ごとに置き直していて、保持者に在席を 10 分刻みで知らせていた
/// （公開リレー一覧の出入りと突き合わせると IP を絞り込める）。いまは起動時に一度、
/// 以後は置き場所が変わる期間ごとに一度、期間内のランダムな時刻に置く。
const PREKEY_FIRST_DELAY_MAX: Duration = Duration::from_secs(300);
/// プレキー束を置けなかったときの再試行間隔
const PREKEY_RETRY: Duration = Duration::from_secs(300);

/// Hint を見つけてから本体を取りに行くまでの最大の遅れ
const FETCH_JITTER_MAX: Duration = Duration::from_secs(60);
/// ダミーの取得の平均間隔
const COVER_FETCH_MEAN: Duration = Duration::from_secs(90);

/// 取りに行くまでの遅れ（0〜FETCH_JITTER_MAX の一様乱数）
fn fetch_jitter() -> Duration {
    Duration::from_millis(rand::random::<u64>() % FETCH_JITTER_MAX.as_millis() as u64)
}

/// 0〜`max` の一様乱数
fn random_below(max: Duration) -> Duration {
    Duration::from_millis(rand::random::<u64>() % (max.as_millis() as u64).max(1))
}

/// 次の期間の中のランダムな時刻までの待ち時間（プレキー束の置き直し）
fn until_random_point_in_next_period(now: u64) -> Duration {
    use aether_core::mailbox::schrodinger::PREKEY_PERIOD_SECS;
    let next_start = (SchrodingerMailbox::prekey_period(now) + 1) * PREKEY_PERIOD_SECS;
    let at = next_start + rand::random::<u64>() % PREKEY_PERIOD_SECS;
    Duration::from_secs(at - now)
}

/// 次のダミー取得までの間隔（指数分布：いつ来るか予測できない）
fn cover_interval() -> Duration {
    let u: f64 = rand::random::<f64>().max(1e-9);
    Duration::from_secs_f64(-u.ln() * COVER_FETCH_MEAN.as_secs_f64())
        .min(COVER_FETCH_MEAN * 6)
}

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
    /// 返信先（ダミーの取得で自分宛てに一周させる）
    reply_to: TunnelEndpoint,
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
            // 起動直後に置くと「この人が今起動した」が保持者に見えるので、少しずらす
            tokio::time::sleep(random_below(PREKEY_FIRST_DELAY_MAX)).await;
            loop {
                let wait = match this.publish_prekeys_once().await {
                    Ok(()) => {
                        events::progress(&this.events, "プレキー束を公開しました");
                        until_random_point_in_next_period(aether_core::protocol::hint::current_timestamp())
                    }
                    Err(e) => {
                        events::warning(&this.events, format!("プレキー公開に失敗: {}", e));
                        PREKEY_RETRY
                    }
                };
                tokio::time::sleep(wait).await;
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
        let period = SchrodingerMailbox::prekey_period(aether_core::protocol::hint::current_timestamp());
        mailbox.publish_prekey_bundle(&bundle, period).await?;
        // 書いた直後に接続を閉じるとシャードが失われる
        tokio::time::sleep(Duration::from_secs(2)).await;
        Ok(())
    }

    async fn open_receive_session(&self, secrets: &HashMap<NodeId, [u8; 32]>) -> Result<LiveSession> {
        let PullSession {
            mailbox,
            receive_tunnel_id,
            reply_to,
            gateway,
        } = self.open_pull_session(secrets.clone()).await?;
        events::progress(&self.events, format!("受信トンネルを張りました (gateway {})", gateway));
        Ok(LiveSession {
            mailbox: Arc::new(mailbox),
            receive_tunnel_id,
            reply_to,
            opened: Instant::now(),
        })
    }

    async fn receive_loop(self: Arc<Self>, identity: Identity, receiver: Arc<Receiver>) -> Result<()> {
        use std::sync::atomic::Ordering;

        let me = identity.public_id();
        let keystore = self.keystore()?;
        let prekeys = keystore.load_prekeys()?.map(|(_, s)| s);
        // 本体の TTL を過ぎた処理済みの目印を掃除する（起動のたびに 1 回）
        if let Err(e) = keystore.prune_seen() {
            events::warning(&self.events, format!("処理済みの目印を掃除できません: {}", e));
        }
        // 認識に使う秘密：購読（静的な DH・板の鍵）＋会話ごとの Hint 鍵チェーン（昨日・今日・明日）
        let secrets_now = || {
            let (secrets, _, moved) = with_hint_chains(&receiver.subs.lock().unwrap(), &keystore);
            if moved {
                // 日が変わった。新しい鍵で拾えるよう次の周回で張り替える
                receiver.changed.store(true, Ordering::SeqCst);
            }
            secrets
        };

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
        let mut next_cover = tokio::time::Instant::now() + cover_interval();

        loop {
            tokio::select! {
                hint = hints.recv() => match hint {
                    Ok(hint) => {
                        let current = sessions[0].mailbox.clone();
                        // 自分宛てかは手元だけで判定する（網には何も出さない）
                        // 処理済みは取りに行かない。Hint は網内で再配送される（backlog 同期・再注入）
                        if let Some((key, secret)) = current.try_decrypt_hint(&hint)
                            && let Some((nonce, _)) = current.decrypt_hint(&hint)
                            && !pending.contains_key(&key)
                            && !keystore.is_seen(&key).unwrap_or(false)
                        {
                            // **すぐには取りに行かない。** Hint の放流直後に取得が出ると、
                            // 放流時刻とガードの観測を突き合わせて受信者を特定できる
                            let delay = fetch_jitter();
                            events::progress(
                                &self.events,
                                format!("自分宛ての Hint を検出。{} 秒後に本体を取り寄せます", delay.as_secs()),
                            );
                            pending.insert(key, PendingBody {
                                secret,
                                nonce,
                                shards: Vec::new(),
                                since: Instant::now() + delay,
                            });
                            tokio::spawn(async move {
                                tokio::time::sleep(delay).await;
                                let _ = current.request_object(&key, &secret).await;
                            });
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        events::warning(&self.events, format!("Hint を {} 件取りこぼしました", n));
                    }
                    Err(_) => return Ok(()),
                },
                // **ダミーの取得。** ガードから見て「Hint の後に取得が出た」が受信の
                // 手掛かりにならないよう、取得の流れを平時から途切れさせない。
                //
                // 以前は実在しない鍵を取りに行っていたが、それでは**返信が戻らない**。
                // 本物の取得はシャードが戻ってくるので、ガードや回線を事後に照会した者は
                // 「取得の後に着信があるか」で本物だけを選べた。いまは本物と同じ本数の
                // 小さな onion を自分の返信トンネルの gateway へ送り、一周して戻らせる
                // （外から見て、本数・大きさ・着信の有無が本物の取得に揃う）
                _ = tokio::time::sleep_until(next_cover) => {
                    let current = sessions[0].mailbox.clone();
                    let reply_to = sessions[0].reply_to.clone();
                    tokio::spawn(async move {
                        send_cover_fetch(&current, &reply_to).await;
                    });
                    next_cover = tokio::time::Instant::now() + cover_interval();
                }
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
            let (_, origins, _) = with_hint_chains(&receiver.subs.lock().unwrap(), &keystore);
            let mut done = Vec::new();
            for (mailbox_key, p) in pending.iter_mut() {
                // 封が別メッセージ・偽造を弾くので、素通しで足していい
                p.shards.extend(decrypted.iter().cloned());
                let Some(origin) = origins.get(&p.secret).cloned() else { continue };

                let (msg, public_object) = match &origin {
                    // 公開コンテンツ：静的 K_pub で復号。中身は Hint の nonce（内容アドレス）と照合する
                    Origin::Public(_) => {
                        match current.open_public(&p.shards, mailbox_key, &p.secret, &p.nonce) {
                            Some((msg, object)) => (msg, Some(object)),
                            None => continue,
                        }
                    }
                    // 私信：生本体を復元し、フレームを開く（前方秘匿）
                    Origin::Private(contact) => {
                        let Ok(Some(body)) = current.reassemble_raw(&p.shards, mailbox_key, &p.secret) else {
                            continue;
                        };
                        // 開く前に処理済みにする。開いた後に落ちると、再配送で初回フレームを
                        // 開き直してセッションを初期化してしまう
                        if !keystore.mark_seen(mailbox_key).unwrap_or(false) {
                            done.push(*mailbox_key);
                            continue;
                        }
                        let had_session = keystore.contains(contact);
                        match open_private_body(&keystore, &identity, prekeys.as_ref(), &me, contact, &body) {
                            Ok(Some(msg)) => {
                                if !had_session {
                                    // 会話が立った。相手はこれから Hint 鍵チェーンで送ってくる
                                    receiver.changed.store(true, Ordering::SeqCst);
                                }
                                (msg, None)
                            }
                            Ok(None) => {
                                done.push(*mailbox_key);
                                continue;
                            }
                            // 1 通の失敗で受信全体を止めない
                            Err(e) => {
                                events::warning(&self.events, format!("私信を開けません: {}", e));
                                done.push(*mailbox_key);
                                continue;
                            }
                        }
                    }
                };
                if public_object.is_some() && !keystore.mark_seen(mailbox_key).unwrap_or(false) {
                    done.push(*mailbox_key);
                    continue;
                }

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

                // 公開コンテンツなら、受け取った者が保持者になる (18.3-C)
                if let Some(object) = public_object {
                    self.spawn_reseed(current.clone(), *mailbox_key, p.secret, object);
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
        object: Vec<u8>,
    ) {
        let events_tx = self.events.clone();
        tokio::spawn(async move {
            // 検証済みの本体からシャードを作り直して置く（偽シャードを広めない）
            match mailbox.reseed_object(&mailbox_key, &secret, &object).await {
                Ok(_) => events::progress(&events_tx, "公開コンテンツを保持者として再シードしました"),
                Err(e) => events::warning(&events_tx, format!("再シードに失敗: {}", e)),
            }
            // 以降も定期的に維持する（保持者の入れ替わりに抗う。人気なほど保持者が多い）
            loop {
                tokio::time::sleep(RESEED_INTERVAL).await;
                let _ = mailbox.reseed_object(&mailbox_key, &secret, &object).await;
            }
        });
    }
}

/// 本物の取得 1 回ぶん（シャード数 × 複製数）の onion を、自分の返信トンネルへ一周させる
///
/// 本物の取得要求（鍵 32 バイト＋返信先）と同じ onion の大きさ区分に収まるよう、
/// 中身は数百バイトの乱数にする。gateway は本物の返信と同じく固定長に詰めて送り返す。
async fn send_cover_fetch(mailbox: &SchrodingerMailbox, reply_to: &TunnelEndpoint) {
    use aether_core::mailbox::{schrodinger::K_REPLICAS, sharding::TOTAL_SHARDS};
    use aether_core::protocol::wire::PacketType;

    for _ in 0..TOTAL_SHARDS * K_REPLICAS {
        let len = 64 + rand::random::<usize>() % 448;
        let mut data = reply_to.tunnel_id.to_vec();
        data.extend((0..len).map(|_| rand::random::<u8>()));
        let _ = mailbox
            .relay_client()
            .send_onion_message_typed(PacketType::TunnelData, &data, reply_to.gateway)
            .await;
    }
}

/// `(認識に使う秘密, 秘密ごとの出どころ, 日が進んだか)`
type ChainedSubscriptions = (HashMap<NodeId, [u8; 32]>, HashMap<[u8; 32], Origin>, bool);

/// 購読に、会話ごとの Hint 鍵チェーンの秘密を足したもの
///
/// チェーンの秘密は合成した NodeId をキーにして Mailbox の連絡先へ入れる
/// （認識は値だけを見るので、キーは重ならなければ何でもよい）。
fn with_hint_chains(
    subs: &Subscriptions,
    keystore: &KeyStore,
) -> ChainedSubscriptions {
    let mut secrets = subs.secrets.clone();
    let mut origins = subs.origins.clone();
    let now = aether_core::protocol::hint::current_timestamp();
    let mut moved_any = false;
    for origin in subs.origins.values() {
        let Origin::Private(contact) = origin else { continue };
        let Ok(Some(mut session)) = keystore.load(contact) else { continue };
        let (keys, moved) = session.hint_secrets_for_receive(now);
        if moved {
            // 古い日の鍵をディスクから消す
            let _ = keystore.save(contact, &session);
            moved_any = true;
        }
        for key in keys {
            secrets.insert(NodeId(key), key);
            origins.insert(key, Origin::Private(*contact));
        }
    }
    (secrets, origins, moved_any)
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
/// 受け取った初回メッセージから応答側のセッションを立てる
fn responder_session(
    identity: &Identity,
    prekeys: Option<&PreKeySecrets>,
    init: &aether_core::crypto::x3dh::InitialMessage,
) -> Option<aether_core::crypto::session::Session> {
    use aether_core::crypto::session::Session;
    let secrets = prekeys?;
    let sk = aether_core::crypto::x3dh::respond(identity, secrets, init).ok()?;
    Some(Session::responder(&sk, &secrets.signed_prekey_secret, init.ephemeral_key))
}

fn open_private_body(
    keystore: &KeyStore,
    identity: &Identity,
    prekeys: Option<&PreKeySecrets>,
    me: &NodeId,
    contact: &NodeId,
    body: &[u8],
) -> Result<Option<Vec<u8>>> {
    use aether_core::crypto::x3dh;

    let Ok((initial, sealed)) = x3dh::parse_frame(body) else {
        return Ok(None); // 壊れたフレームは黙って捨てる
    };

    let existing = keystore.load(contact)?;
    let mut session = match (initial, existing) {
        (None, Some(s)) => s,
        (None, None) => return Ok(None), // 初回メッセージを添えた 1 通がまだ届いていない
        (Some(init), existing) => {
            // 認識で特定した連絡先と、init の差出人が一致すること
            if init.initiator_node_id != *contact {
                return Ok(None);
            }
            match existing {
                // 既に立てたセッションの初回メッセージ（返事が届くまで相手は毎回添えてくる）。
                // **作り直さない** ── 作り直すと、こちらの送信側の状態が相手と食い違って会話が壊れる
                Some(s) if s.peer_initial_ek == Some(init.ephemeral_key) => s,
                // 互いに同時に初回接触した。NodeId の小さい側の接触を採る。
                // こちらが勝つなら、相手の 1 通は使い捨てのセッションで開くだけにして保存しない
                // （相手はこちらの初回メッセージを受け取って、こちらのセッションに乗り換える）
                Some(s) if s.pending_initial.is_some() && me.as_bytes() < contact.as_bytes() => {
                    let Some(mut temp) = responder_session(identity, prekeys, &init) else {
                        return Ok(None);
                    };
                    return Ok(temp.open(sealed, &[]).ok());
                }
                // それ以外（初めての接触・相手が状態を失って接触し直した・同時接触でこちらが負け）
                _ => match responder_session(identity, prekeys, &init) {
                    Some(s) => s,
                    None => return Ok(None),
                },
            }
        }
    };

    match session.open(sealed, &[]) {
        Ok(pt) => {
            keystore.save(contact, &session)?;
            Ok(Some(pt))
        }
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_jitter_stays_in_range_and_varies() {
        let samples: Vec<Duration> = (0..200).map(|_| fetch_jitter()).collect();
        assert!(samples.iter().all(|d| *d < FETCH_JITTER_MAX));
        // 毎回同じ遅れだと、放流時刻から一定だけずらしただけになる
        let distinct: std::collections::HashSet<_> = samples.iter().map(|d| d.as_millis()).collect();
        assert!(distinct.len() > 150);
    }

    #[test]
    fn cover_interval_is_bounded_with_the_expected_mean() {
        let samples: Vec<f64> = (0..5000).map(|_| cover_interval().as_secs_f64()).collect();
        assert!(samples.iter().all(|s| *s <= COVER_FETCH_MEAN.as_secs_f64() * 6.0));
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        let target = COVER_FETCH_MEAN.as_secs_f64();
        assert!((mean - target).abs() < target * 0.15, "平均 {} 秒", mean);
    }
}
