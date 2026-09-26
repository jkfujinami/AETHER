//! 画面から呼べる操作
//!
//! エラーは利用者向けの文字列で返す（画面にそのまま出す）。

use aether_client::bbs::{ReplyContext, Res, ThreadSummary, ThreadView};
use aether_client::{
    AetherClient, BoardId, BoardInfo, ClientConfig, Contact, Friend, KeyFiles, NodeMode,
    RelayOptions, SendReport, Status, TalkMessage, builtin_boards, event_channel, friend_uri,
    parse_friend_id,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::RwLock;

/// 画面へ流すイベント名（中身は [`aether_client::ClientEvent`]）
const EVENT_NAME: &str = "aether-event";

type CmdResult<T> = Result<T, String>;

pub struct AppState {
    data_dir: PathBuf,
    client: RwLock<Option<Arc<AetherClient>>>,
}

impl AppState {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            client: RwLock::new(None),
        }
    }

    async fn client(&self) -> CmdResult<Arc<AetherClient>> {
        self.client
            .read()
            .await
            .clone()
            .ok_or_else(|| "まだ網に接続していません".to_string())
    }
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

// ---------------------------------------------------------------- 起動・接続

#[derive(Serialize)]
pub struct AppInfo {
    data_dir: String,
    has_identity: bool,
    connected: bool,
}

#[tauri::command]
pub async fn app_info(state: State<'_, AppState>) -> CmdResult<AppInfo> {
    Ok(AppInfo {
        data_dir: state.data_dir.display().to_string(),
        has_identity: KeyFiles::new(&state.data_dir, None).has_identity(),
        connected: state.client.read().await.is_some(),
    })
}

/// 私信の身元（identity.key）を作る。返り値は NodeId（hex）
#[tauri::command]
pub async fn create_identity(
    state: State<'_, AppState>,
    passphrase: Option<String>,
) -> CmdResult<String> {
    let keys = KeyFiles::new(&state.data_dir, passphrase);
    let id = keys.create_identity(false).map_err(err)?;
    Ok(hex::encode(id.public_id().as_bytes()))
}

#[derive(Deserialize)]
pub struct ConnectParams {
    seed: String,
    passphrase: Option<String>,
    /// 常駐（リレー）として参加するか。トークの受信には必須
    relay: bool,
    /// リレーとして到達可能と宣言するアドレス（空なら STUN で判定）
    advertise: Option<String>,
}

#[derive(Serialize)]
pub struct Connected {
    /// 私信の宛先としての自分（鍵が無ければ None）
    my_node_id: Option<String>,
    /// トークを受信できるか（常駐かつ鍵あり）
    receiving: bool,
}

#[tauri::command]
pub async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    params: ConnectParams,
) -> CmdResult<Connected> {
    if state.client.read().await.is_some() {
        return Err("既に接続しています".into());
    }

    let seed: SocketAddr = params
        .seed
        .trim()
        .parse()
        .map_err(|_| format!("種ノードのアドレスが不正です: {}", params.seed))?;
    let advertise = match params.advertise.as_deref().map(str::trim) {
        Some(a) if !a.is_empty() => Some(
            a.parse::<SocketAddr>()
                .map_err(|_| format!("広告アドレスが不正です: {}", a))?,
        ),
        _ => None,
    };

    // イベントを画面へ中継する（接続前から流す：到達性判定などの進捗が見える）
    let events = event_channel();
    let mut rx = events.subscribe();
    let forward = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    let _ = forward.emit(EVENT_NAME, ev);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return,
            }
        }
    });

    let mode = if params.relay {
        NodeMode::Relay(RelayOptions {
            advertise,
            ..Default::default()
        })
    } else {
        NodeMode::Ephemeral
    };
    let client = AetherClient::start(
        ClientConfig {
            data_dir: state.data_dir.clone(),
            passphrase: params.passphrase.filter(|p| !p.is_empty()),
            // 到達アドレスを宣言したら、そのポートで待ち受ける（0 だと宣言と食い違う）
            port: advertise.map(|a| a.port()).unwrap_or(0),
            seed: Some(seed),
            min_relays: 3,
            mode,
            network: Default::default(),
        },
        events,
    )
    .await
    .map_err(err)?;

    // 常駐で鍵があれば、友だち全員からのトークを受信する
    let receiving = params.relay && client.keys().has_identity();
    if receiving {
        let contacts = client
            .keys()
            .load_friends()
            .map_err(err)?
            .iter()
            .map(|f| {
                Ok(Contact {
                    node_id: f.node_id()?,
                    secret: None,
                })
            })
            .collect::<aether_client::Result<Vec<_>>>()
            .map_err(err)?;
        client.start_receiving(contacts, Vec::new()).await.map_err(err)?;
        // 誰からでも初回接触を受けられるよう、プレキー束を公開しておく
        client.start_prekey_publisher().map_err(err)?;
    }

    let my_node_id = client
        .my_node_id()
        .ok()
        .map(|id| hex::encode(id.as_bytes()));
    *state.client.write().await = Some(client);
    Ok(Connected {
        my_node_id,
        receiving,
    })
}

#[tauri::command]
pub async fn status(state: State<'_, AppState>) -> CmdResult<Option<Status>> {
    match state.client.read().await.clone() {
        Some(c) => Ok(Some(c.status().await)),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------- 板

#[derive(Serialize)]
pub struct Boards {
    /// 公式の板（アプリに埋め込み・誰でも読める）
    builtin: Vec<BoardInfo>,
    /// お気に入り（入った板・作った板）
    favorites: Vec<BoardInfo>,
}

#[tauri::command]
pub async fn boards(state: State<'_, AppState>) -> CmdResult<Boards> {
    let client = state.client().await?;
    Ok(Boards {
        builtin: builtin_boards(),
        favorites: client.keys().load_favorite_boards().map_err(err)?,
    })
}

/// ID（aether-board:…）で板に入り、お気に入りに入れる
#[tauri::command]
pub async fn join_board(state: State<'_, AppState>, uri: String, label: String) -> CmdResult<BoardInfo> {
    let client = state.client().await?;
    let id = BoardId::parse(&uri).map_err(err)?;
    if let Some(b) = builtin_boards().into_iter().find(|b| b.uri == id.uri()) {
        return Ok(b); // 公式の板はお気に入りに入れなくても常に一覧にある
    }
    client.keys().add_favorite_board(&id, &label).map_err(err)
}

/// 非公開板を作る（乱数の ID。渡された人だけが入れる）
#[tauri::command]
pub async fn create_board(state: State<'_, AppState>, label: String) -> CmdResult<BoardInfo> {
    let client = state.client().await?;
    client
        .keys()
        .add_favorite_board(&BoardId::random(), &label)
        .map_err(err)
}

/// お気に入りの板を削除する（公式の板は削除できない）
#[tauri::command]
pub async fn remove_favorite_board(state: State<'_, AppState>, uri: String) -> CmdResult<()> {
    let client = state.client().await?;
    let id = BoardId::parse(&uri).map_err(err)?;
    if builtin_boards().into_iter().any(|b| b.uri == id.uri()) {
        return Err("公式の板は削除できません".into());
    }
    client.keys().remove_favorite_board(&id).map_err(err)
}

/// 共有用の QR（SVG）
#[tauri::command]
pub async fn qr_svg(text: String) -> CmdResult<String> {
    // 中身は板・自分の宛先の URI に限る（任意の文字列を QR にする口にしない）
    if !(text.starts_with(aether_client::boards::BOARD_URI_PREFIX)
        || text.starts_with(aether_client::friends::FRIEND_URI_PREFIX))
    {
        return Err("共有できない文字列です".into());
    }
    Ok(render_qr(&text)?)
}

fn render_qr(text: &str) -> CmdResult<String> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(err)?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .quiet_zone(true)
        .build())
}

// ---------------------------------------------------------------- 掲示板

#[tauri::command]
pub async fn bbs_threads(state: State<'_, AppState>, board: String) -> CmdResult<Vec<ThreadSummary>> {
    let board = BoardId::parse(&board).map_err(err)?;
    state.client().await?.bbs_threads(&board).await.map_err(err)
}

#[tauri::command]
pub async fn bbs_open_thread(
    state: State<'_, AppState>,
    board: String,
    root_ref: String,
) -> CmdResult<ThreadView> {
    state
        .client()
        .await?
        .bbs_open_thread(&BoardId::parse(&board).map_err(err)?, &root_ref)
        .await
        .map_err(err)
}

#[tauri::command]
pub async fn bbs_new_thread(
    state: State<'_, AppState>,
    board: String,
    title: String,
    body: String,
) -> CmdResult<ThreadView> {
    state
        .client()
        .await?
        .bbs_new_thread(&BoardId::parse(&board).map_err(err)?, &title, &body)
        .await
        .map_err(err)
}

#[tauri::command]
pub async fn bbs_reply(
    state: State<'_, AppState>,
    board: String,
    ctx: ReplyContext,
    body: String,
) -> CmdResult<Res> {
    state
        .client()
        .await?
        .bbs_reply(&BoardId::parse(&board).map_err(err)?, &ctx, &body)
        .await
        .map_err(err)
}

// ---------------------------------------------------------------- 友だち・トーク

#[tauri::command]
pub async fn friends(state: State<'_, AppState>) -> CmdResult<Vec<Friend>> {
    state.client().await?.keys().load_friends().map_err(err)
}

/// 友だちを追加する（`aether:<hex>` か hex）。受信中なら即座に受信対象に加える
#[tauri::command]
pub async fn add_friend(
    state: State<'_, AppState>,
    id: String,
    nickname: String,
) -> CmdResult<Friend> {
    let client = state.client().await?;
    let node_id = parse_friend_id(&id).map_err(err)?;
    if client.my_node_id().ok() == Some(node_id) {
        return Err("自分自身は追加できません".into());
    }
    let friend = client.keys().add_friend(&node_id, &nickname).map_err(err)?;
    client
        .add_contact(Contact {
            node_id,
            secret: None,
        })
        .map_err(err)?;
    Ok(friend)
}

/// 友だちを削除する（トーク履歴も一緒に消える）
///
/// 受信中の購読から即座に外す API は無いので、実際に受信対象から外れるのは
/// 次回の接続から（画面側でその旨を示すこと）。
#[tauri::command]
pub async fn remove_friend(state: State<'_, AppState>, node_id: String) -> CmdResult<()> {
    let client = state.client().await?;
    let id = parse_friend_id(&node_id).map_err(err)?;
    client.keys().remove_friend(&id).map_err(err)
}

#[derive(Serialize)]
pub struct MyQr {
    /// QR に入れた文字列（そのまま共有にも使える）
    uri: String,
    /// QR の SVG
    svg: String,
}

/// 自分の宛先の QR（友だち追加用）
#[tauri::command]
pub async fn my_qr(state: State<'_, AppState>) -> CmdResult<MyQr> {
    let id = state.client().await?.my_node_id().map_err(err)?;
    let uri = friend_uri(&id);
    let svg = render_qr(&uri)?;
    Ok(MyQr { uri, svg })
}

/// トークを送る。進み具合は `ticket` 付きの SendStatus イベントで流れる
#[tauri::command]
pub async fn send_talk(
    state: State<'_, AppState>,
    to: String,
    text: String,
    ticket: u64,
) -> CmdResult<SendReport> {
    let client = state.client().await?;
    let to = parse_friend_id(&to).map_err(err)?;
    if text.trim().is_empty() {
        return Err("本文が空です".into());
    }
    client
        .send_private_tracked(to, None, text.as_bytes(), ticket)
        .await
        .map_err(err)
}

// ---------------------------------------------------------------- トーク履歴の保存

/// 保存済みのトーク履歴を読む（相手の ID(hex) -> 履歴）。起動時（接続後）に呼ぶ
#[tauri::command]
pub async fn talks(state: State<'_, AppState>) -> CmdResult<HashMap<String, Vec<TalkMessage>>> {
    state.client().await?.keys().load_talks().map_err(err)
}

/// トークを1件保存する。送信状態は含めない（再起動をまたぐと意味を失うため）
#[tauri::command]
pub async fn record_talk_message(
    state: State<'_, AppState>,
    peer: String,
    mine: bool,
    text: String,
    time: u64,
) -> CmdResult<()> {
    let client = state.client().await?;
    let node_id = parse_friend_id(&peer).map_err(err)?;
    client
        .keys()
        .append_talk_message(&node_id, TalkMessage { mine, text, time })
        .map_err(err)
}
