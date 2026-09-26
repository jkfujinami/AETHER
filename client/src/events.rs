//! クライアントから UI へ流すイベント

use serde::Serialize;
use tokio::sync::broadcast;

/// イベントの送り口
pub type EventSender = broadcast::Sender<ClientEvent>;

/// UI が購読するイベント
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientEvent {
    /// 進捗（「本体を配置しました」など）
    Progress { message: String },
    /// 注意（平文保存・相関リスクなど）
    Warning { message: String },
    /// 送信の進み具合（`ticket` は送信を頼んだ側が付けた番号）
    SendStatus { ticket: u64, status: SendState },
    /// メッセージを受信した
    Received {
        source: MessageSource,
        text: String,
    },
}

/// 送信の状態
///
/// 相手に届いたか（既読）は分からない。確かめるには相手から返事の通信が要り、
/// 相手のオンライン時間帯が漏れるため、あえて持たない。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SendState {
    /// 本体を網に置いた。Hint を放流する前
    Placed,
    /// 匿名化のため Hint の放流を遅らせている
    Delayed { seconds: u64 },
    /// Hint を放流した（相手が受信できる状態）
    Sent,
}

/// 受信メッセージの出どころ
///
/// X3DH でも差出人の真正性は「どの秘密で開けたか」でしか分からない。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessageSource {
    /// 私信（連絡先の NodeId, hex）
    Contact { node_id: String },
    /// 購読している板（ラベル）
    Board { label: String },
}

/// イベントの送り口を作る
///
/// 受け手が遅れると古いイベントから落ちる（受信本文も落ちうるので UI は速やかに読むこと）。
pub fn event_channel() -> EventSender {
    broadcast::channel(1024).0
}

pub(crate) fn progress(tx: &EventSender, message: impl Into<String>) {
    let _ = tx.send(ClientEvent::Progress { message: message.into() });
}

pub(crate) fn warning(tx: &EventSender, message: impl Into<String>) {
    let _ = tx.send(ClientEvent::Warning { message: message.into() });
}
