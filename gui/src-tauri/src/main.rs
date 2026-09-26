//! AETHER デスクトップ（Tauri）
//!
//! 画面（ui/）は表示だけを受け持ち、**通信は一切しない**（CSP で外部接続を禁止）。
//! 送受信はすべて [`aether_client`] を通す。画面から来るのは下の `#[tauri::command]` だけ。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // 鍵・Mailbox・ガードの置き場所。OS のアプリ用データ領域に置く
            let data_dir = app.path().app_data_dir()?.join("aether-data");
            app.manage(commands::AppState::new(data_dir));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::create_identity,
            commands::connect,
            commands::status,
            commands::boards,
            commands::join_board,
            commands::create_board,
            commands::remove_favorite_board,
            commands::qr_svg,
            commands::bbs_threads,
            commands::bbs_open_thread,
            commands::bbs_new_thread,
            commands::bbs_reply,
            commands::friends,
            commands::add_friend,
            commands::remove_friend,
            commands::my_qr,
            commands::send_talk,
            commands::talks,
            commands::record_talk_message,
        ])
        .run(tauri::generate_context!())
        .expect("AETHER の起動に失敗しました");
}
