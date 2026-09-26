# AETHER デスクトップ（Tauri）

`aether-client` をそのまま呼ぶデスクトップアプリ。画面（`ui/`）は表示だけを受け持ち、
通信はすべて Rust 側（3 ホップ回路）を通る。

## 動かす

```sh
cd gui
npm install          # Tauri CLI だけ（画面はバンドラを使わない素の HTML/JS）
npm run dev          # 開発起動
npm run build        # 配布物（.app / .dmg など）
```

鍵・Mailbox・ガードは OS のアプリ用データ領域（macOS なら
`~/Library/Application Support/org.aether.desktop/aether-data`）に置かれる。

## 画面

- **掲示板（2ch 風）** ── 板＝キーワード。スレ一覧（勢い順）、レス番号、`>>n` アンカー（ホバーで中身）、
  名無しさん、スレ内だけの使い捨て ID（署名付きで騙れない）。レス番号を押すと `>>n` を挿入。
- **トーク（LINE 風）** ── トーク一覧、吹き出し、友だち追加（自分の QR / ID の表示、ID 貼り付けで追加）、
  「送信中 → 送信待ち（匿名化のため約 N 秒）→ 送信済み」の表示。既読・入力中・オンライン表示は
  相手の在席時間を漏らすので持たない。トークの履歴は画面上だけ（再起動で消える）。

## 構成

| 場所 | 役割 |
|---|---|
| `src-tauri/src/commands.rs` | 画面から呼べる操作（接続・掲示板・友だち・トーク） |
| `ui/app.js` | 画面。網から来た文字列は必ず `textContent` で描く |
| `src-tauri/tauri.conf.json` | CSP で外部接続を禁止、`incognito` で WebView にデータを残さない |
| `src-tauri/capabilities/default.json` | 画面に許すのはイベント購読だけ |

`src-tauri` は本体のワークスペースから外してある（`cargo test --workspace` に Tauri を巻き込まない）。

## 守っていること

- **画面は網に出ない。** CSP の `connect-src` は IPC だけ。画像・フォントも外部から読まない。
- **網から来た文字列を HTML として解釈しない。** 投稿名・本文・受信メッセージは
  `textContent` で描く。innerHTML に入れると、悪意ある投稿が画面上でコマンドを呼べてしまう。
- **WebView に履歴・キャッシュを残さない**（`incognito`）。ログも画面上だけでディスクに書かない。
