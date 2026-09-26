// AETHER デスクトップの画面
//
// **網から来た文字列（スレタイ・レス・トーク）は必ず textContent で描く。**
// innerHTML に入れると、悪意ある書き込みがこの画面でスクリプトを動かし、
// 送信などのコマンドを勝手に呼べてしまう。

"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

/** 要素を作る。文字列はすべて textContent として入れる */
function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "text") node.textContent = v;
    else if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children) node.append(c);
  return node;
}

const state = {
  connected: false,
  receiving: false,
  // 掲示板
  boards: [], // BoardInfo（公式＋お気に入り）
  board: null, // 開いている板（BoardInfo）
  thread: null, // ThreadView
  // トーク
  friends: [], // [{node_id, nickname, added_at}]
  talks: new Map(), // node_id -> [{mine, text, time, ticket, status}]
  active: null, // 開いているトークの node_id
  unread: new Map(), // node_id -> 件数
  nextTicket: 1,
};

// ================================================================ 共通

function show(view) {
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${view}`));
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
}
document.querySelectorAll(".nav-item").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));

function setConnected(on) {
  state.connected = on;
  document.querySelectorAll("[data-needs-connection]").forEach((b) => (b.disabled = !on));
  $("conn-state").textContent = on ? (state.receiving ? "常駐中" : "接続中") : "未接続";
  $("conn-state").classList.toggle("on", on);
}

let toastTimer;
function toast(message, kind = "info") {
  const t = $("toast");
  t.textContent = message;
  t.className = `toast ${kind}`;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), kind === "error" ? 9000 : 4000);
}

/** 時間のかかる操作を「処理中」で包む。失敗は通知して undefined を返す */
async function busy(label, fn) {
  $("busy-text").textContent = label;
  $("busy-detail").textContent = "";
  $("busy").hidden = false;
  try {
    return await fn();
  } catch (e) {
    toast(String(e), "error");
    log(String(e), "warn");
    return undefined;
  } finally {
    $("busy").hidden = true;
  }
}

function log(message, kind = "") {
  const now = new Date().toLocaleTimeString("ja-JP", { hour12: false });
  $("log").prepend(el("li", { class: kind }, [el("time", { text: now }), el("span", { text: message })]));
  while ($("log").children.length > 500) $("log").lastChild.remove();
}

function hhmm(date) {
  return date.toLocaleTimeString("ja-JP", { hour: "2-digit", minute: "2-digit", hour12: false });
}

// ================================================================ イベント

listen("aether-event", ({ payload }) => {
  switch (payload.kind) {
    case "progress":
      log(payload.message);
      $("busy-detail").textContent = payload.message;
      break;
    case "warning":
      log(payload.message, "warn");
      toast(payload.message, "warn");
      break;
    case "send_status":
      updateSendStatus(payload.ticket, payload.status);
      break;
    case "received":
      if (payload.source.type === "contact") receiveTalk(payload.source.node_id, payload.text);
      break;
  }
});

// ================================================================ 接続

document.querySelectorAll('input[name="mode"]').forEach((r) =>
  r.addEventListener("change", () => {
    $("advertise-row").hidden = document.querySelector('input[name="mode"]:checked').value !== "relay";
  }),
);

$("btn-create-id").addEventListener("click", async () => {
  const pass = $("id-pass").value;
  // パスフレーズ無しは、平文保存を理解したチェックを入れない限り進めない
  if (!pass && !$("id-plaintext-ok").checked) {
    toast("パスフレーズを設定しないなら、チェックを入れて理解したことを示してください", "warn");
    return;
  }
  const id = await busy("鍵を生成しています…", () => invoke("create_identity", { passphrase: pass || null }));
  if (!id) return;
  $("identity-card").hidden = true;
  $("passphrase").value = pass;
  toast("鍵を作りました");
});

$("connect-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const relay = document.querySelector('input[name="mode"]:checked').value === "relay";
  const passphrase = $("passphrase").value;
  if (!passphrase && !$("passphrase-plaintext-ok").checked) {
    toast("パスフレーズを設定しないなら、チェックを入れて理解したことを示してください", "warn");
    return;
  }
  const params = {
    seed: $("seed").value,
    passphrase: passphrase || null,
    relay,
    advertise: relay ? $("advertise").value || null : null,
  };
  const res = await busy("網に参加しています…", () => invoke("connect", { params }));
  if (!res) return;
  state.receiving = res.receiving;
  setConnected(true);
  $("btn-connect").disabled = true;
  $("receive-warn").hidden = res.receiving;
  toast("参加しました");
  refreshStatus();
  await Promise.all([loadFriends(), loadBoards()]);
  await loadTalks();
  show("bbs");
});

async function refreshStatus() {
  try {
    const s = await invoke("status");
    if (s) $("relay-count").textContent = `既知リレー ${s.known_relays} 台`;
  } catch (_) {
    /* 状態が取れなくても表示だけ諦める */
  }
}
setInterval(refreshStatus, 5000);

// ================================================================ 掲示板（2ch 風）

const WEEK = ["日", "月", "火", "水", "木", "金", "土"];
function bbsTime(sec) {
  const d = new Date(sec * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}/${p(d.getMonth() + 1)}/${p(d.getDate())}(${WEEK[d.getDay()]}) ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** 掲示板の右側で見せる部分を切り替える */
function showBbs(part) {
  for (const id of ["empty", "join", "create", "share", "list", "thread"]) {
    $(`bbs-${id}`).hidden = id !== part;
  }
}

// ---------- 板一覧 ----------

async function loadBoards() {
  let boards;
  try {
    boards = await invoke("boards");
  } catch (e) {
    toast(String(e), "error");
    return;
  }
  state.boards = [...boards.builtin, ...boards.favorites];
  renderBoardMenu(boards);
}

function boardItem(b) {
  const label = el("span", { class: "board-label", onclick: () => openBoard(b) }, [
    document.createTextNode(b.label),
    el("span", { class: "fp", text: `#${b.fingerprint}` }),
  ]);
  const children = [label];
  if (!b.builtin) {
    // 公式の板は削除できない（ここには来ない：favorites にしか無い）
    children.push(
      el("button", {
        type: "button",
        class: "board-del",
        title: "お気に入りから削除",
        text: "×",
        onclick: (ev) => {
          ev.stopPropagation();
          removeFavoriteBoard(b);
        },
      }),
    );
  }
  return el("li", { class: state.board?.uri === b.uri ? "active" : "" }, children);
}

async function removeFavoriteBoard(b) {
  const ok = await busy("削除しています…", () => invoke("remove_favorite_board", { uri: b.uri }));
  if (ok === undefined) return;
  if (state.board?.uri === b.uri) {
    state.board = null;
    state.thread = null;
    showBbs("empty");
  }
  await loadBoards();
  toast(`${b.label} をお気に入りから削除しました`);
}

function renderBoardMenu(boards) {
  $("builtin-boards").replaceChildren(...boards.builtin.map(boardItem));
  $("fav-boards").replaceChildren(...boards.favorites.map(boardItem));
  $("fav-empty").hidden = boards.favorites.length > 0;
}

function refreshBoardMenu() {
  const builtin = state.boards.filter((b) => b.builtin);
  const favorites = state.boards.filter((b) => !b.builtin);
  renderBoardMenu({ builtin, favorites });
}

$("btn-join-board").addEventListener("click", () => {
  showBbs("join");
  $("join-uri").focus();
});

$("bbs-join").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const b = await busy("板を登録しています…", () =>
    invoke("join_board", { uri: $("join-uri").value, label: $("join-label").value }),
  );
  if (!b) return;
  $("join-uri").value = "";
  $("join-label").value = "";
  await loadBoards();
  openBoard(b);
});

$("btn-create-board").addEventListener("click", () => {
  showBbs("create");
  $("create-label").focus();
});

$("bbs-create").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const b = await busy("板を作っています…", () => invoke("create_board", { label: $("create-label").value }));
  if (!b) return;
  $("create-label").value = "";
  await loadBoards();
  state.board = b;
  refreshBoardMenu();
  // 作った直後は、渡すための QR と ID を見せる
  shareBoard(b);
});

async function shareBoard(b) {
  $("share-title").textContent = `${b.label} #${b.fingerprint} を共有`;
  $("share-uri").textContent = b.uri;
  $("share-qr").removeAttribute("src");
  showBbs("share");
  try {
    const svg = await invoke("qr_svg", { text: b.uri });
    // SVG はこちらで生成したもの（網由来ではない）。data URL の img として表示する
    $("share-qr").src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
  } catch (e) {
    toast(String(e), "error");
  }
}

$("btn-share-board").addEventListener("click", () => state.board && shareBoard(state.board));
$("btn-share-back").addEventListener("click", () => state.board && openBoard(state.board));
$("btn-copy-board").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("share-uri").textContent);
  toast("コピーしました");
});

// ---------- スレ一覧 ----------

async function openBoard(b) {
  state.board = b;
  state.thread = null;
  refreshBoardMenu();
  $("board-title").textContent = b.label;
  $("board-fp").textContent = `#${b.fingerprint}`;
  $("new-thread-form").hidden = true;
  $("thread-list").replaceChildren();
  $("list-state").textContent = "読み込み中…";
  // 読み込みに失敗しても、板の画面（スレ立て）は出しておく
  showBbs("list");
  const threads = await busy(`${b.label} 板を読み込んでいます…`, () => invoke("bbs_threads", { board: b.uri }));
  if (!threads) {
    $("list-state").textContent = "スレ一覧を読み込めませんでした。「更新」で再試行できます";
    return;
  }
  $("list-state").textContent = threads.length
    ? `スレッド ${threads.length} 本（勢い順）`
    : "まだスレッドがありません。最初のスレッドを立ててみてください";
  $("thread-list").replaceChildren(
    ...threads.map((t) =>
      el("li", {}, [
        el("a", { text: t.title || "(無題)", onclick: () => openThread(t.root_ref) }),
        el("span", { class: "count", text: ` (${t.res_count})` }),
      ]),
    ),
  );
}

$("btn-reload-list").addEventListener("click", () => state.board && openBoard(state.board));

$("btn-new-thread").addEventListener("click", () => {
  $("new-thread-form").hidden = false;
  $("nt-title").focus();
});
$("btn-cancel-thread").addEventListener("click", () => ($("new-thread-form").hidden = true));

$("new-thread-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const view = await busy("スレッドを立てています…", () =>
    invoke("bbs_new_thread", { board: state.board.uri, title: $("nt-title").value, body: $("nt-body").value }),
  );
  if (!view) return;
  $("nt-title").value = "";
  $("nt-body").value = "";
  $("new-thread-form").hidden = true;
  toast("スレッドを立てました（他の人の一覧に出るまで少しかかります）");
  // 網から読み直さず、手元の内容でそのまま開く
  showThread(view);
});

// ---------- スレ本体 ----------

$("back-to-list").addEventListener("click", (ev) => {
  ev.preventDefault();
  openBoard(state.board);
});
$("btn-reload-thread").addEventListener("click", () => state.thread && openThread(state.thread.root_ref));

async function openThread(rootRef) {
  const view = await busy("スレッドを読み込んでいます…", () =>
    invoke("bbs_open_thread", { board: state.board.uri, rootRef }),
  );
  if (!view) return;
  showThread(view);
}

function showThread(view) {
  state.thread = view;
  $("thread-title").textContent = view.title || "(無題)";
  renderPosts(view.posts);
  showBbs("thread");
}

function postHeader(p) {
  return [
    el("span", { class: "no", text: String(p.no), onclick: () => insertAnchor(p.no) }),
    document.createTextNode(" ："),
    el("span", { class: "name", text: p.name }),
    document.createTextNode(`：${bbsTime(p.timestamp)}${p.id ? ` ID:${p.id}` : ""}`),
  ];
}

function postBody(p) {
  if (p.missing) return [document.createTextNode("（このレスは取得できませんでした）")];
  return p.body.map((seg) => {
    if (seg.t === "text") return document.createTextNode(seg.text);
    // アンカー：指す先があればリンク（ホバーで中身、クリックで移動）
    if (seg.no == null) return el("span", { class: "anchor dead", text: ">>?" });
    const a = el("a", { class: "anchor", text: `>>${seg.no}` });
    a.addEventListener("mouseenter", (e) => showPopup(seg.no, e));
    a.addEventListener("mouseleave", hidePopup);
    a.addEventListener("click", () => document.getElementById(`res-${seg.no}`)?.scrollIntoView({ behavior: "smooth" }));
    return a;
  });
}

function renderPosts(posts) {
  const dl = $("posts");
  dl.replaceChildren();
  for (const p of posts) {
    dl.append(el("dt", { id: `res-${p.no}` }, postHeader(p)));
    dl.append(el("dd", { class: p.missing ? "missing" : "" }, postBody(p)));
  }
}

function showPopup(no, e) {
  const p = state.thread?.posts.find((x) => x.no === no);
  if (!p) return;
  const box = $("popup");
  box.replaceChildren(el("div", {}, postHeader(p)), el("div", {}, postBody(p)));
  box.hidden = false;
  box.style.left = `${Math.min(e.clientX + 12, window.innerWidth - 540)}px`;
  box.style.top = `${e.clientY + 14}px`;
}
function hidePopup() {
  $("popup").hidden = true;
}

function insertAnchor(no) {
  const t = $("write-body");
  t.value += `${t.value && !t.value.endsWith("\n") ? "\n" : ""}>>${no}\n`;
  t.focus();
}

$("write-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!state.thread) return;
  const res = await busy("書き込んでいます…", () =>
    invoke("bbs_reply", { board: state.board.uri, ctx: state.thread.reply, body: $("write-body").value }),
  );
  if (!res) return;
  $("write-body").value = "";
  // 網から読み直さず、自分のレスを末尾に足す（他人の新着は「更新」で取り込む）
  state.thread.posts.push(res);
  state.thread.reply.refs.push(res.content_ref);
  renderPosts(state.thread.posts);
  document.getElementById(`res-${res.no}`)?.scrollIntoView({ behavior: "smooth" });
  toast("書き込みました");
});

// ================================================================ トーク（LINE 風）

async function loadFriends() {
  try {
    state.friends = await invoke("friends");
  } catch (e) {
    toast(String(e), "error");
    state.friends = [];
  }
  renderFriendList();
}

function friendName(nodeId) {
  return state.friends.find((f) => f.node_id === nodeId)?.nickname ?? `未登録 ${nodeId.slice(0, 8)}…`;
}

function renderFriendList() {
  const ul = $("friend-list");
  ul.replaceChildren();
  $("friend-empty").hidden = state.friends.length > 0;
  // 最後にやりとりした順（LINE と同じ）
  const last = (id) => state.talks.get(id)?.at(-1);
  const sorted = [...state.friends].sort((a, b) => (last(b.node_id)?.time ?? 0) - (last(a.node_id)?.time ?? 0));
  for (const f of sorted) {
    const m = last(f.node_id);
    const unread = state.unread.get(f.node_id) ?? 0;
    const side = el("div", { class: "friend-side" }, [el("span", { text: m ? hhmm(new Date(m.time)) : "" })]);
    if (unread) side.append(el("span", { class: "badge", text: String(unread) }));
    ul.append(
      el("li", { class: f.node_id === state.active ? "active" : "", onclick: () => openTalk(f.node_id) }, [
        el("div", { class: "avatar", text: [...f.nickname][0] ?? "?" }),
        el("div", { class: "friend-main" }, [
          el("div", { class: "friend-name", text: f.nickname }),
          el("div", { class: "friend-last", text: m ? m.text.replace(/\s+/g, " ") : "" }),
        ]),
        side,
      ]),
    );
  }
  const total = [...state.unread.values()].reduce((a, b) => a + b, 0);
  $("talk-badge").hidden = total === 0;
  $("talk-badge").textContent = String(total);
}

function showTalkPane(pane) {
  $("chat").hidden = pane !== "chat";
  $("add-friend").hidden = pane !== "add";
  $("talk-empty").hidden = pane !== "empty";
}

function openTalk(nodeId) {
  state.active = nodeId;
  state.unread.delete(nodeId);
  $("chat-name").textContent = friendName(nodeId);
  deleteFriendConfirm = null;
  $("btn-delete-friend").textContent = "削除";
  renderBubbles();
  renderFriendList();
  showTalkPane("chat");
  $("chat-text").focus();
}

let deleteFriendConfirm = null;
$("btn-delete-friend").addEventListener("click", async () => {
  const nodeId = state.active;
  if (!nodeId) return;
  // 2 度押しで確認する（ブラウザの confirm は使わない）
  if (deleteFriendConfirm !== nodeId) {
    deleteFriendConfirm = nodeId;
    $("btn-delete-friend").textContent = "本当に削除";
    toast("もう一度押すと削除します。トーク履歴も消え、次回の接続からは受信しなくなります", "warn");
    return;
  }
  deleteFriendConfirm = null;
  $("btn-delete-friend").textContent = "削除";
  const ok = await busy("削除しています…", () => invoke("remove_friend", { nodeId }));
  if (ok === undefined) return;
  const name = friendName(nodeId);
  state.talks.delete(nodeId);
  state.unread.delete(nodeId);
  state.friends = state.friends.filter((f) => f.node_id !== nodeId);
  state.active = null;
  renderFriendList();
  showTalkPane("empty");
  toast(`${name} を削除しました（次回の接続からは受信しません）`);
});

const STATUS_TEXT = {
  sending: "送信中…",
  placed: "送信中…",
  sent: "送信済み",
  failed: "送信失敗",
};

function statusText(m) {
  if (m.status === "delayed") return `送信待ち（匿名化のため約${m.delay}秒）`;
  return STATUS_TEXT[m.status] ?? "";
}

function renderBubbles() {
  const box = $("bubbles");
  box.replaceChildren();
  for (const m of state.talks.get(state.active) ?? []) {
    const meta = el("div", { class: "meta" });
    if (m.mine) {
      const pending = m.status !== "sent" && m.status !== "failed";
      meta.append(el("span", { class: `status ${pending ? "pending" : m.status}`, text: statusText(m) }));
    }
    meta.append(el("span", { text: hhmm(new Date(m.time)) }));
    box.append(el("div", { class: `msg ${m.mine ? "mine" : "theirs"}` }, [el("div", { class: "bubble", text: m.text }), meta]));
  }
  box.scrollTop = box.scrollHeight;
}

function pushTalk(nodeId, msg) {
  if (!state.talks.has(nodeId)) state.talks.set(nodeId, []);
  state.talks.get(nodeId).push(msg);
}

function receiveTalk(nodeId, text) {
  const time = Date.now();
  pushTalk(nodeId, { mine: false, text, time });
  persistTalk(nodeId, false, text, time);
  const viewing = state.active === nodeId && $("view-talk").classList.contains("active");
  if (viewing) renderBubbles();
  else {
    state.unread.set(nodeId, (state.unread.get(nodeId) ?? 0) + 1);
    toast(`${friendName(nodeId)} からトークが届きました`);
  }
  renderFriendList();
}

/** トークの保存先（talks.bin）へ 1 件追記する。失敗しても画面表示は止めない */
async function persistTalk(peer, mine, text, time) {
  try {
    await invoke("record_talk_message", { peer, mine, text, time });
  } catch (e) {
    log(`トーク履歴の保存に失敗しました: ${e}`, "warn");
  }
}

/** 保存済みのトーク履歴を読み込む（接続後、起動時に1回） */
async function loadTalks() {
  let talks;
  try {
    talks = await invoke("talks");
  } catch (e) {
    log(`トーク履歴の読み込みに失敗しました: ${e}`, "warn");
    return;
  }
  for (const [nodeId, list] of Object.entries(talks)) {
    // 送信状態は保存していない。自分の発言は「送信済み」として出す
    state.talks.set(
      nodeId,
      list.map((m) => ({ mine: m.mine, text: m.text, time: m.time, status: m.mine ? "sent" : undefined })),
    );
  }
  renderFriendList();
  if (state.active) renderBubbles();
}

function findByTicket(ticket) {
  for (const list of state.talks.values()) {
    const m = list.find((x) => x.ticket === ticket);
    if (m) return m;
  }
  return null;
}

function updateSendStatus(ticket, status) {
  const m = findByTicket(ticket);
  if (!m || m.status === "failed") return;
  m.status = status.state;
  if (status.state === "delayed") m.delay = status.seconds;
  renderBubbles();
}

$("chat-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const text = $("chat-text").value;
  if (!text.trim() || !state.active) return;
  const to = state.active;
  const ticket = state.nextTicket++;
  const time = Date.now();
  const msg = { mine: true, text, time, ticket, status: "sending" };
  pushTalk(to, msg);
  $("chat-text").value = "";
  renderBubbles();
  renderFriendList();
  persistTalk(to, true, text, time);
  // 送信は待たない（遅延放流で数分かかることがある）。状態は SendStatus で更新される
  invoke("send_talk", { to, text, ticket })
    .then(() => {
      msg.status = "sent";
      renderBubbles();
    })
    .catch((e) => {
      msg.status = "failed";
      renderBubbles();
      toast(String(e), "error");
      log(String(e), "warn");
    });
});

// Enter で送信、Shift+Enter で改行（変換確定の Enter では送らない）
$("chat-text").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
    e.preventDefault();
    $("chat-form").requestSubmit();
  }
});

$("btn-add-friend").addEventListener("click", async () => {
  state.active = null;
  renderFriendList();
  showTalkPane("add");
  try {
    const qr = await invoke("my_qr");
    // SVG はこちらで生成したもの（網由来ではない）。data URL の img として表示する
    $("my-qr").src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(qr.svg)}`;
    $("my-uri").textContent = qr.uri;
  } catch (e) {
    $("my-uri").textContent = String(e);
  }
});

$("btn-copy-uri").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("my-uri").textContent);
  toast("コピーしました");
});

$("add-friend-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = await busy("追加しています…", () =>
    invoke("add_friend", { id: $("friend-id").value, nickname: $("friend-name").value }),
  );
  if (!f) return;
  $("friend-id").value = "";
  $("friend-name").value = "";
  await loadFriends();
  toast(`${f.nickname} を追加しました`);
  openTalk(f.node_id);
});

// ================================================================ 起動

(async () => {
  setConnected(false);
  showBbs("empty");
  showTalkPane("empty");
  const info = await invoke("app_info");
  $("identity-card").hidden = info.has_identity;
  log(`データの保存先: ${info.data_dir}`);
})();
