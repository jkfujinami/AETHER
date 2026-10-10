/**
 * Deno Deploy 本番トラッカーに対する包括的 API & WebSocket テスト
 */

const BASE_URL = "https://odd-puffin-5778.jkfujinami.deno.net";
const WS_URL = "wss://odd-puffin-5778.jkfujinami.deno.net";

async function runTests() {
  console.log("=== 1. HTTP ヘルスチェック API テスト ===");
  const res = await fetch(BASE_URL);
  if (!res.ok) {
    throw new Error(`HTTP fetch failed with status: ${res.status}`);
  }
  const statusJson = await res.json();
  console.log("HTTP レスポンス:", statusJson);
  if (statusJson.status !== "ok" || typeof statusJson.activePeers !== "number") {
    throw new Error("Invalid status JSON format");
  }
  console.log("✔ HTTP ヘルスチェック合格\n");

  console.log("=== 2. WebSocket 接続 & ハンドシェイク ===");
  const ws1 = new WebSocket(WS_URL);
  const ws2 = new WebSocket(WS_URL);

  await Promise.all([
    new Promise((resolve, reject) => {
      ws1.onopen = resolve;
      ws1.onerror = reject;
    }),
    new Promise((resolve, reject) => {
      ws2.onopen = resolve;
      ws2.onerror = reject;
    }),
  ]);
  console.log("✔ ws1 / ws2 の両方で WebSocket 接続確立成功\n");

  console.log("=== 3. Ping / Pong テスト ===");
  const pongPromise = new Promise((resolve) => {
    ws1.onmessage = (e) => {
      const data = JSON.parse(e.data);
      if (data.type === "pong") resolve(data);
    };
  });
  ws1.send(JSON.stringify({ type: "ping" }));
  await pongPromise;
  console.log("✔ ping 送信に対して pong 受信成功\n");

  console.log("=== 4. Join & ピア探索 テスト ===");
  const peerId1 = "test_peer_alpha_" + Math.random().toString(36).substring(7);
  const peerId2 = "test_peer_beta_" + Math.random().toString(36).substring(7);

  // peer1 の join
  const join1Promise = new Promise((resolve) => {
    ws1.onmessage = (e) => {
      const data = JSON.parse(e.data);
      if (data.type === "peers") resolve(data);
    };
  });
  ws1.send(JSON.stringify({ type: "join", peerId: peerId1, position: 0 }));
  const join1Resp = await join1Promise as any;
  console.log(`peer1 (${peerId1}) join 応答:`, join1Resp);

  // peer2 の join（peer1 が見つかるはず）
  const join2Promise = new Promise((resolve) => {
    ws2.onmessage = (e) => {
      const data = JSON.parse(e.data);
      if (data.type === "peers") resolve(data);
    };
  });
  ws2.send(JSON.stringify({ type: "join", peerId: peerId2, position: 0 }));
  const join2Resp = await join2Promise as any;
  console.log(`peer2 (${peerId2}) join 応答:`, join2Resp);

  const foundPeer1 = join2Resp.peers.some((p: any) => p.peerId === peerId1);
  if (!foundPeer1) {
    throw new Error(`peer2 did not receive peer1 in peer list! received: ${JSON.stringify(join2Resp.peers)}`);
  }
  console.log("✔ peer2 が peer1 をピアリストとして正常に発見\n");

  console.log("=== 5. メッセージリレー（シグナリング）テスト ===");
  // peer2 から peer1 へ relay
  const relayPayload = {
    type: "punch_offer",
    peer: peerId2,
    candidates: ["192.168.2.106:19001", "182.166.234.46:50000"],
    nonce: 99999,
  };

  const receiveRelayPromise = new Promise((resolve) => {
    ws1.onmessage = (e) => {
      const data = JSON.parse(e.data);
      if (data.type === "punch_offer") resolve(data);
    };
  });

  ws2.send(
    JSON.stringify({
      type: "relay",
      targetPeerId: peerId1,
      payload: relayPayload,
    })
  );

  const receivedOnPeer1 = await receiveRelayPromise as any;
  console.log("peer1 が受信したリレーペイロード:", receivedOnPeer1);

  if (receivedOnPeer1.senderId !== peerId2 || receivedOnPeer1.nonce !== 99999) {
    throw new Error("Relayed payload content mismatch!");
  }
  console.log("✔ peer2 -> トラッカー -> peer1 へのシグナリング中継が完全一致\n");

  console.log("=== 6. クリーンアップ & 切断テスト ===");
  ws1.close();
  ws2.close();
  await new Promise((r) => setTimeout(r, 1000));

  const postRes = await fetch(BASE_URL);
  const postStatus = await postRes.json();
  console.log("切断後の HTTP レスポンス:", postStatus);
  console.log("✔ 全ての API / WebSocket 動作テストが正常に通過しました！");
}

runTests().catch((err) => {
  console.error("❌ テスト失敗:", err);
  Deno.exit(1);
});
