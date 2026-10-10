/**
 * AETHER Signaling Tracker (Deno Deploy / Deno 2 compatible)
 *
 * WebRTC (aether-web-lite) および QUIC/STUN (AETHER Core) の両方に対応した
 * エッジシグナリングサーバー。
 */

interface PeerSession {
  peerId: string;
  position: number;
  zones: number[];
  socket: WebSocket;
  lastActive: number;
  isSeed: boolean;
  isCache: boolean;
}

class SessionManager {
  private sessions = new Map<string, PeerSession>();
  private socketToPeerId = new Map<WebSocket, string>();
  private cleanupTimer: number;

  constructor() {
    this.cleanupTimer = setInterval(() => this.cleanupInactive(), 60_000);
  }

  public register(
    socket: WebSocket,
    peerId: string,
    position: number,
    zones: number[] = [],
    isSeed: boolean = false,
    isCache: boolean = false
  ): void {
    // 既存セッションが存在する場合は切断して上書き
    const existing = this.sessions.get(peerId);
    if (existing && existing.socket !== socket) {
      try {
        existing.socket.close(1000, "Replaced by new connection");
      } catch (_) {}
    }

    this.sessions.set(peerId, {
      peerId,
      position,
      zones,
      socket,
      lastActive: Date.now(),
      isSeed,
      isCache,
    });
    this.socketToPeerId.set(socket, peerId);

    console.log(`[Tracker] Registered ${isSeed ? "Seed" : (isCache ? "Cache" : "Peer")}: ${peerId}`);
  }

  public unregisterBySocket(socket: WebSocket): void {
    const peerId = this.socketToPeerId.get(socket);
    if (peerId) {
      this.socketToPeerId.delete(socket);
      this.sessions.delete(peerId);
      console.log(`[Tracker] Unregistered: ${peerId}`);
    }
  }

  public getSession(peerId: string): PeerSession | undefined {
    return this.sessions.get(peerId);
  }

  public getPeerId(socket: WebSocket): string | undefined {
    return this.socketToPeerId.get(socket);
  }

  public getRandomPeers(excludeId: string, count: number = 8) {
    const all = Array.from(this.sessions.values()).filter((s) => s.peerId !== excludeId);
    // Fisher-Yates shuffle
    for (let i = all.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [all[i], all[j]] = [all[j], all[i]];
    }
    return all.slice(0, count).map((s) => ({
      peerId: s.peerId,
      position: s.position,
      zones: s.zones,
    }));
  }

  public getSeedCount(): number {
    let count = 0;
    for (const s of this.sessions.values()) {
      if (s.isSeed) count++;
    }
    return count;
  }

  public getActiveCount(): number {
    return this.sessions.size;
  }

  public touch(socket: WebSocket): void {
    const peerId = this.socketToPeerId.get(socket);
    if (peerId) {
      const session = this.sessions.get(peerId);
      if (session) session.lastActive = Date.now();
    }
  }

  private cleanupInactive(): void {
    const now = Date.now();
    for (const [peerId, session] of this.sessions.entries()) {
      // 2分間パケットがなければタイムアウト切断
      if (now - session.lastActive > 120_000) {
        try {
          session.socket.close(1000, "Ping timeout");
        } catch (_) {}
        this.socketToPeerId.delete(session.socket);
        this.sessions.delete(peerId);
        console.log(`[Tracker] Timed out: ${peerId}`);
      }
    }
  }
}

const manager = new SessionManager();

function handleWebSocket(socket: WebSocket) {
  socket.onopen = () => {
    // 接続開始
  };

  socket.onmessage = (event) => {
    manager.touch(socket);
    try {
      const raw = typeof event.data === "string" ? event.data : new TextDecoder().decode(event.data);
      const data = JSON.parse(raw);

      if (data.type === "ping") {
        socket.send(JSON.stringify({ type: "pong" }));
        return;
      }

      if (data.type === "join") {
        const { peerId, position = 0, zones = [], isSeed = false, isCache = false } = data;
        if (typeof peerId !== "string") {
          socket.send(JSON.stringify({ type: "error", message: "Invalid peerId" }));
          return;
        }

        if (isSeed && manager.getSeedCount() >= 10) {
          socket.send(JSON.stringify({ type: "error", message: "Seed limit reached" }));
          return;
        }

        manager.register(socket, peerId, position, zones, isSeed, isCache);

        const peers = manager.getRandomPeers(peerId, 8);
        socket.send(JSON.stringify({ type: "peers", peers }));
        return;
      }

      if (data.type === "relay") {
        const senderId = manager.getPeerId(socket);
        if (!senderId) {
          socket.send(JSON.stringify({ type: "error", message: "Join required before relay" }));
          return;
        }

        const { targetPeerId, payload } = data;
        if (typeof targetPeerId !== "string" || !payload) {
          socket.send(JSON.stringify({ type: "error", message: "Invalid relay format" }));
          return;
        }

        const target = manager.getSession(targetPeerId);
        if (target && target.socket.readyState === WebSocket.OPEN) {
          const forwarded = {
            ...payload,
            senderId,
            from: senderId,
          };
          target.socket.send(JSON.stringify(forwarded));
        } else {
          socket.send(JSON.stringify({ type: "error", message: `Peer ${targetPeerId} not found` }));
        }
        return;
      }
    } catch (_) {
      socket.send(JSON.stringify({ type: "error", message: "JSON parse failed" }));
    }
  };

  socket.onclose = () => {
    manager.unregisterBySocket(socket);
  };

  socket.onerror = (err) => {
    console.error("[Tracker] Socket error:", err);
    manager.unregisterBySocket(socket);
  };
}

Deno.serve((req: Request) => {
  if (req.headers.get("upgrade") === "websocket") {
    const { socket, response } = Deno.upgradeWebSocket(req);
    handleWebSocket(socket);
    return response;
  }

  // ヘルスチェック用 HTTP エンドポイント
  return new Response(
    JSON.stringify(
      {
        status: "ok",
        service: "AETHER Signaling Tracker",
        activePeers: manager.getActiveCount(),
        seeds: manager.getSeedCount(),
      },
      null,
      2
    ),
    {
      headers: { "content-type": "application/json; charset=utf-8" },
    }
  );
});
