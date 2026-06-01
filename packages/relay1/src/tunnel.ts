// WebSocket TCP tunnel — relay1 blind passthrough.
// relay1 never decrypts the first message (HPKE-encrypted destination).
// It only HMAC-signs the upgrade request to relay2 for authentication.
import { hmacSign } from "../../shared/src/crypto.ts";
import {
  RELAY2_HMAC_HEADER,
  RELAY2_TIMESTAMP_HEADER,
} from "../../shared/src/types.ts";

export async function handleTunnel(
  request: Request,
  relay2BaseUrl: string,
  hmacSecret: string,
): Promise<Response> {
  if (request.headers.get("Upgrade") !== "websocket") {
    return new Response("Expected WebSocket upgrade", { status: 426 });
  }

  // HMAC over empty body — just authenticates the relay1→relay2 handshake
  const timestamp = Date.now().toString();
  const hmac = await hmacSign(hmacSecret, timestamp, new Uint8Array(0));

  const relay2WsUrl = relay2BaseUrl
    .replace(/^https:\/\//, "wss://")
    .replace(/^http:\/\//, "ws://") + "/tunnel";

  // Open WebSocket to relay2 with HMAC auth headers
  const relay2Resp = await fetch(relay2WsUrl, {
    headers: {
      "Upgrade":                "websocket",
      "Connection":             "Upgrade",
      [RELAY2_HMAC_HEADER]:     hmac,
      [RELAY2_TIMESTAMP_HEADER]: timestamp,
    },
  });

  if (relay2Resp.status !== 101 || !relay2Resp.webSocket) {
    return new Response("relay2 WebSocket upgrade failed", { status: 502 });
  }
  const relay2Ws = relay2Resp.webSocket;
  relay2Ws.accept();

  // Create the client-facing WebSocket pair
  const [client, server] = Object.values(new WebSocketPair()) as [WebSocket, WebSocket];
  server.accept();

  // Blind pipe: relay1 forwards raw bytes without reading them
  server.addEventListener("message", (ev) => {
    relay2Ws.send(ev.data as string | ArrayBuffer);
  });
  relay2Ws.addEventListener("message", (ev) => {
    server.send(ev.data as string | ArrayBuffer);
  });
  server.addEventListener("close", (ev) => {
    relay2Ws.close((ev as CloseEvent).code, (ev as CloseEvent).reason);
  });
  relay2Ws.addEventListener("close", (ev) => {
    server.close((ev as CloseEvent).code, (ev as CloseEvent).reason);
  });
  server.addEventListener("error",    () => { try { relay2Ws.close(); } catch {} });
  relay2Ws.addEventListener("error", () => { try { server.close(); } catch {} });

  return new Response(null, { status: 101, webSocket: client });
}
