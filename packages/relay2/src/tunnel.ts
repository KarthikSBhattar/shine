/// <reference lib="deno.ns" />

// WebSocket-to-TCP bridge — relay2 decrypts the destination and proxies TCP.
// relay2 knows the destination but never the user's IP (that stays at relay1).
import { hpkeOpen } from "./hpke.ts";
import { verifyRelayAuth } from "./auth.ts";
import {
  RELAY2_HMAC_HEADER,
  RELAY2_TIMESTAMP_HEADER,
  TUNNEL_ENC_LEN,
  TUNNEL_HPKE_INFO,
} from "../../shared/src/types.ts";
import { validateTcpDestination } from "./validate.ts";

const TUNNEL_INFO = new TextEncoder().encode(TUNNEL_HPKE_INFO);

export async function handleTunnel(
  request: Request,
  hmacSecret: string,
  hpkePrivJwk: JsonWebKey,
  hpkePubBytes: Uint8Array,
): Promise<Response> {
  // Verify HMAC auth over empty body before upgrading
  const timestamp = request.headers.get(RELAY2_TIMESTAMP_HEADER);
  const hmac = request.headers.get(RELAY2_HMAC_HEADER);
  if (!timestamp || !hmac) return new Response("Unauthorized", { status: 401 });

  try {
    await verifyRelayAuth(hmacSecret, timestamp, hmac, new Uint8Array(0));
  } catch {
    return new Response("Unauthorized", { status: 401 });
  }

  if (request.headers.get("upgrade") !== "websocket") {
    return new Response("Expected WebSocket upgrade", { status: 426 });
  }

  const { socket, response } = Deno.upgradeWebSocket(request);

  let tcpConn: Deno.TcpConn | null = null;

  socket.onopen = () => {};

  socket.onmessage = async (ev: MessageEvent) => {
    const data: Uint8Array = ev.data instanceof ArrayBuffer
      ? new Uint8Array(ev.data)
      : typeof ev.data === "string"
      ? new TextEncoder().encode(ev.data)
      : ev.data;

    if (tcpConn === null) {
      // First message: HPKE-encrypted {host, port}
      // Wire: enc (32 bytes) || ciphertext
      if (data.length <= TUNNEL_ENC_LEN) {
        socket.close(4400, "First message too short");
        return;
      }

      const enc = data.slice(0, TUNNEL_ENC_LEN);
      const ciphertext = data.slice(TUNNEL_ENC_LEN);

      let dest: { host: string; port: number };
      try {
        const { plaintext } = await hpkeOpen(
          hpkePrivJwk,
          hpkePubBytes,
          enc,
          TUNNEL_INFO,
          ciphertext,
        );
        dest = JSON.parse(new TextDecoder().decode(plaintext)) as {
          host: string;
          port: number;
        };
        validateTcpDestination(dest.host, dest.port);
      } catch {
        socket.close(4400, "Bad destination");
        return;
      }

      try {
        tcpConn = await Deno.connect({ hostname: dest.host, port: dest.port });
      } catch {
        socket.close(4502, "TCP connect failed");
        return;
      }

      // Pump TCP → WebSocket in the background
      (async () => {
        const buf = new Uint8Array(16384);
        try {
          for (;;) {
            const n = await tcpConn!.read(buf);
            if (n === null) {
              socket.close(1000, "TCP closed");
              break;
            }
            socket.send(buf.slice(0, n).buffer as ArrayBuffer);
          }
        } catch {
          try {
            socket.close(1011, "TCP read error");
          } catch {}
        }
      })();
    } else {
      // Subsequent messages: raw bytes forwarded to TCP
      try {
        let off = 0;
        while (off < data.length) {
          const n = await tcpConn.write(data.subarray(off));
          off += n;
        }
      } catch {
        try {
          socket.close(1011, "TCP write error");
        } catch {}
        tcpConn?.close();
        tcpConn = null;
      }
    }
  };

  socket.onclose = () => {
    try {
      tcpConn?.close();
    } catch {}
    tcpConn = null;
  };

  socket.onerror = () => {
    try {
      tcpConn?.close();
    } catch {}
    tcpConn = null;
  };

  return response;
}
