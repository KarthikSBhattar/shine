// Client-side WebSocket TCP tunnel through the Shine relay chain.
// relay1 is blind to the destination (it only pipes bytes).
// relay2 decrypts the first message to learn the destination.
import { TOKEN_HEADER, TUNNEL_ENC_LEN, TUNNEL_HPKE_INFO } from "../../shared/src/types.ts";
import { hpkeSeal } from "./hpke.ts";

export interface TunnelConfig {
  relay1Url: string;
  relay2HpkePublicKeyBytes: Uint8Array; // relay2's X25519 key (same as OHTTP)
  token?: string;                       // from issuer; sent as ?token= query param
}

const TUNNEL_INFO = new TextEncoder().encode(TUNNEL_HPKE_INFO);

// Opens a WebSocket tunnel through relay1 → relay2 → TCP destination.
//
// Returns a WebSocket where:
//   - Binary messages RECEIVED are raw TCP bytes from the destination
//   - Binary messages SENT are forwarded as raw TCP bytes to the destination
//
// The caller is responsible for handling WebSocket events (onopen, onmessage, onclose, onerror).
// The tunnel is established on the first binary message the caller sends — there is no
// separate handshake; the HPKE-encrypted destination is sent automatically on WebSocket open.
export async function openTunnel(
  config: TunnelConfig,
  destination: { host: string; port: number },
): Promise<WebSocket> {
  // HPKE-encrypt the destination so relay1 stays blind
  const plaintext = new TextEncoder().encode(
    JSON.stringify({ host: destination.host, port: destination.port }),
  );
  const { enc, ciphertext } = await hpkeSeal(
    config.relay2HpkePublicKeyBytes,
    TUNNEL_INFO,
    plaintext,
  );

  // Wire: enc (32 bytes) || ciphertext
  const firstMsg = new Uint8Array(enc.length + ciphertext.length);
  firstMsg.set(enc);
  firstMsg.set(ciphertext, enc.length);

  // Browsers can't send custom headers on WebSocket upgrades.
  // Pass the token as a query param; relay1 reads it as a fallback.
  const wsUrl = new URL(
    config.relay1Url.replace(/^http/, "ws") + "/tunnel",
  );
  if (config.token) wsUrl.searchParams.set("token", config.token);

  const ws = new WebSocket(wsUrl.toString());
  ws.binaryType = "arraybuffer";

  // Send the encrypted destination as the first binary message
  ws.addEventListener("open", () => {
    ws.send(firstMsg.buffer as ArrayBuffer);
  }, { once: true });

  return ws;
}
