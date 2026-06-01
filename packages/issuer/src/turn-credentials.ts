// TURN long-term credential generation (RFC 8489 §9.2 / coturn `use-auth-secret` mode).
//
// coturn verifies credentials as:
//   key      = HMAC-SHA1(TURN_SHARED_SECRET, username)
//   username = "<expiry_unix_seconds>:<identifier>"
//
// Web Crypto supports HMAC-SHA1 even though SHA-1 hashing is deprecated
// (HMAC-SHA1 for authentication is still considered secure).

export interface TurnCredentials {
  username: string;
  password: string;  // base64 (NOT base64url — coturn expects standard base64)
  urls: string[];
  ttl: number;       // seconds until expiry
}

export async function generateTurnCredentials(
  sharedSecret: string,
  turnHost: string,
  ttlSeconds: number,
  identifier: string,
): Promise<TurnCredentials> {
  const expiry   = Math.floor(Date.now() / 1000) + ttlSeconds;
  const username = `${expiry}:${identifier}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(sharedSecret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(username));

  // Standard base64 (not URL-safe) — what coturn expects
  let bin = "";
  for (const b of new Uint8Array(sigBuf)) bin += String.fromCharCode(b);
  const password = btoa(bin);

  return {
    username,
    password,
    urls: [
      `turns:${turnHost}:443`,               // TURN over TLS (preferred)
      `turn:${turnHost}:3478`,               // TURN over UDP/TCP (fallback)
      `turn:${turnHost}:3478?transport=tcp`, // TURN over TCP explicit
    ],
    ttl: ttlSeconds,
  };
}
