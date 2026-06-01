export const SHINE_VERSION = 1 as const;
export const PADDING_BLOCK_SIZE = 8192;

// Replay window: nonces are not stored (stateless design), so timestamp is the
// only replay guard. 15 s is narrow enough to limit damage while allowing for
// reasonable clock skew across CDN PoPs.
export const MAX_TIMESTAMP_SKEW_MS = 15_000;

// relay1 receives outer-encrypted payload; outer JSON wraps base64url(inner ciphertext)
// so the outer body is ~4/3× larger than the inner. 4 MB gives ~2 MB effective request body.
export const MAX_OUTER_BODY_BYTES = 4 * 1024 * 1024;
// relay2 receives the raw inner ciphertext binary (no extra base64 wrapper).
export const MAX_INNER_BODY_BYTES = 2 * 1024 * 1024;
export const MAX_RESPONSE_BODY_BYTES = 10 * 1024 * 1024;
export const MAX_DESTINATION_URL_LENGTH = 2048;
export const MAX_REDIRECTS = 10;

export const ALLOWED_HTTP_METHODS: ReadonlySet<string> = new Set([
  "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
]);

// ── relay1 ↔ relay2 authentication ───────────────────────────────────────────
export const RELAY2_HMAC_HEADER      = "x-shine-hmac";
export const RELAY2_TIMESTAMP_HEADER = "x-shine-ts";
export const TOKEN_HEADER            = "x-shine-token";

// ── OHTTP (RFC 9458) ──────────────────────────────────────────────────────────
// Suite: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM
export const OHTTP_KEY_ID  = 0x01;
export const OHTTP_KEM_ID  = 0x0020; // DHKEM(X25519, HKDF-SHA256)
export const OHTTP_KDF_ID  = 0x0001; // HKDF-SHA256
export const OHTTP_AEAD_ID = 0x0002; // AES-256-GCM
// Nk=32 (key bytes), Nn=12 (nonce bytes), Nt=16 (tag bytes)
// enc size for X25519 = 32 bytes
export const OHTTP_ENC_LEN          = 32;
export const OHTTP_RESPONSE_NONCE_LEN = 32; // max(Nk=32, Nn=12) = 32

// OHTTP content types (RFC 9458 §6)
export const CT_OHTTP_REQ = "message/ohttp-req";
export const CT_OHTTP_RES = "message/ohttp-res";

// ── ODoH (RFC 9230) ───────────────────────────────────────────────────────────
export const CT_ODOH = "application/oblivious-dns-message";
export const CT_DNS  = "application/dns-message";
export const MAX_DNS_MESSAGE_BYTES = 65535;
export const ODOH_QUERY_TYPE    = 0x01;
export const ODOH_RESPONSE_TYPE = 0x02;

// ── Blind token ───────────────────────────────────────────────────────────────
export const BLIND_SIG_BYTES = 256;     // RSA-2048 signature size
export const BLIND_NONCE_BYTES = 32;    // token nonce size
export const BLIND_TOKEN_PREFIX = "bs1."; // wire format discriminant

// ── TCP tunnel ────────────────────────────────────────────────────────────────
// First WebSocket message wire format: enc (32 bytes) || HPKE ciphertext
export const TUNNEL_ENC_LEN = 32;                              // X25519 enc size
export const TUNNEL_HPKE_INFO = "shine-tunnel-v1\0";           // HPKE domain separator
export const TUNNEL_MAX_DEST_HOST_LENGTH = 253;
// Ports blocked to prevent relay abuse (email, RPC, SMB, RDP, chargen)
export const TUNNEL_BLOCKED_PORTS: ReadonlySet<number> = new Set([
  11, 19, 25, 135, 137, 138, 139, 445, 465, 587, 1080, 1081, 3389,
]);

// ── Legacy ECIES protocol (kept for backward compat) ─────────────────────────
export interface OuterEnvelope {
  version: typeof SHINE_VERSION;
  relay2Url: string;
  innerCiphertext: string;
  nonce: string;
  timestamp: number;
}

export interface InnerEnvelope {
  destination: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
  responseKey: string;
  nonce: string;
  timestamp: number;
}

export interface EncryptedResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  iv: string;
}
