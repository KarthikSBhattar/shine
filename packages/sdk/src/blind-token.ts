// Client-side RSA blind signature flow (RFC 9474).
// The issuer never sees the plaintext nonce — only the blinded message.
// After unblinding, the final signature is verifiable with standard RSA-PSS.
import { b64uDecode, b64uEncode } from "../../shared/src/crypto.ts";
import {
  os2ip,
  rsaBlind,
  rsaUnblind,
} from "../../shared/src/rsa-blind.ts";
import {
  BLIND_TOKEN_PREFIX,
  BLIND_SIG_BYTES,
  BLIND_NONCE_BYTES,
} from "../../shared/src/types.ts";

export interface BlindTokenConfig {
  issuerUrl: string;       // e.g. "https://shine-issuer.workers.dev"
  authCredential: string;  // Bearer token for POST /blind-sign
}

// Cached per SDK instance — the issuer's public key changes infrequently
let _cachedKey: { n: bigint; e: bigint } | null = null;

export async function fetchIssuerPublicKey(config: BlindTokenConfig): Promise<void> {
  const resp = await fetch(`${config.issuerUrl}/issuer-key`);
  if (!resp.ok) throw new Error(`Issuer key fetch failed: ${resp.status}`);
  const jwk = await resp.json() as JsonWebKey;
  if (!jwk.n || !jwk.e) throw new Error("Invalid issuer JWK");

  const dec = (field: string): bigint => {
    const b64 = field.replace(/-/g, "+").replace(/_/g, "/");
    const pad = (4 - (b64.length % 4)) % 4;
    const bin = atob(b64 + "=".repeat(pad));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return os2ip(bytes);
  };

  _cachedKey = { n: dec(jwk.n), e: dec(jwk.e) };
}

// Full blind token issuance:
// 1. PSS-encodes a fresh random nonce
// 2. Blinds the encoded message with a random factor r
// 3. Sends the blind message to the issuer for signing
// 4. Unblinds the response to get a standard RSA-PSS signature over the nonce
// 5. Returns a token string for the x-shine-token header
export async function obtainBlindToken(config: BlindTokenConfig): Promise<string> {
  if (!_cachedKey) await fetchIssuerPublicKey(config);
  const { n, e } = _cachedKey!;

  const nonce = crypto.getRandomValues(new Uint8Array(BLIND_NONCE_BYTES));

  // rsaBlind: PSS-encodes nonce, then blinds with random r
  const { blindMsg, r } = await rsaBlind(nonce, e, n);

  const resp = await fetch(`${config.issuerUrl}/blind-sign`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${config.authCredential}`,
    },
    body: JSON.stringify({ blind_msg: b64uEncode(blindMsg) }),
  });
  if (!resp.ok) throw new Error(`Blind sign failed: ${resp.status}`);

  const body = await resp.json() as { blind_sig: string };
  const blindSig = b64uDecode(body.blind_sig);
  if (blindSig.length !== BLIND_SIG_BYTES) throw new Error("Invalid blind_sig length");

  // Unblind: sig = blind_sig * r^{-1} mod n
  // The resulting sig passes Web Crypto RSA-PSS verify over nonce
  const sig = rsaUnblind(blindSig, r, n);

  return BLIND_TOKEN_PREFIX + b64uEncode(nonce) + "." + b64uEncode(sig);
}

export interface BlindTokenParts {
  nonce: Uint8Array;
  sig: Uint8Array;
}

export function parseBlindToken(tokenHeader: string): BlindTokenParts {
  if (!tokenHeader.startsWith(BLIND_TOKEN_PREFIX)) {
    throw new Error("Not a blind token");
  }
  const rest = tokenHeader.slice(BLIND_TOKEN_PREFIX.length);
  const lastDot = rest.lastIndexOf(".");
  if (lastDot < 1) throw new Error("Malformed blind token");
  return {
    nonce: b64uDecode(rest.slice(0, lastDot)),
    sig:   b64uDecode(rest.slice(lastDot + 1)),
  };
}
