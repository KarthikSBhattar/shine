import { asBufferSource, b64uDecode } from "../../shared/src/crypto.ts";
import { BLIND_TOKEN_PREFIX, BLIND_SIG_BYTES, BLIND_NONCE_BYTES } from "../../shared/src/types.ts";

// relay1 verifies blind tokens using only Web Crypto RSA-PSS — no BigInt needed.
// The issuer's blind signing produces a signature that satisfies standard RSA-PSS verify.

let _issuerPubKey: CryptoKey | null = null;

export async function fetchAndCacheIssuerPubKey(issuerUrl: string): Promise<void> {
  const resp = await fetch(`${issuerUrl}/issuer-key`);
  if (!resp.ok) throw new Error(`Failed to fetch issuer key: ${resp.status}`);
  const jwk = await resp.json() as JsonWebKey;
  _issuerPubKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["verify"],
  );
}

export async function getIssuerPubKey(issuerUrl: string): Promise<CryptoKey> {
  if (!_issuerPubKey) await fetchAndCacheIssuerPubKey(issuerUrl);
  return _issuerPubKey!;
}

// Verifies a blind token.
// Token format: "bs1." + base64url(nonce_32) + "." + base64url(sig_256)
export async function verifyBlindToken(tokenHeader: string, pubKey: CryptoKey): Promise<void> {
  if (!tokenHeader.startsWith(BLIND_TOKEN_PREFIX)) {
    throw new Error("Not a blind token");
  }
  const rest = tokenHeader.slice(BLIND_TOKEN_PREFIX.length);
  const lastDot = rest.lastIndexOf(".");
  if (lastDot < 1) throw new Error("Malformed blind token");

  const nonce = b64uDecode(rest.slice(0, lastDot));
  const sig   = b64uDecode(rest.slice(lastDot + 1));

  if (nonce.length !== BLIND_NONCE_BYTES) throw new Error("Invalid nonce length");
  if (sig.length !== BLIND_SIG_BYTES)     throw new Error("Invalid signature length");

  // Web Crypto RSA-PSS verify: internally computes sig^e mod n and checks PSS structure.
  // saltLength must match the sLen used in EMSA-PSS-ENCODE (32 for SHA-256).
  const valid = await crypto.subtle.verify(
    { name: "RSA-PSS", saltLength: 32 },
    pubKey,
    asBufferSource(sig),
    asBufferSource(nonce),
  );
  if (!valid) throw new Error("Blind token signature invalid");
}
