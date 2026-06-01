import { asBufferSource, b64uEncode, b64uDecode } from "../../../packages/shared/src/crypto.ts";

// Token format (x-shine-token header):
//   base64url(nonce + "." + exp_decimal) + "." + base64url(HMAC-SHA256(secret, nonce + "." + exp_decimal))
//
// Privacy guarantee: the issuer sees the auth credential at issuance time; relay1 sees only the
// opaque token at use time. Since the issuer and relay1 do not share logs, no one can join them.
// This is weaker than RSA blind signatures (where even the issuer can't link issuance to use),
// but avoids the need for RSA blind arithmetic not available in Web Crypto.

export async function issueToken(secret: string, ttlSeconds: number): Promise<string> {
  const nonce  = b64uEncode(crypto.getRandomValues(new Uint8Array(16)));
  const exp    = Math.floor(Date.now() / 1000) + ttlSeconds;
  const payload = `${nonce}.${exp}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, asBufferSource(new TextEncoder().encode(payload))),
  );

  return `${b64uEncode(new TextEncoder().encode(payload))}.${b64uEncode(sig)}`;
}

export async function verifyToken(secret: string, tokenHeader: string): Promise<void> {
  const lastDot = tokenHeader.lastIndexOf(".");
  if (lastDot < 1) throw new Error("Malformed token");
  const payloadB64 = tokenHeader.slice(0, lastDot);
  const sigB64     = tokenHeader.slice(lastDot + 1);
  const payloadStr = new TextDecoder().decode(b64uDecode(payloadB64));
  const sigBytes   = b64uDecode(sigB64);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "HMAC", key, asBufferSource(sigBytes), new TextEncoder().encode(payloadStr),
  );
  if (!valid) throw new Error("Token signature invalid");

  const dotIdx = payloadStr.indexOf(".");
  const exp = parseInt(payloadStr.slice(dotIdx + 1), 10);
  if (isNaN(exp) || exp * 1000 < Date.now()) throw new Error("Token expired");
}
