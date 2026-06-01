import { asBufferSource, b64uDecode } from "../../shared/src/crypto.ts";

// Token format (x-shine-token header):
//   base64url(nonce + "." + exp_decimal) + "." + base64url(HMAC-SHA256(secret, nonce + "." + exp_decimal))
//
// relay1 holds the same ISSUER_SECRET as the issuer — both are CF Workers secrets.
// The token does not contain user identity; the issuer enforces rate limits at issuance time.

export async function verifyClientToken(tokenHeader: string, issuerSecret: string): Promise<void> {
  const lastDot = tokenHeader.lastIndexOf(".");
  if (lastDot < 1) throw new Error("Malformed token");

  const payloadB64 = tokenHeader.slice(0, lastDot);
  const sigB64     = tokenHeader.slice(lastDot + 1);

  const payloadStr = new TextDecoder().decode(b64uDecode(payloadB64));
  // payloadStr = "nonce.exp_decimal"
  const sigBytes   = b64uDecode(sigB64);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(issuerSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );

  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    asBufferSource(sigBytes),
    new TextEncoder().encode(payloadStr),
  );
  if (!valid) throw new Error("Token signature invalid");

  const dotIdx = payloadStr.indexOf(".");
  if (dotIdx < 0) throw new Error("Malformed token payload");
  const exp = parseInt(payloadStr.slice(dotIdx + 1), 10);
  if (isNaN(exp) || exp * 1000 < Date.now()) throw new Error("Token expired");
}
