import { hmacVerify } from "../../shared/src/crypto.ts";
import { MAX_TIMESTAMP_SKEW_MS } from "../../shared/src/types.ts";

export async function verifyRelayAuth(
  secret: string,
  timestamp: string,
  providedHmac: string,
  body: Uint8Array,
): Promise<void> {
  // Validate timestamp before the HMAC check — stale-request rejection is not secret
  const ts = parseInt(timestamp, 10);
  if (isNaN(ts) || Math.abs(Date.now() - ts) > MAX_TIMESTAMP_SKEW_MS) {
    throw new Error("Timestamp invalid or expired");
  }
  // crypto.subtle.verify is constant-time — safe against timing attacks
  await hmacVerify(secret, timestamp, providedHmac, body);
}
