import { asBodyInit, hmacSign } from "../../shared/src/crypto.ts";
import { RELAY2_HMAC_HEADER, RELAY2_TIMESTAMP_HEADER } from "../../shared/src/types.ts";

export async function forwardToRelay2(
  innerCiphertext: Uint8Array,
  relay2BaseUrl: string,
  hmacSecret: string,
): Promise<Response> {
  const timestamp = Date.now().toString();
  const hmac = await hmacSign(hmacSecret, timestamp, innerCiphertext);

  const upstream = await fetch(`${relay2BaseUrl}/relay`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      [RELAY2_HMAC_HEADER]: hmac,
      [RELAY2_TIMESTAMP_HEADER]: timestamp,
    },
    body: asBodyInit(innerCiphertext),
  });

  // Relay the encrypted response as-is — relay1 cannot read it
  return new Response(upstream.body, {
    status: upstream.status,
    headers: {
      "Content-Type":
        upstream.headers.get("Content-Type") ?? "application/octet-stream",
    },
  });
}
