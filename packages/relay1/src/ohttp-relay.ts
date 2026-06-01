// OHTTP relay passthrough (RFC 9458 §3.1).
// relay1 is intentionally blind to OHTTP content — no HPKE occurs here.
// It authenticates the client token, HMAC-signs the body for relay2, and forwards.
import { asBodyInit, hmacSign } from "../../shared/src/crypto.ts";
import {
  RELAY2_HMAC_HEADER,
  RELAY2_TIMESTAMP_HEADER,
  CT_OHTTP_REQ,
  CT_OHTTP_RES,
  MAX_OUTER_BODY_BYTES,
} from "../../shared/src/types.ts";

export async function handleOhttpRelay(
  body: Uint8Array,
  relay2BaseUrl: string,
  hmacSecret: string,
): Promise<Response> {
  if (body.length > MAX_OUTER_BODY_BYTES) throw new Error("OHTTP request too large");

  const timestamp = Date.now().toString();
  const hmac = await hmacSign(hmacSecret, timestamp, body);

  const upstream = await fetch(`${relay2BaseUrl}/ohttp`, {
    method: "POST",
    headers: {
      "Content-Type": CT_OHTTP_REQ,
      [RELAY2_HMAC_HEADER]: hmac,
      [RELAY2_TIMESTAMP_HEADER]: timestamp,
    },
    body: asBodyInit(body),
  });

  return new Response(upstream.body, {
    status: upstream.status,
    headers: {
      "Content-Type": upstream.headers.get("Content-Type") ?? CT_OHTTP_RES,
    },
  });
}
