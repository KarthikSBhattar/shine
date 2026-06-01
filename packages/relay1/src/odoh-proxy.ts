// ODoH proxy passthrough (RFC 9230 §5).
// relay1 sees only encrypted DNS bytes — completely blind to the query content.
import { asBodyInit, hmacSign } from "../../shared/src/crypto.ts";
import {
  RELAY2_HMAC_HEADER,
  RELAY2_TIMESTAMP_HEADER,
  CT_ODOH,
  MAX_OUTER_BODY_BYTES,
} from "../../shared/src/types.ts";

export async function handleOdohProxy(
  body: Uint8Array,
  relay2BaseUrl: string,
  hmacSecret: string,
): Promise<Response> {
  if (body.length > MAX_OUTER_BODY_BYTES) throw new Error("ODoH request too large");

  const timestamp = Date.now().toString();
  const hmac = await hmacSign(hmacSecret, timestamp, body);

  const upstream = await fetch(`${relay2BaseUrl}/dns-query`, {
    method: "POST",
    headers: {
      "Content-Type": CT_ODOH,
      [RELAY2_HMAC_HEADER]: hmac,
      [RELAY2_TIMESTAMP_HEADER]: timestamp,
    },
    body: asBodyInit(body),
  });

  return new Response(upstream.body, {
    status: upstream.status,
    headers: {
      "Content-Type": upstream.headers.get("Content-Type") ?? CT_ODOH,
    },
  });
}
