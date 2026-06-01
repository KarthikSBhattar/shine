import { asBodyInit, b64uDecode } from "../../shared/src/crypto.ts";
import {
  InnerEnvelope,
  MAX_RESPONSE_BODY_BYTES,
  MAX_REDIRECTS,
  ALLOWED_HTTP_METHODS,
} from "../../shared/src/types.ts";
import { validateDestination } from "./validate.ts";

// Headers that must not be forwarded to the origin (hop-by-hop / internal)
const STRIP_REQUEST_HEADERS: ReadonlySet<string> = new Set([
  "host",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "proxy-authorization",
  "proxy-authenticate",
  "proxy-connection",
  "authorization",
  "cookie",
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "cf-visitor",
  "cf-worker",
  "forwarded",
  "true-client-ip",
  "via",
  "x-client-ip",
  "x-cluster-client-ip",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
]);

// Stream the response body while enforcing a byte cap.
// Using arrayBuffer() directly would allow a response with no Content-Length
// header (or a lying one) to exhaust memory before we can reject it.
async function readBodyCapped(
  response: Response,
  maxBytes: number,
): Promise<Uint8Array> {
  if (!response.body) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) {
        throw new Error("Origin response body exceeds size limit");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export async function fetchOrigin(envelope: InnerEnvelope): Promise<{ body: Uint8Array; response: Response }> {
  if (!ALLOWED_HTTP_METHODS.has(envelope.method)) {
    throw new Error(`Disallowed HTTP method: ${envelope.method}`);
  }

  let currentUrl = envelope.destination;
  let currentMethod = envelope.method;
  let redirectCount = 0;

  while (true) {
    const headers = new Headers();
    for (const [k, v] of Object.entries(envelope.headers)) {
      if (!STRIP_REQUEST_HEADERS.has(k.toLowerCase())) headers.set(k, v);
    }

    // Send the body only on the initial request or on method-preserving redirects (307/308)
    let body: BodyInit | null = null;
    if (envelope.body !== null && currentMethod !== "GET" && currentMethod !== "HEAD") {
      body = asBodyInit(b64uDecode(envelope.body));
    }

    const response = await fetch(currentUrl, {
      method: currentMethod,
      headers,
      body,
      redirect: "manual", // handle redirects manually so we can re-validate each hop
    });

    if (response.status >= 300 && response.status < 400) {
      if (redirectCount >= MAX_REDIRECTS) {
        throw new Error("Too many redirects");
      }
      const location = response.headers.get("location");
      if (!location) throw new Error("Redirect with no Location header");

      const nextUrl = new URL(location, currentUrl).toString();
      validateDestination(nextUrl); // SSRF check on every hop

      // RFC 7231: 301/302/303 collapse POST → GET; 307/308 preserve original method
      if (response.status !== 307 && response.status !== 308) {
        currentMethod = "GET";
      }

      currentUrl = nextUrl;
      redirectCount++;
      continue;
    }

    // Reject early on known-oversized responses before buffering
    const cl = response.headers.get("content-length");
    if (cl !== null) {
      const clNum = parseInt(cl, 10);
      if (!isNaN(clNum) && clNum > MAX_RESPONSE_BODY_BYTES) {
        throw new Error("Origin response body exceeds size limit");
      }
    }

    const body2 = await readBodyCapped(response, MAX_RESPONSE_BODY_BYTES);
    return { body: body2, response };
  }
}
