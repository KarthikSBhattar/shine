/// <reference lib="deno.ns" />

import {
  asBodyInit,
  asBufferSource,
  b64uDecode,
  b64uEncode,
  eciesDecrypt,
} from "../../shared/src/crypto.ts";
import { unpad } from "../../shared/src/padding.ts";
import {
  CT_ODOH,
  CT_OHTTP_REQ,
  EncryptedResponse,
  InnerEnvelope,
  MAX_INNER_BODY_BYTES,
  MAX_TIMESTAMP_SKEW_MS,
  RELAY2_HMAC_HEADER,
  RELAY2_TIMESTAMP_HEADER,
} from "../../shared/src/types.ts";
import { verifyRelayAuth } from "./auth.ts";
import { addJitter } from "./jitter.ts";
import { fetchOrigin } from "./origin.ts";
import { validateDestination } from "./validate.ts";
import { buildOhttpKeyConfig, handleOhttp } from "./ohttp-gateway.ts";
import { handleOdoh } from "./odoh-target.ts";
import { handleTunnel } from "./tunnel.ts";
import { serializePublicKey } from "./hpke.ts";

function requireEnv(name: string): string {
  const v = Deno.env.get(name);
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

// ── Cached key material ───────────────────────────────────────────────────────

let _eciesKey: CryptoKey | null = null;
let _eciesPubBytes: Uint8Array | null = null;
let _hpkePrivJwk: JsonWebKey | null = null;
let _hpkePubBytes: Uint8Array | null = null;

async function getEciesKeys() {
  if (!_eciesKey) {
    _eciesKey = await crypto.subtle.importKey(
      "jwk",
      JSON.parse(requireEnv("RELAY2_PRIVATE_KEY_JWK")) as JsonWebKey,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    _eciesPubBytes = b64uDecode(requireEnv("RELAY2_PUBLIC_KEY_RAW"));
  }
  return { privateKey: _eciesKey!, ownPubBytes: _eciesPubBytes! };
}

async function getHpkeKeys() {
  if (!_hpkePrivJwk) {
    _hpkePrivJwk = JSON.parse(
      requireEnv("RELAY2_HPKE_PRIVATE_KEY_JWK"),
    ) as JsonWebKey;
    _hpkePubBytes = b64uDecode(requireEnv("RELAY2_HPKE_PUBLIC_KEY_RAW"));
  }
  return { privJwk: _hpkePrivJwk!, pubBytes: _hpkePubBytes! };
}

// ── Auth helper ───────────────────────────────────────────────────────────────

async function verifyAuth(request: Request, body: Uint8Array): Promise<void> {
  const timestamp = request.headers.get(RELAY2_TIMESTAMP_HEADER);
  const hmac = request.headers.get(RELAY2_HMAC_HEADER);
  if (!timestamp || !hmac) throw new Error("Missing auth headers");
  await verifyRelayAuth(
    requireEnv("RELAY2_HMAC_SECRET"),
    timestamp,
    hmac,
    body,
  );
}

// ── Entry point ───────────────────────────────────────────────────────────────

Deno.serve(async (request: Request): Promise<Response> => {
  const url = new URL(request.url);

  if (url.pathname === "/healthz") {
    return Response.json({
      ok: true,
      hash: Deno.env.get("BUNDLE_HASH") ?? "dev",
    });
  }

  // Publish HPKE key config so SDK can fetch it (not sensitive)
  if (request.method === "GET" && url.pathname === "/ohttp-keys") {
    const { pubBytes } = await getHpkeKeys();
    const keyConfig = buildOhttpKeyConfig(pubBytes);
    return new Response(asBodyInit(keyConfig), {
      headers: { "Content-Type": "application/ohttp-keys" },
    });
  }

  // WebSocket TCP tunnel — checked before POST-only guard
  if (
    url.pathname === "/tunnel" && request.headers.get("upgrade") === "websocket"
  ) {
    const { privJwk, pubBytes } = await getHpkeKeys();
    return handleTunnel(
      request,
      requireEnv("RELAY2_HMAC_SECRET"),
      privJwk,
      pubBytes,
    );
  }

  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  try {
    if (url.pathname === "/ohttp") return await handleOhttpRoute(request);
    if (url.pathname === "/dns-query") return await handleOdohRoute(request);
    if (url.pathname === "/relay") return await handleRelayRoute(request);
    return new Response("Not Found", { status: 404 });
  } catch {
    return new Response("Bad Request", { status: 400 });
  }
});

// ── OHTTP gateway ─────────────────────────────────────────────────────────────

async function handleOhttpRoute(request: Request): Promise<Response> {
  const bodyBytes = new Uint8Array(await request.arrayBuffer());
  if (bodyBytes.length === 0 || bodyBytes.length > MAX_INNER_BODY_BYTES) {
    throw new Error("Body size out of range");
  }
  await verifyAuth(request, bodyBytes);
  const { privJwk, pubBytes } = await getHpkeKeys();
  return handleOhttp(bodyBytes, privJwk, pubBytes);
}

// ── ODoH target ───────────────────────────────────────────────────────────────

async function handleOdohRoute(request: Request): Promise<Response> {
  const bodyBytes = new Uint8Array(await request.arrayBuffer());
  if (bodyBytes.length === 0 || bodyBytes.length > 65535 + 256) {
    throw new Error("Body size out of range");
  }
  await verifyAuth(request, bodyBytes);
  const { privJwk, pubBytes } = await getHpkeKeys();
  const resolverUrl = Deno.env.get("ODOH_RESOLVER_URL") ??
    "https://1.1.1.1/dns-query";
  return handleOdoh(bodyBytes, privJwk, pubBytes, resolverUrl);
}

// ── Legacy ECIES relay (backward compat) ──────────────────────────────────────

async function handleRelayRoute(request: Request): Promise<Response> {
  const bodyBytes = new Uint8Array(await request.arrayBuffer());
  if (bodyBytes.length === 0 || bodyBytes.length > MAX_INNER_BODY_BYTES) {
    throw new Error("Body size out of range");
  }
  await verifyAuth(request, bodyBytes);

  const { privateKey, ownPubBytes } = await getEciesKeys();
  const decrypted = await eciesDecrypt(
    privateKey,
    ownPubBytes,
    bodyBytes,
    "shine-relay2-v1",
  );
  const unpadded = unpad(decrypted);
  const envelope = JSON.parse(
    new TextDecoder().decode(unpadded),
  ) as InnerEnvelope;

  if (Math.abs(Date.now() - envelope.timestamp) > MAX_TIMESTAMP_SKEW_MS) {
    throw new Error("Timestamp out of range");
  }

  validateDestination(envelope.destination);
  await addJitter();

  const { body: originBody, response: originResponse } = await fetchOrigin(
    envelope,
  );

  const responseKeyBytes = b64uDecode(envelope.responseKey);
  if (responseKeyBytes.length !== 32) {
    throw new Error("Invalid response key length");
  }

  const aesKey = await crypto.subtle.importKey(
    "raw",
    asBufferSource(responseKeyBytes),
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedBody = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asBufferSource(iv) },
    aesKey,
    asBufferSource(originBody),
  );

  const safeHeaders: Record<string, string> = {};
  for (
    const key of [
      "content-type",
      "content-language",
      "cache-control",
      "etag",
      "last-modified",
    ]
  ) {
    const val = originResponse.headers.get(key);
    if (val) safeHeaders[key] = val;
  }

  const resp: EncryptedResponse = {
    status: originResponse.status,
    headers: safeHeaders,
    body: b64uEncode(new Uint8Array(encryptedBody)),
    iv: b64uEncode(iv),
  };
  return Response.json(resp);
}
