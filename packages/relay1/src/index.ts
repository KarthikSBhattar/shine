import { eciesDecrypt, b64uDecode } from "../../shared/src/crypto.ts";
import { unpad } from "../../shared/src/padding.ts";
import {
  OuterEnvelope,
  MAX_OUTER_BODY_BYTES,
  MAX_TIMESTAMP_SKEW_MS,
  TOKEN_HEADER,
  CT_OHTTP_REQ,
  CT_ODOH,
  BLIND_TOKEN_PREFIX,
} from "../../shared/src/types.ts";
import { forwardToRelay2 } from "./forward.ts";
import { handleOhttpRelay } from "./ohttp-relay.ts";
import { handleOdohProxy } from "./odoh-proxy.ts";
import { verifyClientToken } from "./token-verify.ts";
import { verifyBlindToken, getIssuerPubKey } from "./blind-token-verify.ts";
import { handleTunnel } from "./tunnel.ts";

export interface Env {
  // Legacy ECIES keys
  RELAY1_PRIVATE_KEY_JWK: string;
  RELAY1_PUBLIC_KEY_RAW: string;
  // Routing
  RELAY2_URL: string;
  RELAY2_HMAC_SECRET: string;
  // Token gating
  ISSUER_SECRET: string;     // shared secret for HMAC tokens
  ISSUER_URL: string;        // issuer worker URL (for fetching RSA public key)
  REQUIRE_TOKEN: string;     // "true" to enforce
  TOKEN_MODE: string;        // "hmac" | "blind" | "any"
  // Transparency
  BUNDLE_HASH: string;
}

let _cachedPrivateKey: CryptoKey | null = null;
let _cachedPubBytes: Uint8Array | null = null;

async function getEciesKeys(env: Env) {
  if (!_cachedPrivateKey) {
    _cachedPrivateKey = await crypto.subtle.importKey(
      "jwk",
      JSON.parse(env.RELAY1_PRIVATE_KEY_JWK) as JsonWebKey,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    _cachedPubBytes = b64uDecode(env.RELAY1_PUBLIC_KEY_RAW);
  }
  return { privateKey: _cachedPrivateKey!, ownPubBytes: _cachedPubBytes! };
}

async function maybeVerifyToken(request: Request, env: Env): Promise<void> {
  if (env.REQUIRE_TOKEN !== "true") return;

  // For WebSocket upgrades, browsers can't send custom headers.
  // Fall back to query-param token: ?token=<value>
  const url = new URL(request.url);
  const token =
    request.headers.get(TOKEN_HEADER) ?? url.searchParams.get("token");
  if (!token) throw new Error("Missing client token");

  const mode = env.TOKEN_MODE ?? "hmac";
  const isBlind = token.startsWith(BLIND_TOKEN_PREFIX);

  if (mode === "blind" || (mode === "any" && isBlind)) {
    const pubKey = await getIssuerPubKey(env.ISSUER_URL);
    await verifyBlindToken(token, pubKey);
  } else {
    await verifyClientToken(token, env.ISSUER_SECRET);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      return Response.json({ ok: true, hash: env.BUNDLE_HASH ?? "dev" });
    }

    // WebSocket tunnel — must be checked before the POST-only guard
    if (url.pathname === "/tunnel") {
      try {
        await maybeVerifyToken(request, env);
        return handleTunnel(request, env.RELAY2_URL, env.RELAY2_HMAC_SECRET);
      } catch {
        return new Response("Unauthorized", { status: 401 });
      }
    }

    if (request.method !== "POST") {
      return new Response("Not Found", { status: 404 });
    }

    try {
      await maybeVerifyToken(request, env);

      if (url.pathname === "/ohttp") {
        const body = new Uint8Array(await request.arrayBuffer());
        return handleOhttpRelay(body, env.RELAY2_URL, env.RELAY2_HMAC_SECRET);
      }
      if (url.pathname === "/dns-query") {
        const body = new Uint8Array(await request.arrayBuffer());
        return handleOdohProxy(body, env.RELAY2_URL, env.RELAY2_HMAC_SECRET);
      }
      if (url.pathname === "/relay") {
        return handleLegacyRelay(request, env);
      }
      return new Response("Not Found", { status: 404 });
    } catch {
      return new Response("Bad Request", { status: 400 });
    }
  },
};

async function handleLegacyRelay(request: Request, env: Env): Promise<Response> {
  const bodyBytes = new Uint8Array(await request.arrayBuffer());
  if (bodyBytes.length === 0 || bodyBytes.length > MAX_OUTER_BODY_BYTES) {
    throw new Error("Body size out of range");
  }
  const { privateKey, ownPubBytes } = await getEciesKeys(env);
  const decrypted = await eciesDecrypt(privateKey, ownPubBytes, bodyBytes, "shine-relay1-v1");
  const unpadded  = unpad(decrypted);
  const envelope  = JSON.parse(new TextDecoder().decode(unpadded)) as OuterEnvelope;

  if (envelope.version !== 1) throw new Error("Unsupported envelope version");
  if (Math.abs(Date.now() - envelope.timestamp) > MAX_TIMESTAMP_SKEW_MS) {
    throw new Error("Timestamp out of range");
  }
  const allowed   = new URL(env.RELAY2_URL);
  const requested = new URL(envelope.relay2Url);
  if (requested.origin !== allowed.origin) throw new Error("Unauthorized relay2 URL");

  return forwardToRelay2(b64uDecode(envelope.innerCiphertext), env.RELAY2_URL, env.RELAY2_HMAC_SECRET);
}
