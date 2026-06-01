// Primary path: node:crypto privateDecrypt with RSA_NO_PADDING calls native
// BoringSSL — raw m^d mod n in <1 ms. nodejs_compat flag enables this in CF Workers.
// Fallback: BigInt CRT (50-150 ms) if the native path is unavailable.
import { privateDecrypt, createPrivateKey } from "node:crypto";
import type { JsonWebKey as NodeJsonWebKey, KeyObject } from "node:crypto";
import {
  extractRsaKey,
  rsaBlindSign as rsaBlindSignBigInt,
} from "../../shared/src/rsa-blind.ts";

import { issueToken } from "./token.ts";
import { generateTurnCredentials } from "./turn-credentials.ts";
import { asBufferSource, b64uDecode, b64uEncode } from "../../shared/src/crypto.ts";
import { BLIND_SIG_BYTES } from "../../shared/src/types.ts";

// RSA_NO_PADDING = 3 in OpenSSL/BoringSSL — raw modular exponentiation, no padding
const RSA_NO_PADDING = 3;

export interface Env {
  ISSUER_SECRET: string;
  TOKEN_TTL_SECONDS: string;
  BUNDLE_HASH: string;
  AUTH_KEYS: string;
  ISSUER_RSA_PRIVATE_KEY_JWK: string;
  TURN_SHARED_SECRET: string;
  TURN_SERVER_HOST: string;
}

// Cached per isolate
let _privKey: KeyObject | null = null;
let _pubJwk: JsonWebKey | null = null;
let _useNative: boolean | null = null; // null = not yet probed

function getPrivKey(env: Env): { key: KeyObject; jwk: JsonWebKey } {
  if (!_privKey) {
    const jwk = JSON.parse(env.ISSUER_RSA_PRIVATE_KEY_JWK) as JsonWebKey;
    _privKey = createPrivateKey({ key: jwk as NodeJsonWebKey, format: "jwk" });
    _pubJwk = { kty: "RSA", alg: "PS256", n: jwk.n, e: jwk.e };
  }
  return { key: _privKey!, jwk: JSON.parse(env.ISSUER_RSA_PRIVATE_KEY_JWK) as JsonWebKey };
}

function blindSign(blindMsgBytes: Uint8Array, env: Env): Uint8Array {
  const { key, jwk } = getPrivKey(env);

  // Probe native support once per isolate — some CF Workers builds expose a
  // node:crypto stub that doesn't implement privateDecrypt.
  if (_useNative === null) {
    try {
      privateDecrypt({ key, padding: RSA_NO_PADDING }, Buffer.alloc(256));
      _useNative = true;
    } catch {
      _useNative = false;
    }
  }

  if (_useNative) {
    const result = privateDecrypt({ key, padding: RSA_NO_PADDING }, Buffer.from(blindMsgBytes));
    return new Uint8Array(result);
  }

  // BigInt CRT fallback — correct but ~50-150 ms per operation
  return rsaBlindSignBigInt(blindMsgBytes, extractRsaKey(jwk));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      return Response.json({ ok: true, hash: env.BUNDLE_HASH ?? "dev" });
    }

    if (request.method === "GET" && url.pathname === "/issuer-key") {
      getPrivKey(env); // populate _pubJwk
      return Response.json(_pubJwk, {
        headers: { "Cache-Control": "public, max-age=3600" },
      });
    }

    if (request.method === "GET" && url.pathname === "/token-key") {
      const fp = await sha256Hex(new TextEncoder().encode(env.ISSUER_SECRET));
      return Response.json({ alg: "HMAC-SHA256", key_id: fp });
    }

    if (request.method !== "POST") {
      return new Response("Not Found", { status: 404 });
    }

    try {
      const credential = extractBearerToken(request);
      await verifyCredential(credential, env.AUTH_KEYS);

      if (url.pathname === "/blind-sign")      return handleBlindSign(request, env);
      if (url.pathname === "/issue")           return handleIssue(env);
      if (url.pathname === "/turn-credentials") return handleTurnCredentials(request, env);
      return new Response("Not Found", { status: 404 });
    } catch {
      return new Response("Unauthorized", { status: 401 });
    }
  },
};

// ── Blind sign (RFC 9474) ─────────────────────────────────────────────────────

async function handleBlindSign(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as { blind_msg?: string };
  if (typeof body.blind_msg !== "string") {
    return new Response("Bad Request", { status: 400 });
  }

  const blindMsgBytes = b64uDecode(body.blind_msg);
  if (blindMsgBytes.length !== BLIND_SIG_BYTES) {
    return new Response(`Bad Request: blind_msg must be ${BLIND_SIG_BYTES} bytes`, { status: 400 });
  }

  const blindSig = blindSign(blindMsgBytes, env);
  return Response.json({ blind_sig: b64uEncode(blindSig) });
}

// ── TURN credentials ──────────────────────────────────────────────────────────

async function handleTurnCredentials(request: Request, env: Env): Promise<Response> {
  const body = (await request.json().catch(() => ({}))) as { identifier?: string };
  const identifier = typeof body.identifier === "string" ? body.identifier : "anon";

  const ttl = parseInt(env.TOKEN_TTL_SECONDS ?? "3600", 10);
  const creds = await generateTurnCredentials(
    env.TURN_SHARED_SECRET,
    env.TURN_SERVER_HOST,
    ttl,
    identifier,
  );
  return Response.json(creds);
}

// ── Legacy HMAC token ─────────────────────────────────────────────────────────

async function handleIssue(env: Env): Promise<Response> {
  const ttl   = parseInt(env.TOKEN_TTL_SECONDS ?? "3600", 10);
  const token = await issueToken(env.ISSUER_SECRET, ttl);
  return Response.json({ token, exp: Math.floor(Date.now() / 1000) + ttl });
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

function extractBearerToken(request: Request): string {
  const auth = request.headers.get("Authorization") ?? "";
  if (!auth.startsWith("Bearer ")) throw new Error("Missing Bearer");
  return auth.slice(7).trim();
}

async function verifyCredential(credential: string, authKeys: string): Promise<void> {
  const valid = (authKeys ?? "").split("\n").map((k) => k.trim()).filter(Boolean);
  if (!valid.length) throw new Error("No auth keys");
  const credBytes = new TextEncoder().encode(credential);
  let ok = false;
  for (const k of valid) {
    ok = ok || await timingSafeEqual(credBytes, new TextEncoder().encode(k));
  }
  if (!ok) throw new Error("Bad credential");
}

async function timingSafeEqual(a: Uint8Array, b: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigA = await crypto.subtle.sign("HMAC", key, asBufferSource(a));
  return (await crypto.subtle.verify("HMAC", key, sigA, asBufferSource(b))) && a.length === b.length;
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", asBufferSource(data));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
