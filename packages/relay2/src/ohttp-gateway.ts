// OHTTP gateway (RFC 9458) — relay2 decapsulates and proxies OHTTP requests.
import { asBodyInit, asBufferSource, b64uDecode, b64uEncode } from "../../shared/src/crypto.ts";
import {
  OHTTP_KEY_ID,
  OHTTP_KEM_ID,
  OHTTP_KDF_ID,
  OHTTP_AEAD_ID,
  OHTTP_ENC_LEN,
  OHTTP_RESPONSE_NONCE_LEN,
  CT_OHTTP_RES,
  MAX_INNER_BODY_BYTES,
} from "../../shared/src/types.ts";
import {
  encodeBhttpRequest,
  decodeBhttpRequest,
  encodeBhttpResponse,
  BhttpRequest,
} from "../../shared/src/bhttp.ts";
import { hpkeOpen } from "./hpke.ts";
import { fetchOrigin } from "./origin.ts";
import { validateDestination } from "./validate.ts";
import { addJitter } from "./jitter.ts";
import { InnerEnvelope, ALLOWED_HTTP_METHODS } from "../../shared/src/types.ts";

// ── Key Config (RFC 9458 §3) ─────────────────────────────────────────────────

// Builds the 41-byte OHTTP Key Configuration binary:
//   key_id (1) + kem_id (2) + public_key (32) + cipher_suites_len (2) + kdf_id (2) + aead_id (2)
export function buildOhttpKeyConfig(publicKeyBytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + 2 + publicKeyBytes.length + 2 + 2 + 2);
  const view = new DataView(out.buffer);
  let off = 0;
  out[off++] = OHTTP_KEY_ID;
  view.setUint16(off, OHTTP_KEM_ID, false); off += 2;
  out.set(publicKeyBytes, off); off += publicKeyBytes.length;
  view.setUint16(off, 4, false); off += 2;  // cipher_suites length = 4 bytes (one suite)
  view.setUint16(off, OHTTP_KDF_ID, false);  off += 2;
  view.setUint16(off, OHTTP_AEAD_ID, false); off += 2;
  return out;
}

// ── HPKE info string (RFC 9458 §5.1) ─────────────────────────────────────────

function buildOhttpInfo(): Uint8Array {
  // info = "message/bhttp request" || 0x00 || hdr
  // hdr  = key_id (1) || kem_id (2) || kdf_id (2) || aead_id (2)
  const label = new TextEncoder().encode("message/bhttp request");
  const hdr = new Uint8Array(7);
  const view = new DataView(hdr.buffer);
  hdr[0] = OHTTP_KEY_ID;
  view.setUint16(1, OHTTP_KEM_ID, false);
  view.setUint16(3, OHTTP_KDF_ID, false);
  view.setUint16(5, OHTTP_AEAD_ID, false);
  const info = new Uint8Array(label.length + 1 + hdr.length);
  info.set(label);
  info[label.length] = 0x00;
  info.set(hdr, label.length + 1);
  return info;
}

const OHTTP_INFO = buildOhttpInfo();

// ── Response key derivation (RFC 9458 §5.2) ───────────────────────────────────

async function deriveResponseKey(
  exportSecret: Uint8Array,
): Promise<{ aesKey: CryptoKey; iv: Uint8Array; nonce: Uint8Array }> {
  const responsNonce = crypto.getRandomValues(new Uint8Array(OHTTP_RESPONSE_NONCE_LEN));

  // HKDF-Extract(salt = response_nonce, ikm = exportSecret)
  const saltKey = await crypto.subtle.importKey(
    "raw", asBufferSource(responsNonce), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const prk = new Uint8Array(await crypto.subtle.sign("HMAC", saltKey, asBufferSource(exportSecret)));

  // HKDF-Expand(prk, "key", 32) and HKDF-Expand(prk, "nonce", 12)
  const prkKey = await crypto.subtle.importKey(
    "raw", asBufferSource(prk), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );

  const keyInfo   = new Uint8Array([...new TextEncoder().encode("key"),   0x01]);
  const nonceInfo = new Uint8Array([...new TextEncoder().encode("nonce"), 0x01]);

  const aesKeyBytes = new Uint8Array(await crypto.subtle.sign("HMAC", prkKey, keyInfo)).slice(0, 32);
  const ivBytes     = new Uint8Array(await crypto.subtle.sign("HMAC", prkKey, nonceInfo)).slice(0, 12);

  const aesKey = await crypto.subtle.importKey("raw", asBufferSource(aesKeyBytes), { name: "AES-GCM" }, false, ["encrypt"]);
  return { aesKey, iv: ivBytes, nonce: responsNonce };
}

// ── Decapsulate OHTTP request (RFC 9458 §5.1) ─────────────────────────────────

export async function decapsulateOhttpRequest(
  body: Uint8Array,
  privateKeyJwk: JsonWebKey,
  publicKeyBytes: Uint8Array,
): Promise<{
  bhttpRequest: BhttpRequest;
  exportSecret: Uint8Array;
}> {
  // Parse the fixed 7-byte header
  if (body.length < 7 + OHTTP_ENC_LEN + 1) throw new Error("OHTTP request too short");
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  if (body[0] !== OHTTP_KEY_ID)               throw new Error("Unknown OHTTP key_id");
  if (view.getUint16(1, false) !== OHTTP_KEM_ID)  throw new Error("Unsupported KEM");
  if (view.getUint16(3, false) !== OHTTP_KDF_ID)  throw new Error("Unsupported KDF");
  if (view.getUint16(5, false) !== OHTTP_AEAD_ID) throw new Error("Unsupported AEAD");

  const enc        = body.slice(7, 7 + OHTTP_ENC_LEN);
  const ciphertext = body.slice(7 + OHTTP_ENC_LEN);

  const { plaintext, exportSecret } = await hpkeOpen(
    privateKeyJwk, publicKeyBytes, enc, OHTTP_INFO, ciphertext,
  );

  const bhttpRequest = decodeBhttpRequest(plaintext);
  return { bhttpRequest, exportSecret };
}

// ── Encapsulate OHTTP response (RFC 9458 §5.2) ────────────────────────────────

export async function encapsulateOhttpResponse(
  exportSecret: Uint8Array,
  bhttpResponseBytes: Uint8Array,
): Promise<Uint8Array> {
  const { aesKey, iv, nonce: responsNonce } = await deriveResponseKey(exportSecret);
  const encryptedBody = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asBufferSource(iv) },
    aesKey,
    asBufferSource(bhttpResponseBytes),
  );
  // Wire: response_nonce (32 bytes) || ciphertext
  const out = new Uint8Array(OHTTP_RESPONSE_NONCE_LEN + encryptedBody.byteLength);
  out.set(responsNonce);
  out.set(new Uint8Array(encryptedBody), OHTTP_RESPONSE_NONCE_LEN);
  return out;
}

// ── Main OHTTP handler ────────────────────────────────────────────────────────

export async function handleOhttp(
  bodyBytes: Uint8Array,
  privateKeyJwk: JsonWebKey,
  publicKeyBytes: Uint8Array,
): Promise<Response> {
  if (bodyBytes.length > MAX_INNER_BODY_BYTES) throw new Error("OHTTP request too large");

  const { bhttpRequest, exportSecret } = await decapsulateOhttpRequest(
    bodyBytes, privateKeyJwk, publicKeyBytes,
  );

  const destination =
    `${bhttpRequest.scheme}://${bhttpRequest.authority}${bhttpRequest.path}`;

  validateDestination(destination);

  if (!ALLOWED_HTTP_METHODS.has(bhttpRequest.method)) {
    throw new Error(`Disallowed method: ${bhttpRequest.method}`);
  }

  // Synthesize an InnerEnvelope-compatible shape for fetchOrigin
  const fakeEnvelope: InnerEnvelope = {
    destination,
    method: bhttpRequest.method,
    headers: bhttpRequest.headers,
    body: bhttpRequest.body.length > 0 ? b64uEncode(bhttpRequest.body) : null,
    responseKey: "",  // not used by fetchOrigin
    nonce: "",
    timestamp: 0,
  };

  await addJitter();
  const { body: originBody, response: originResponse } = await fetchOrigin(fakeEnvelope);

  const safeHeaders: Record<string, string> = {};
  for (const key of ["content-type", "content-language", "cache-control", "etag", "last-modified"]) {
    const val = originResponse.headers.get(key);
    if (val) safeHeaders[key] = val;
  }

  const bhttpResp = encodeBhttpResponse({
    status: originResponse.status,
    headers: safeHeaders,
    body: originBody,
  });

  const encapsulated = await encapsulateOhttpResponse(exportSecret, bhttpResp);

  return new Response(asBodyInit(encapsulated), {
    status: 200,
    headers: { "Content-Type": CT_OHTTP_RES },
  });
}
