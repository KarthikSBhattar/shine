// OHTTP client (RFC 9458) and ODoH client (RFC 9230) for the Sunny browser.
import { asBodyInit, asBufferSource, b64uDecode } from "../../shared/src/crypto.ts";
import {
  OHTTP_KEY_ID,
  OHTTP_KEM_ID,
  OHTTP_KDF_ID,
  OHTTP_AEAD_ID,
  OHTTP_ENC_LEN,
  OHTTP_RESPONSE_NONCE_LEN,
  CT_OHTTP_REQ,
  CT_ODOH,
  CT_DNS,
  TOKEN_HEADER,
  ODOH_QUERY_TYPE,
  MAX_DNS_MESSAGE_BYTES,
} from "../../shared/src/types.ts";
import {
  encodeBhttpRequest,
  decodeBhttpResponse,
  BhttpResponse,
} from "../../shared/src/bhttp.ts";
import { hpkeSeal } from "./hpke.ts";

// ── Key Config parsing ────────────────────────────────────────────────────────

export interface OhttpKeyConfig {
  keyId: number;
  kemId: number;
  publicKeyBytes: Uint8Array;
  kdfId: number;
  aeadId: number;
}

// Parse the binary key config returned by relay2's GET /ohttp-keys
export function parseOhttpKeyConfig(data: Uint8Array): OhttpKeyConfig {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let off = 0;
  const keyId = data[off++]!;
  const kemId = view.getUint16(off, false); off += 2;
  const publicKeyBytes = data.slice(off, off + OHTTP_ENC_LEN); off += OHTTP_ENC_LEN;
  const csLen = view.getUint16(off, false); off += 2;
  const kdfId  = view.getUint16(off, false); off += 2;
  const aeadId = view.getUint16(off, false); off += 2;
  void csLen;
  return { keyId, kemId, publicKeyBytes, kdfId, aeadId };
}

// ── HPKE info for OHTTP ───────────────────────────────────────────────────────

function buildOhttpInfo(keyConfig: OhttpKeyConfig): Uint8Array {
  const label = new TextEncoder().encode("message/bhttp request");
  const hdr = new Uint8Array(7);
  const view = new DataView(hdr.buffer);
  hdr[0] = keyConfig.keyId;
  view.setUint16(1, keyConfig.kemId, false);
  view.setUint16(3, keyConfig.kdfId, false);
  view.setUint16(5, keyConfig.aeadId, false);
  const info = new Uint8Array(label.length + 1 + hdr.length);
  info.set(label);
  info[label.length] = 0x00;
  info.set(hdr, label.length + 1);
  return info;
}

// ── OHTTP request encapsulation ───────────────────────────────────────────────

interface EncapsulatedOhttpRequest {
  bytes: Uint8Array;
  exportSecret: Uint8Array; // held by client for response decryption
}

async function encapsulateOhttpRequest(
  keyConfig: OhttpKeyConfig,
  bhttpBytes: Uint8Array,
): Promise<EncapsulatedOhttpRequest> {
  const info = buildOhttpInfo(keyConfig);
  const { enc, ciphertext, exportSecret } = await hpkeSeal(
    keyConfig.publicKeyBytes, info, bhttpBytes,
  );

  // Wire: hdr (7 bytes) || enc (32 bytes) || ciphertext
  const hdr = new Uint8Array(7);
  const view = new DataView(hdr.buffer);
  hdr[0] = keyConfig.keyId;
  view.setUint16(1, keyConfig.kemId, false);
  view.setUint16(3, keyConfig.kdfId, false);
  view.setUint16(5, keyConfig.aeadId, false);

  const bytes = new Uint8Array(hdr.length + enc.length + ciphertext.length);
  bytes.set(hdr);
  bytes.set(enc, hdr.length);
  bytes.set(ciphertext, hdr.length + enc.length);

  return { bytes, exportSecret };
}

// ── OHTTP response decapsulation ─────────────────────────────────────────────

async function decapsulateOhttpResponse(
  exportSecret: Uint8Array,
  encapsulatedResponse: Uint8Array,
): Promise<Uint8Array> {
  if (encapsulatedResponse.length < OHTTP_RESPONSE_NONCE_LEN + 16) {
    throw new Error("OHTTP response too short");
  }
  const responseNonce = encapsulatedResponse.slice(0, OHTTP_RESPONSE_NONCE_LEN);
  const ciphertext    = encapsulatedResponse.slice(OHTTP_RESPONSE_NONCE_LEN);

  // HKDF-Extract(salt=responseNonce, ikm=exportSecret) then Expand for key and nonce
  const saltKey = await crypto.subtle.importKey(
    "raw", asBufferSource(responseNonce), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const prk = new Uint8Array(await crypto.subtle.sign("HMAC", saltKey, asBufferSource(exportSecret)));

  const prkKey = await crypto.subtle.importKey(
    "raw", asBufferSource(prk), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const aesKeyBytes = new Uint8Array(
    await crypto.subtle.sign("HMAC", prkKey, new Uint8Array([...new TextEncoder().encode("key"), 0x01])),
  ).slice(0, 32);
  const ivBytes = new Uint8Array(
    await crypto.subtle.sign("HMAC", prkKey, new Uint8Array([...new TextEncoder().encode("nonce"), 0x01])),
  ).slice(0, 12);

  const aesKey = await crypto.subtle.importKey("raw", asBufferSource(aesKeyBytes), { name: "AES-GCM" }, false, ["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: asBufferSource(ivBytes) }, aesKey, asBufferSource(ciphertext)));
}

// ── Public API ────────────────────────────────────────────────────────────────

export interface OhttpClientConfig {
  relay1Url: string;
  keyConfig: OhttpKeyConfig;
  token?: string; // from the issuer, if REQUIRE_TOKEN=true at relay1
}

export interface OhttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

export async function ohttpRequest(
  config: OhttpClientConfig,
  destination: string,
  init: { method?: string; headers?: Record<string, string>; body?: Uint8Array | string } = {},
): Promise<OhttpResponse> {
  const method = (init.method ?? "GET").toUpperCase();
  const url    = new URL(destination);

  let bodyBytes: Uint8Array = new Uint8Array(0);
  if (init.body !== undefined) {
    bodyBytes = typeof init.body === "string"
      ? new TextEncoder().encode(init.body)
      : init.body;
  }

  const bhttpBytes = encodeBhttpRequest({
    method,
    scheme:    url.protocol.replace(/:$/, ""),
    authority: url.host,
    path:      url.pathname + url.search,
    headers:   init.headers ?? {},
    body:      bodyBytes,
  });

  const { bytes: encapsulated, exportSecret } = await encapsulateOhttpRequest(
    config.keyConfig,
    bhttpBytes,
  );

  const reqHeaders: Record<string, string> = {
    "Content-Type": CT_OHTTP_REQ,
  };
  if (config.token) reqHeaders[TOKEN_HEADER] = config.token;

  const httpResp = await fetch(`${config.relay1Url}/ohttp`, {
    method: "POST",
    headers: reqHeaders,
    body: asBodyInit(encapsulated),
  });
  if (!httpResp.ok) throw new Error(`Relay error: HTTP ${httpResp.status}`);

  const encapsulatedResp = new Uint8Array(await httpResp.arrayBuffer());
  const bhttpResp = await decapsulateOhttpResponse(exportSecret, encapsulatedResp);
  const decoded   = decodeBhttpResponse(bhttpResp);

  return {
    status:  decoded.status,
    headers: decoded.headers,
    body:    decoded.body,
  };
}

// ── ODoH client ───────────────────────────────────────────────────────────────

export interface OdohClientConfig {
  relay1Url: string;
  targetPublicKeyBytes: Uint8Array; // relay2's X25519 HPKE public key
  token?: string;
}

export async function odohQuery(
  config: OdohClientConfig,
  dnsWireBytes: Uint8Array,
): Promise<Uint8Array> {
  if (dnsWireBytes.length > MAX_DNS_MESSAGE_BYTES) throw new Error("DNS query too large");

  // ODoH key_id = SHA-256(public key bytes) — simplified (full spec hashes the KeyConfig)
  const keyHashBuf = await crypto.subtle.digest("SHA-256", asBufferSource(config.targetPublicKeyBytes));
  const keyHash = new Uint8Array(keyHashBuf);

  // Build ODoH info string: "odoh query\0" + key_id_field
  const label = new TextEncoder().encode("odoh query");
  const keyIdField = new Uint8Array(1 + keyHash.length);
  keyIdField[0] = keyHash.length;
  keyIdField.set(keyHash, 1);
  const info = new Uint8Array(label.length + 1 + keyIdField.length);
  info.set(label);
  info[label.length] = 0x00;
  info.set(keyIdField, label.length + 1);

  // Encode query plaintext
  const plaintext = new Uint8Array(2 + dnsWireBytes.length + 2);
  new DataView(plaintext.buffer).setUint16(0, dnsWireBytes.length, false);
  plaintext.set(dnsWireBytes, 2);
  // zero-length padding already zero-initialized

  const { enc, ciphertext, exportSecret } = await hpkeSeal(
    config.targetPublicKeyBytes, info, plaintext, "odoh",
  );

  // Build ObliviousDoHMessage (query)
  const keyIdFieldLen = 1 + keyHash.length;
  const encLen = enc.length; // 32 bytes
  const payloadLen = ciphertext.length;
  const msg = new Uint8Array(1 + 1 + keyIdField.length + 2 + encLen + 4 + payloadLen);
  const msgView = new DataView(msg.buffer);
  let off = 0;
  msg[off++] = ODOH_QUERY_TYPE;
  msg[off++] = keyHash.length;      // key_id length byte
  msg.set(keyHash, off); off += keyHash.length;
  msgView.setUint16(off, encLen, false); off += 2;
  msg.set(enc, off); off += encLen;
  msgView.setUint32(off, payloadLen, false); off += 4;
  msg.set(ciphertext, off);

  const reqHeaders: Record<string, string> = { "Content-Type": CT_ODOH };
  if (config.token) reqHeaders[TOKEN_HEADER] = config.token;

  const httpResp = await fetch(`${config.relay1Url}/dns-query`, {
    method: "POST",
    headers: reqHeaders,
    body: asBodyInit(msg),
  });
  if (!httpResp.ok) throw new Error(`ODoH relay error: HTTP ${httpResp.status}`);

  // Decrypt ODoH response
  const respMsg = new Uint8Array(await httpResp.arrayBuffer());
  return decryptOdohResponse(exportSecret, enc, respMsg);
}

async function decryptOdohResponse(
  exportSecret: Uint8Array,
  requestEnc: Uint8Array,   // enc from the query, used as part of the salt
  responseMsg: Uint8Array,
): Promise<Uint8Array> {
  // Parse response ObliviousDoHMessage: type(1) + key_id_len(1) + enc_len(2) + payload_len(4) + payload
  const view = new DataView(responseMsg.buffer, responseMsg.byteOffset, responseMsg.byteLength);
  let off = 0;
  off++; // msg_type = 0x02
  off += 1 + responseMsg[1]!; // skip key_id
  const encLen = view.getUint16(off, false); off += 2;
  off += encLen; // skip empty enc
  const payloadLen = view.getUint32(off, false); off += 4;
  const encryptedPayload = responseMsg.slice(off, off + payloadLen);

  const responseNonce = encryptedPayload.slice(0, OHTTP_RESPONSE_NONCE_LEN);
  const ciphertext    = encryptedPayload.slice(OHTTP_RESPONSE_NONCE_LEN);

  // salt = requestEnc || responseNonce
  const salt = new Uint8Array([...requestEnc, ...responseNonce]);
  const saltKey = await crypto.subtle.importKey("raw", asBufferSource(salt), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const prk = new Uint8Array(await crypto.subtle.sign("HMAC", saltKey, asBufferSource(exportSecret)));

  const prkKey = await crypto.subtle.importKey("raw", asBufferSource(prk), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const aesKeyBytes = new Uint8Array(
    await crypto.subtle.sign("HMAC", prkKey, new Uint8Array([...new TextEncoder().encode("odoh key"), 0x01])),
  ).slice(0, 32);
  const ivBytes = new Uint8Array(
    await crypto.subtle.sign("HMAC", prkKey, new Uint8Array([...new TextEncoder().encode("odoh nonce"), 0x01])),
  ).slice(0, 12);

  const aesKey = await crypto.subtle.importKey("raw", asBufferSource(aesKeyBytes), { name: "AES-GCM" }, false, ["decrypt"]);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: asBufferSource(ivBytes) }, aesKey, asBufferSource(ciphertext)));

  // Decode ObliviousDoHResponse: dns_message_len(2) + dns_message + padding_len(2) + padding
  const dnsLen = new DataView(plaintext.buffer, plaintext.byteOffset).getUint16(0, false);
  return plaintext.slice(2, 2 + dnsLen);
}
