// ODoH target (RFC 9230) — relay2 decrypts DNS queries and proxies to a real DoH resolver.
import { asBodyInit, asBufferSource } from "../../shared/src/crypto.ts";
import {
  CT_ODOH,
  CT_DNS,
  MAX_DNS_MESSAGE_BYTES,
  ODOH_QUERY_TYPE,
  ODOH_RESPONSE_TYPE,
  OHTTP_KEM_ID,
  OHTTP_KDF_ID,
  OHTTP_AEAD_ID,
  OHTTP_ENC_LEN,
  OHTTP_RESPONSE_NONCE_LEN,
} from "../../shared/src/types.ts";
import { hpkeOpen } from "./hpke.ts";

// ── HPKE info string (RFC 9230 §4.1) ─────────────────────────────────────────

function buildOdohInfo(keyConfigHash: Uint8Array): Uint8Array {
  // info = "odoh query" || 0x00 || key_id_field
  // key_id_field = 1-byte-length (0x20) + SHA-256(KeyConfig)
  const label = new TextEncoder().encode("odoh query");
  const keyIdField = new Uint8Array(1 + keyConfigHash.length);
  keyIdField[0] = keyConfigHash.length; // length prefix
  keyIdField.set(keyConfigHash, 1);
  const info = new Uint8Array(label.length + 1 + keyIdField.length);
  info.set(label);
  info[label.length] = 0x00;
  info.set(keyIdField, label.length + 1);
  return info;
}

// ── ODoH message parsing (RFC 9230 §4) ────────────────────────────────────────

interface OdohMessage {
  msgType: number;
  keyId: Uint8Array;
  enc: Uint8Array;
  payload: Uint8Array;
}

function parseOdohMessage(data: Uint8Array): OdohMessage {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let off = 0;

  const msgType = data[off++]!;

  // key_id: 1-byte length prefix
  const keyIdLen = data[off++]!;
  const keyId = data.slice(off, off + keyIdLen); off += keyIdLen;

  // enc: 2-byte length prefix
  const encLen = view.getUint16(off, false); off += 2;
  const enc = data.slice(off, off + encLen); off += encLen;

  // payload: 4-byte length prefix
  const payloadLen = view.getUint32(off, false); off += 4;
  const payload = data.slice(off, off + payloadLen);

  return { msgType, keyId, enc, payload };
}

function buildOdohResponseMessage(encryptedPayload: Uint8Array): Uint8Array {
  // msg_type=0x02, key_id=[0x00] (empty), enc=[0x00,0x00] (empty), payload=4-byte-len+bytes
  const out = new Uint8Array(1 + 1 + 2 + 4 + encryptedPayload.length);
  const view = new DataView(out.buffer);
  let off = 0;
  out[off++] = ODOH_RESPONSE_TYPE;
  out[off++] = 0x00;             // empty key_id
  view.setUint16(off, 0, false); off += 2; // empty enc
  view.setUint32(off, encryptedPayload.length, false); off += 4;
  out.set(encryptedPayload, off);
  return out;
}

// ── ODoH plaintext encoding ────────────────────────────────────────────────────

function encodeOdohQuery(dnsBytes: Uint8Array): Uint8Array {
  // ObliviousDoHQuery: dns_message (2-byte len prefix) + padding (2-byte len prefix, 0 bytes)
  const out = new Uint8Array(2 + dnsBytes.length + 2);
  const view = new DataView(out.buffer);
  view.setUint16(0, dnsBytes.length, false);
  out.set(dnsBytes, 2);
  view.setUint16(2 + dnsBytes.length, 0, false); // zero-length padding
  return out;
}

function decodeOdohQuery(data: Uint8Array): Uint8Array {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const dnsLen = view.getUint16(0, false);
  if (2 + dnsLen > data.length) throw new Error("ODoH query DNS message truncated");
  return data.slice(2, 2 + dnsLen);
}

function encodeOdohResponse(dnsBytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + dnsBytes.length + 2);
  const view = new DataView(out.buffer);
  view.setUint16(0, dnsBytes.length, false);
  out.set(dnsBytes, 2);
  view.setUint16(2 + dnsBytes.length, 0, false);
  return out;
}

// ── ODoH response encryption (RFC 9230 §4.4) — same HKDF-over-nonce as OHTTP ─

async function encryptOdohResponse(
  exportSecret: Uint8Array,
  enc: Uint8Array,            // from the query's HPKE enc field
  responsePlaintext: Uint8Array,
): Promise<Uint8Array> {
  const responseNonce = crypto.getRandomValues(new Uint8Array(OHTTP_RESPONSE_NONCE_LEN));

  const saltKey = await crypto.subtle.importKey(
    "raw",
    asBufferSource(new Uint8Array([...enc, ...responseNonce])), // salt = enc || response_nonce
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const prk = new Uint8Array(await crypto.subtle.sign("HMAC", saltKey, asBufferSource(exportSecret)));

  const prkKey = await crypto.subtle.importKey(
    "raw", asBufferSource(prk), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );

  const aesKeyBytes = new Uint8Array(
    await crypto.subtle.sign("HMAC", prkKey, new Uint8Array([...new TextEncoder().encode("odoh key"), 0x01])),
  ).slice(0, 32);

  const ivBytes = new Uint8Array(
    await crypto.subtle.sign("HMAC", prkKey, new Uint8Array([...new TextEncoder().encode("odoh nonce"), 0x01])),
  ).slice(0, 12);

  const aesKey = await crypto.subtle.importKey("raw", asBufferSource(aesKeyBytes), { name: "AES-GCM" }, false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asBufferSource(ivBytes) },
    aesKey,
    asBufferSource(responsePlaintext),
  );

  // Wire: response_nonce (32) || ciphertext
  const out = new Uint8Array(OHTTP_RESPONSE_NONCE_LEN + ct.byteLength);
  out.set(responseNonce);
  out.set(new Uint8Array(ct), OHTTP_RESPONSE_NONCE_LEN);
  return out;
}

// ── Main ODoH handler ─────────────────────────────────────────────────────────

export async function handleOdoh(
  bodyBytes: Uint8Array,
  privateKeyJwk: JsonWebKey,
  publicKeyBytes: Uint8Array,
  resolverUrl: string,
): Promise<Response> {
  const msg = parseOdohMessage(bodyBytes);
  if (msg.msgType !== ODOH_QUERY_TYPE) throw new Error("Expected ODoH query");
  if (msg.enc.length !== OHTTP_ENC_LEN) throw new Error("Unexpected enc length");

  // SHA-256 of the key config for the info string
  // (We reuse relay2's HPKE key config — same key used for OHTTP and ODoH)
  const keyConfigHashBuf = await crypto.subtle.digest("SHA-256", asBufferSource(publicKeyBytes)); // simplified: hash just pubkey
  const keyConfigHash = new Uint8Array(keyConfigHashBuf);
  const odohInfo = buildOdohInfo(keyConfigHash);

  const { plaintext, exportSecret } = await hpkeOpen(
    privateKeyJwk, publicKeyBytes, msg.enc, odohInfo, msg.payload, "odoh",
  );

  const dnsQuery = decodeOdohQuery(plaintext);
  if (dnsQuery.length > MAX_DNS_MESSAGE_BYTES) throw new Error("DNS query too large");

  // Forward to the DoH resolver
  const dohResp = await fetch(resolverUrl, {
    method: "POST",
    headers: { "Content-Type": CT_DNS, "Accept": CT_DNS },
    body: asBodyInit(dnsQuery),
  });
  if (!dohResp.ok) throw new Error(`DoH resolver returned ${dohResp.status}`);

  const dnsResponse = new Uint8Array(await dohResp.arrayBuffer());
  if (dnsResponse.length > MAX_DNS_MESSAGE_BYTES) throw new Error("DNS response too large");

  const odohResponsePlaintext = encodeOdohResponse(dnsResponse);
  const encryptedPayload = await encryptOdohResponse(exportSecret, msg.enc, odohResponsePlaintext);
  const responseMsg = buildOdohResponseMessage(encryptedPayload);

  return new Response(asBodyInit(responseMsg), {
    status: 200,
    headers: { "Content-Type": CT_ODOH },
  });
}
