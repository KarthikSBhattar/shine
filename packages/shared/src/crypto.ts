import { SHINE_VERSION } from "./types.ts";

// ECIES: ephemeral P-256 ECDH + HKDF-SHA-256 + AES-256-GCM
// Wire format: [version:1][ephemPub:65][iv:12][ciphertext+tag:N]

const PUBKEY_BYTES = 65; // uncompressed P-256
const IV_BYTES = 12;

export function b64uEncode(buf: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as Uint8Array<ArrayBuffer>;
}

export function asBodyInit(bytes: Uint8Array): BodyInit {
  return bytes as Uint8Array<ArrayBuffer>;
}

export function b64uDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (b64.length % 4)) % 4;
  const bin = atob(b64 + "=".repeat(pad));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveAesKey(
  sharedBits: ArrayBuffer,
  ephemPubBytes: Uint8Array,
  recipientPubBytes: Uint8Array,
  info: string,
): Promise<CryptoKey> {
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    { name: "HKDF" },
    false,
    ["deriveKey"],
  );
  // Salt = SHA-256(ephemPub || recipientPub) — binds key to both parties
  const saltInput = new Uint8Array(
    ephemPubBytes.length + recipientPubBytes.length,
  );
  saltInput.set(ephemPubBytes);
  saltInput.set(recipientPubBytes, ephemPubBytes.length);
  const salt = await crypto.subtle.digest("SHA-256", saltInput);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: new TextEncoder().encode(info),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function eciesEncrypt(
  recipientPublicKeyBytes: Uint8Array,
  plaintext: Uint8Array,
  info: string,
): Promise<Uint8Array> {
  const recipientKey = await crypto.subtle.importKey(
    "raw",
    asBufferSource(recipientPublicKeyBytes),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const ephemKp = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const ephemPubBytes = new Uint8Array(
    await crypto.subtle.exportKey("raw", ephemKp.publicKey),
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: recipientKey },
    ephemKp.privateKey,
    256,
  );
  const aesKey = await deriveAesKey(
    sharedBits,
    ephemPubBytes,
    recipientPublicKeyBytes,
    info,
  );
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asBufferSource(iv) },
    aesKey,
    asBufferSource(plaintext),
  );
  const out = new Uint8Array(
    1 + PUBKEY_BYTES + IV_BYTES + ciphertext.byteLength,
  );
  let off = 0;
  out[off++] = SHINE_VERSION;
  out.set(ephemPubBytes, off);
  off += PUBKEY_BYTES;
  out.set(iv, off);
  off += IV_BYTES;
  out.set(new Uint8Array(ciphertext), off);
  return out;
}

export async function eciesDecrypt(
  privateKey: CryptoKey,
  ownPublicKeyBytes: Uint8Array,
  data: Uint8Array,
  info: string,
): Promise<Uint8Array> {
  if (data.length < 1 + PUBKEY_BYTES + IV_BYTES + 16) {
    throw new Error("Ciphertext too short");
  }
  let off = 0;
  const version = data[off++];
  if (version !== SHINE_VERSION) throw new Error(`Unsupported version: ${version}`);
  const ephemPubBytes = data.slice(off, off + PUBKEY_BYTES);
  off += PUBKEY_BYTES;
  const iv = data.slice(off, off + IV_BYTES);
  off += IV_BYTES;
  const encryptedData = data.slice(off);
  const ephemKey = await crypto.subtle.importKey(
    "raw",
    asBufferSource(ephemPubBytes),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: ephemKey },
    privateKey,
    256,
  );
  const aesKey = await deriveAesKey(
    sharedBits,
    ephemPubBytes,
    ownPublicKeyBytes,
    info,
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asBufferSource(iv) },
    aesKey,
    asBufferSource(encryptedData),
  );
  return new Uint8Array(plaintext);
}

export async function generateKeyPair(): Promise<{
  privateKeyJwk: JsonWebKey;
  publicKeyRaw: string; // base64url
}> {
  const kp = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const privateKeyJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pubBytes = new Uint8Array(
    await crypto.subtle.exportKey("raw", kp.publicKey),
  );
  return { privateKeyJwk, publicKeyRaw: b64uEncode(pubBytes) };
}

export async function hmacSign(
  secret: string,
  timestamp: string,
  body: Uint8Array,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const bodyHash = await crypto.subtle.digest("SHA-256", asBufferSource(body));
  const msg = new TextEncoder().encode(timestamp + ":");
  const combined = new Uint8Array(msg.length + bodyHash.byteLength);
  combined.set(msg);
  combined.set(new Uint8Array(bodyHash), msg.length);
  const sig = await crypto.subtle.sign("HMAC", key, combined);
  return b64uEncode(new Uint8Array(sig));
}

export async function hmacVerify(
  secret: string,
  timestamp: string,
  providedHmac: string,
  body: Uint8Array,
): Promise<void> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const bodyHash = await crypto.subtle.digest("SHA-256", asBufferSource(body));
  const msg = new TextEncoder().encode(timestamp + ":");
  const combined = new Uint8Array(msg.length + bodyHash.byteLength);
  combined.set(msg);
  combined.set(new Uint8Array(bodyHash), msg.length);
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    asBufferSource(b64uDecode(providedHmac)),
    asBufferSource(combined),
  );
  if (!valid) throw new Error("HMAC verification failed");
}
