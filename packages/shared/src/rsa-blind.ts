// RSA Blind Signature primitives (RFC 9474 / RFC 8017).
// Used by the issuer (blind signing) and SDK (blinding/unblinding).
// relay1 verification uses only Web Crypto — no BigInt needed there.
//
// All operations are constant-time within BigInt's own arithmetic.
// BigInt in V8 uses optimized multi-precision arithmetic.
import { asBufferSource } from "./crypto.ts";

// ── Byte ↔ BigInt conversions ─────────────────────────────────────────────────

export function os2ip(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = 0; i < bytes.length; i++) {
    n = (n << 8n) | BigInt(bytes[i]!);
  }
  return n;
}

export function i2osp(n: bigint, len: number): Uint8Array {
  if (n < 0n) throw new RangeError("i2osp: negative value");
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new RangeError("i2osp: value too large for requested length");
  return out;
}

// ── Modular arithmetic ────────────────────────────────────────────────────────

export function modExp(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = result * base % mod;
    exp >>= 1n;
    base = base * base % mod;
  }
  return result;
}

// Extended Euclidean algorithm — modular inverse.
// Returns x such that a*x ≡ 1 (mod n). Throws if gcd(a,n) ≠ 1.
export function modInverse(a: bigint, n: bigint): bigint {
  let [old_r, r] = [a, n];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error("modInverse: inputs are not coprime");
  return ((old_s % n) + n) % n;
}

// Positive modulo (JS BigInt % can be negative, like C)
function posMod(a: bigint, m: bigint): bigint {
  return ((a % m) + m) % m;
}

// ── MGF1 with SHA-256 (RFC 8017 Appendix B.2.1) ───────────────────────────────

export async function mgf1Sha256(seed: Uint8Array, maskLen: number): Promise<Uint8Array> {
  const hLen = 32; // SHA-256 output
  const blocks = Math.ceil(maskLen / hLen);
  const mask = new Uint8Array(maskLen);
  for (let i = 0; i < blocks; i++) {
    const counter = new Uint8Array([i >>> 24, (i >>> 16) & 0xff, (i >>> 8) & 0xff, i & 0xff]);
    const combined = new Uint8Array(seed.length + 4);
    combined.set(seed);
    combined.set(counter, seed.length);
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", asBufferSource(combined)));
    const start = i * hLen;
    const end = Math.min(start + hLen, maskLen);
    mask.set(hash.slice(0, end - start), start);
  }
  return mask;
}

// ── EMSA-PSS-ENCODE (RFC 8017 §9.1.1) ────────────────────────────────────────
// For RSA-2048: emBits=2047, emLen=256, hLen=32, sLen=32
// The produced EM is 256 bytes and passes PSS-VERIFY when sig = EM^d mod n.

export async function emsaPssEncode(
  msg: Uint8Array,
  emBits: number,
  sLen: number,
): Promise<Uint8Array> {
  const hLen = 32; // SHA-256
  const emLen = Math.ceil(emBits / 8);
  if (emLen < hLen + sLen + 2) throw new Error("EMSA-PSS: emLen too small");

  const mHash = new Uint8Array(await crypto.subtle.digest("SHA-256", asBufferSource(msg)));
  const salt = crypto.getRandomValues(new Uint8Array(sLen));

  // M' = 0x00×8 || mHash || salt
  const mPrime = new Uint8Array(8 + hLen + sLen);
  mPrime.set(mHash, 8);
  mPrime.set(salt, 8 + hLen);
  const H = new Uint8Array(await crypto.subtle.digest("SHA-256", asBufferSource(mPrime)));

  // DB = PS || 0x01 || salt, where PS is (emLen - sLen - hLen - 2) zero bytes
  const psLen = emLen - sLen - hLen - 2;
  const DB = new Uint8Array(psLen + 1 + sLen);
  DB[psLen] = 0x01;
  DB.set(salt, psLen + 1);

  const dbMask = await mgf1Sha256(H, emLen - hLen - 1);
  const maskedDB = new Uint8Array(DB.length);
  for (let i = 0; i < DB.length; i++) maskedDB[i] = DB[i]! ^ dbMask[i]!;

  // Zero the leftmost (8*emLen - emBits) bits of maskedDB[0]
  // For emBits=2047: 8*256 - 2047 = 1 bit to zero
  const bitsToZero = 8 * emLen - emBits;
  // Cannot use compound assignment on a non-null asserted index (not a valid lvalue in TS)
  maskedDB[0] = (maskedDB[0] ?? 0) & (0xff >> bitsToZero);

  // EM = maskedDB || H || 0xbc
  const EM = new Uint8Array(emLen);
  EM.set(maskedDB);
  EM.set(H, maskedDB.length);
  EM[emLen - 1] = 0xbc;
  return EM;
}

// ── Client-side blinding and unblinding ───────────────────────────────────────

export interface BlindResult {
  blindMsg: Uint8Array;  // 256 bytes — send to issuer
  r: bigint;             // blinding factor — keep in memory, never send
}

// Encodes msg with PSS, then blinds the result with a random r.
// n and e come from the issuer's RSA-2048 JWK.
export async function rsaBlind(
  msg: Uint8Array,
  e: bigint,
  n: bigint,
): Promise<BlindResult> {
  const emBits = 2047; // RSA-2048: modBits-1
  const sLen = 32;
  const emLen = 256;

  const em = await emsaPssEncode(msg, emBits, sLen);
  const m = os2ip(em);

  // Generate r in Z_n^* — random value coprime to n.
  // For RSA-2048, P(random 2048-bit value NOT coprime to n) ≈ 2^{-1023}: negligible.
  let r: bigint;
  let blindMsg: bigint;
  for (;;) {
    const rBytes = crypto.getRandomValues(new Uint8Array(emLen));
    r = os2ip(rBytes) % n;
    if (r <= 0n) continue;
    try {
      // verify coprimality via modular inverse
      modInverse(r, n);
    } catch {
      continue; // astronomically unlikely but correct to retry
    }
    blindMsg = m * modExp(r, e, n) % n;
    break;
  }

  return { blindMsg: i2osp(blindMsg!, emLen), r: r! };
}

// Unblinds the issuer's raw signature to recover a standard RSA-PSS signature.
export function rsaUnblind(blindSigBytes: Uint8Array, r: bigint, n: bigint): Uint8Array {
  const emLen = 256;
  const z = os2ip(blindSigBytes);
  const rInv = modInverse(r, n);
  const sig = z * rInv % n;
  return i2osp(sig, emLen);
}

// ── Issuer-side blind signing using CRT (from JWK private key fields) ─────────

export interface RsaPrivateKey {
  n: bigint; e: bigint; d: bigint;
  p: bigint; q: bigint;
  dp: bigint; dq: bigint; qi: bigint;
}

// Extracts BigInt components from an RSA JWK (fields are base64url-encoded big-endian integers).
export function extractRsaKey(jwk: JsonWebKey): RsaPrivateKey {
  const dec = (field: string | undefined): bigint => {
    if (!field) throw new Error(`Missing JWK field`);
    const b64 = field.replace(/-/g, "+").replace(/_/g, "/");
    const pad = (4 - (b64.length % 4)) % 4;
    const bin = atob(b64 + "=".repeat(pad));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return os2ip(bytes);
  };
  return {
    n:  dec(jwk.n),  e:  dec(jwk.e),  d:  dec(jwk.d),
    p:  dec(jwk.p),  q:  dec(jwk.q),
    dp: dec(jwk.dp), dq: dec(jwk.dq), qi: dec(jwk.qi),
  };
}

// Raw RSA private-key operation using CRT — computes blindMsg^d mod n.
// CRT is ~4× faster than naive modExp(x, d, n) for RSA-2048.
export function rsaBlindSign(blindMsgBytes: Uint8Array, key: RsaPrivateKey): Uint8Array {
  const { n, p, q, dp, dq, qi } = key;
  const x = os2ip(blindMsgBytes) % n;
  const m1 = modExp(x % p, dp, p);
  const m2 = modExp(x % q, dq, q);
  // CRT recombination — avoid negative intermediate via posMod
  const h = posMod(qi * posMod(m1 - m2, p), p);
  const sig = m2 + q * h;
  return i2osp(sig, 256);
}
