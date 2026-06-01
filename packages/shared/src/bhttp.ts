// Binary HTTP encoding/decoding — RFC 9292 §3.1 known-length format
// Varints use QUIC encoding (RFC 9000 §16): 2 MSBs encode byte-width.

export interface BhttpRequest {
  method: string;
  scheme: string;
  authority: string;
  path: string;
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface BhttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

// ── Varint ────────────────────────────────────────────────────────────────────

function encodeVarint(n: number): Uint8Array {
  if (n < 0) throw new RangeError("Varint must be non-negative");
  if (n < 64)        return new Uint8Array([n]);
  if (n < 16384)     return new Uint8Array([0x40 | (n >> 8), n & 0xff]);
  if (n < 1073741824)
    return new Uint8Array([0x80 | (n >>> 24), (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
  throw new RangeError(`Varint value ${n} exceeds 30-bit limit`);
}

function decodeVarint(buf: Uint8Array, offset: number): [value: number, bytesRead: number] {
  if (offset >= buf.length) throw new RangeError("Buffer underflow reading varint");
  const first = buf[offset]!;
  const width = (first >> 6) & 0x03;
  if (width === 0) return [first & 0x3f, 1];
  if (width === 1) {
    if (offset + 1 >= buf.length) throw new RangeError("Buffer underflow (2-byte varint)");
    return [((first & 0x3f) << 8) | buf[offset + 1]!, 2];
  }
  if (width === 2) {
    if (offset + 3 >= buf.length) throw new RangeError("Buffer underflow (4-byte varint)");
    return [
      ((first & 0x3f) << 24) | (buf[offset + 1]! << 16) | (buf[offset + 2]! << 8) | buf[offset + 3]!,
      4,
    ];
  }
  throw new RangeError("8-byte varints not supported");
}

// ── Reader / Writer helpers ───────────────────────────────────────────────────

const ENC = new TextEncoder();
const DEC = new TextDecoder();

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function lenPrefix(bytes: Uint8Array): Uint8Array {
  return concat([encodeVarint(bytes.length), bytes]);
}

function strBytes(s: string): Uint8Array {
  return lenPrefix(ENC.encode(s));
}

class Reader {
  private off = 0;
  constructor(private buf: Uint8Array) {}

  varint(): number {
    const [v, n] = decodeVarint(this.buf, this.off);
    this.off += n;
    return v;
  }

  bytes(n: number): Uint8Array {
    const s = this.buf.slice(this.off, this.off + n);
    if (s.length < n) throw new RangeError("Buffer underflow reading bytes");
    this.off += n;
    return s;
  }

  str(): string {
    return DEC.decode(this.bytes(this.varint()));
  }

  remaining(): Uint8Array {
    return this.buf.slice(this.off);
  }
}

// ── Encode ────────────────────────────────────────────────────────────────────

export function encodeBhttpRequest(req: BhttpRequest): Uint8Array {
  const parts: Uint8Array[] = [
    encodeVarint(0), // framing indicator: known-length request
    strBytes(req.method),
    strBytes(req.scheme),
    strBytes(req.authority),
    strBytes(req.path),
  ];
  for (const [k, v] of Object.entries(req.headers)) {
    parts.push(strBytes(k.toLowerCase()), strBytes(v));
  }
  parts.push(
    encodeVarint(0),                  // end of headers
    lenPrefix(req.body),              // content
    encodeVarint(0),                  // empty trailers
  );
  return concat(parts);
}

export function encodeBhttpResponse(resp: BhttpResponse): Uint8Array {
  const parts: Uint8Array[] = [
    encodeVarint(1), // framing indicator: known-length response
    encodeVarint(resp.status),
  ];
  for (const [k, v] of Object.entries(resp.headers)) {
    parts.push(strBytes(k.toLowerCase()), strBytes(v));
  }
  parts.push(
    encodeVarint(0),            // end of headers
    lenPrefix(resp.body),       // content
    encodeVarint(0),            // empty trailers
  );
  return concat(parts);
}

// ── Decode ────────────────────────────────────────────────────────────────────

export function decodeBhttpRequest(data: Uint8Array): BhttpRequest {
  const r = new Reader(data);

  const fi = r.varint();
  if (fi !== 0) throw new Error(`Expected known-length request (fi=0), got ${fi}`);

  const method    = r.str();
  const scheme    = r.str();
  const authority = r.str();
  const path      = r.str();

  const headers: Record<string, string> = {};
  for (;;) {
    const nameLen = r.varint();
    if (nameLen === 0) break;
    const name  = DEC.decode(r.bytes(nameLen));
    const value = r.str();
    headers[name] = value;
  }

  const bodyLen = r.varint();
  const body    = r.bytes(bodyLen);

  return { method, scheme, authority, path, headers, body };
}

export function decodeBhttpResponse(data: Uint8Array): BhttpResponse {
  const r = new Reader(data);

  const fi = r.varint();
  if (fi !== 1) throw new Error(`Expected known-length response (fi=1), got ${fi}`);

  const status = r.varint();

  const headers: Record<string, string> = {};
  for (;;) {
    const nameLen = r.varint();
    if (nameLen === 0) break;
    const name  = DEC.decode(r.bytes(nameLen));
    const value = r.str();
    headers[name] = value;
  }

  const bodyLen = r.varint();
  const body    = r.bytes(bodyLen);

  return { status, headers, body };
}
