import { PADDING_BLOCK_SIZE } from "./types.ts";

// Format: [length: 4 bytes big-endian][payload][random padding to next block boundary]

export function pad(data: Uint8Array): Uint8Array {
  const headerSize = 4;
  const totalMin = headerSize + data.length;
  const paddedSize =
    Math.ceil(totalMin / PADDING_BLOCK_SIZE) * PADDING_BLOCK_SIZE;
  const result = new Uint8Array(paddedSize);
  new DataView(result.buffer).setUint32(0, data.length, false);
  result.set(data, headerSize);
  const paddingStart = headerSize + data.length;
  if (paddingStart < paddedSize) {
    crypto.getRandomValues(result.subarray(paddingStart));
  }
  return result;
}

export function unpad(padded: Uint8Array): Uint8Array {
  if (padded.length < 4) throw new Error("Padded buffer too short");
  const dataLen = new DataView(
    padded.buffer,
    padded.byteOffset,
    padded.byteLength,
  ).getUint32(0, false);
  if (dataLen + 4 > padded.length) {
    throw new Error("Padding length field exceeds buffer");
  }
  return padded.slice(4, 4 + dataLen);
}
