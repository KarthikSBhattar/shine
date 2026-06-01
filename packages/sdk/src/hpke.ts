// HPKE wrapper (RFC 9180) using hpke-js — identical to relay2/src/hpke.ts
// but imported via npm (not Deno npm: specifier) since the SDK targets browsers/Node.
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

export const suite = new CipherSuite({
  kem: KemId.DhkemX25519HkdfSha256,
  kdf: KdfId.HkdfSha256,
  aead: AeadId.Aes256Gcm,
});

export interface HpkeSealResult {
  enc: Uint8Array;
  ciphertext: Uint8Array;
  exportSecret: Uint8Array;
}

const EXPORT_LABEL_OHTTP = new TextEncoder().encode("message/bhttp response");
const EXPORT_LABEL_ODOH  = new TextEncoder().encode("odoh response");

export async function hpkeSeal(
  recipientPublicKeyBytes: Uint8Array,
  info: Uint8Array,
  plaintext: Uint8Array,
  exportLabel: "ohttp" | "odoh" = "ohttp",
): Promise<HpkeSealResult> {
  const recipientPublicKey = await suite.kem.deserializePublicKey(recipientPublicKeyBytes);
  const sender = await suite.createSenderContext({ recipientPublicKey, info });
  const ciphertext = new Uint8Array(await sender.seal(plaintext));
  const label = exportLabel === "ohttp" ? EXPORT_LABEL_OHTTP : EXPORT_LABEL_ODOH;
  const exportSecret = new Uint8Array(await sender.export(label, 32));
  return { enc: new Uint8Array(sender.enc), ciphertext, exportSecret };
}
