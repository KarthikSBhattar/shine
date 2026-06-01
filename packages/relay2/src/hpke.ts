// HPKE wrapper (RFC 9180) using hpke-js.
// Suite: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

export const suite = new CipherSuite({
  kem: KemId.DhkemX25519HkdfSha256,
  kdf: KdfId.HkdfSha256,
  aead: AeadId.Aes256Gcm,
});

export interface HpkeSealResult {
  enc: Uint8Array;         // ephemeral public key (32 bytes for X25519)
  ciphertext: Uint8Array;  // AEAD ciphertext + tag
  exportSecret: Uint8Array; // 32-byte export for response key derivation
}

export interface HpkeOpenResult {
  plaintext: Uint8Array;
  exportSecret: Uint8Array; // same derivation as sender's export
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

export async function hpkeOpen(
  recipientPrivateKeyJwk: JsonWebKey,
  recipientPublicKeyBytes: Uint8Array,
  enc: Uint8Array,
  info: Uint8Array,
  ciphertext: Uint8Array,
  exportLabel: "ohttp" | "odoh" = "ohttp",
): Promise<HpkeOpenResult> {
  const privateKey = await suite.kem.importKey("jwk", recipientPrivateKeyJwk, false);
  const publicKey  = await suite.kem.deserializePublicKey(recipientPublicKeyBytes);
  const recipient  = await suite.createRecipientContext({
    recipientKey: { privateKey, publicKey },
    enc,
    info,
  });
  const plaintext = new Uint8Array(await recipient.open(ciphertext));
  const label = exportLabel === "ohttp" ? EXPORT_LABEL_OHTTP : EXPORT_LABEL_ODOH;
  const exportSecret = new Uint8Array(await recipient.export(label, 32));
  return { plaintext, exportSecret };
}

// Serialize the relay2 X25519 public key for the OHTTP Key Config.
export async function serializePublicKey(jwk: JsonWebKey): Promise<Uint8Array> {
  const key = await suite.kem.importKey("jwk", jwk, true);
  return new Uint8Array(await suite.kem.serializePublicKey(key));
}
