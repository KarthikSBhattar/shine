import {
  eciesEncrypt,
  b64uEncode,
  b64uDecode,
  asBodyInit,
  asBufferSource,
} from "../../shared/src/crypto.ts";
import { pad } from "../../shared/src/padding.ts";
import {
  OuterEnvelope,
  InnerEnvelope,
  EncryptedResponse,
  SHINE_VERSION,
} from "../../shared/src/types.ts";

export interface ShineConfig {
  relay1Url: string;
  relay2Url: string;
  relay1PublicKey: string; // base64url uncompressed P-256
  relay2PublicKey: string; // base64url uncompressed P-256
}

export interface ShineRequestInit {
  method?: string;
  headers?: Record<string, string>;
  body?: ArrayBuffer | string;
}

export interface ShineResponse {
  status: number;
  headers: Record<string, string>;
  body: ArrayBuffer;
}

export async function shineRequest(
  config: ShineConfig,
  destination: string,
  init: ShineRequestInit = {},
): Promise<ShineResponse> {
  const method = (init.method ?? "GET").toUpperCase();

  let bodyEncoded: string | null = null;
  if (init.body !== undefined) {
    const bytes =
      typeof init.body === "string"
        ? new TextEncoder().encode(init.body)
        : new Uint8Array(init.body);
    bodyEncoded = b64uEncode(bytes);
  }

  // Per-request symmetric key — relay2 uses it to encrypt the response.
  // Only this client ever holds it; relay1 never sees it.
  const responseKeyBytes = crypto.getRandomValues(new Uint8Array(32));
  const responseKey = b64uEncode(responseKeyBytes);

  const inner: InnerEnvelope = {
    destination,
    method,
    headers: init.headers ?? {},
    body: bodyEncoded,
    responseKey,
    nonce: b64uEncode(crypto.getRandomValues(new Uint8Array(16))),
    timestamp: Date.now(),
  };

  const relay2PubBytes = b64uDecode(config.relay2PublicKey);
  const innerJson = new TextEncoder().encode(JSON.stringify(inner));
  const innerCiphertext = await eciesEncrypt(
    relay2PubBytes,
    pad(innerJson),
    "shine-relay2-v1",
  );

  const outer: OuterEnvelope = {
    version: SHINE_VERSION,
    relay2Url: config.relay2Url,
    innerCiphertext: b64uEncode(innerCiphertext),
    nonce: b64uEncode(crypto.getRandomValues(new Uint8Array(16))),
    timestamp: Date.now(),
  };

  const relay1PubBytes = b64uDecode(config.relay1PublicKey);
  const outerJson = new TextEncoder().encode(JSON.stringify(outer));
  const outerCiphertext = await eciesEncrypt(
    relay1PubBytes,
    pad(outerJson),
    "shine-relay1-v1",
  );

  const httpResp = await fetch(`${config.relay1Url}/relay`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: asBodyInit(outerCiphertext),
  });

  if (!httpResp.ok) {
    throw new Error(`Shine relay error: HTTP ${httpResp.status}`);
  }

  const encrypted: EncryptedResponse = await httpResp.json();

  const aesKey = await crypto.subtle.importKey(
    "raw",
    asBufferSource(responseKeyBytes),
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  const iv = b64uDecode(encrypted.iv);
  const cipherBody = b64uDecode(encrypted.body);

  const plainBody = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asBufferSource(iv) },
    aesKey,
    asBufferSource(cipherBody),
  );

  return {
    status: encrypted.status,
    headers: encrypted.headers,
    body: plainBody,
  };
}

// Verify relay integrity against the public transparency log, NOT against the
// relay itself. Asking the relay "what hash are you?" is circular — a compromised
// relay returns whatever hash you expect.
//
// transparencyLogUrl: raw URL to the transparency-log.jsonl file
//   e.g. "https://raw.githubusercontent.com/org/shine/transparency-log/transparency-log.jsonl"
// relay: "relay1" | "relay2"
// expectedCommit: the git SHA the Sunny browser was built against
export async function verifyRelayIntegrity(opts: {
  transparencyLogUrl: string;
  relay: "relay1" | "relay2";
  expectedCommit?: string;
  expectedHash?: string;
  relayUrl?: string;
  relayHealthzUrl: string;
}): Promise<{ logHash: string; relayHash: string }> {
  const [logResp, healthzResp] = await Promise.all([
    fetch(opts.transparencyLogUrl),
    fetch(opts.relayHealthzUrl),
  ]);

  if (!logResp.ok) throw new Error(`Transparency log fetch failed: ${logResp.status}`);
  if (!healthzResp.ok) throw new Error(`Relay healthz failed: ${healthzResp.status}`);

  const logText = await logResp.text();
  const healthz = (await healthzResp.json()) as { hash: string };

  if (!opts.expectedCommit && !opts.expectedHash && !opts.relayUrl) {
    throw new Error("Expected at least one of expectedCommit, expectedHash, or relayUrl");
  }

  // Find the most recent log entry matching the caller's trust anchor.
  const entries = logText
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as { relay: string; commit: string; hash: string })
    .filter((e) => {
      const withOptionalUrl = e as { url?: string };
      return e.relay === opts.relay &&
        (opts.expectedCommit === undefined || e.commit === opts.expectedCommit) &&
        (opts.expectedHash === undefined || e.hash === opts.expectedHash) &&
        (opts.relayUrl === undefined || withOptionalUrl.url === opts.relayUrl);
    });

  if (entries.length === 0) {
    throw new Error(`No matching transparency log entry found for ${opts.relay}`);
  }

  const logHash = entries[entries.length - 1]!.hash;
  const relayHash = healthz.hash;

  if (logHash !== relayHash) {
    throw new Error(
      `Relay hash mismatch for ${opts.relay}: log=${logHash} relay=${relayHash}`,
    );
  }

  return { logHash, relayHash };
}
