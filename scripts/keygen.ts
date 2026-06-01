#!/usr/bin/env -S deno run --allow-env

function b64uEncode(buf: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function genEcdhKeys(name: string): Promise<void> {
  const kp = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"],
  );
  const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub  = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  console.log(`\n# ${name} P-256 key pair (legacy ECIES protocol)`);
  console.log(`${name}_PRIVATE_KEY_JWK='${JSON.stringify(priv)}'`);
  console.log(`${name}_PUBLIC_KEY_RAW='${b64uEncode(pub)}'`);
}

async function genHpkeKeys(name: string): Promise<void> {
  // X25519 key pair for OHTTP/ODoH (RFC 9458 / RFC 9230)
  const kp = await crypto.subtle.generateKey(
    { name: "X25519" } as AlgorithmIdentifier, true, ["deriveBits"] as KeyUsage[],
  );
  const priv = await crypto.subtle.exportKey("jwk", (kp as CryptoKeyPair).privateKey);
  const pub  = new Uint8Array(
    await crypto.subtle.exportKey("raw", (kp as CryptoKeyPair).publicKey),
  );
  console.log(`\n# ${name} X25519 key pair (OHTTP / ODoH)`);
  console.log(`${name}_HPKE_PRIVATE_KEY_JWK='${JSON.stringify(priv)}'`);
  console.log(`${name}_HPKE_PUBLIC_KEY_RAW='${b64uEncode(pub)}'`);
}

async function genSecret(name: string, label: string): Promise<void> {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  console.log(`\n# ${label}`);
  console.log(`${name}='${b64uEncode(secret)}'`);
}

async function genRsaKeys(): Promise<void> {
  // RSA-2048 with SHA-256 for blind signatures (RFC 9474)
  const kp = await crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pubJwk  = await crypto.subtle.exportKey("jwk", kp.publicKey);
  console.log(`\n# Issuer RSA-2048 key pair (blind token signing, RFC 9474)`);
  console.log(`ISSUER_RSA_PRIVATE_KEY_JWK='${JSON.stringify(privJwk)}'`);
  console.log(`\n# Public key — bake into Sunny browser build, not secret:`);
  console.log(`ISSUER_RSA_PUBLIC_KEY_JWK='${JSON.stringify(pubJwk)}'`);
}

console.log("# Shine key material — store each as a secret in your deployment environment");
console.log("# NEVER commit these to version control\n");

await genEcdhKeys("RELAY1");
await genEcdhKeys("RELAY2");
await genHpkeKeys("RELAY2");
await genRsaKeys();
await genSecret("RELAY2_HMAC_SECRET",  "Relay1 → Relay2 authentication");
await genSecret("ISSUER_SECRET",       "Token issuer ↔ relay1 shared secret (HMAC tokens)");
await genSecret("TURN_SHARED_SECRET",  "Issuer ↔ TURN server shared secret (HMAC-SHA1 credentials)");

console.log(`
# TURN server deployment:
#   cd packages/turn
#   fly launch --no-deploy
#   fly ips allocate-v4              (dedicated IP for relay addresses)
#   fly secrets set TURN_SHARED_SECRET='<value above>'
#   fly deploy
#   fly ips list                     (note the IPv4 — update TURN_SERVER_HOST in issuer wrangler.toml)
#
# Deployment checklist:
#
# CF Worker (relay1) secrets:
#   wrangler secret put RELAY1_PRIVATE_KEY_JWK
#   wrangler secret put RELAY1_PUBLIC_KEY_RAW
#   wrangler secret put RELAY2_HMAC_SECRET
#   wrangler secret put ISSUER_SECRET
#
# CF Worker (issuer) secrets:
#   wrangler secret put ISSUER_SECRET        (same value as relay1's)
#   wrangler secret put AUTH_KEYS            (newline-separated bearer tokens)
#
# Deno Deploy (relay2) env vars:
#   RELAY2_PRIVATE_KEY_JWK   RELAY2_PUBLIC_KEY_RAW
#   RELAY2_HPKE_PRIVATE_KEY_JWK  RELAY2_HPKE_PUBLIC_KEY_RAW
#   RELAY2_HMAC_SECRET
#   ODOH_RESOLVER_URL  (default: https://1.1.1.1/dns-query)
#
# Bake into the Sunny browser build (not secret):
#   RELAY1_PUBLIC_KEY_RAW       — for legacy ECIES
#   RELAY2_PUBLIC_KEY_RAW       — for legacy ECIES
#   RELAY2_HPKE_PUBLIC_KEY_RAW  — for OHTTP / ODoH
`);
