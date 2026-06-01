import relay1Worker from "../packages/relay1/src/index.ts";
import { generateKeyPair, b64uEncode } from "../packages/shared/src/crypto.ts";
import { shineRequest } from "../packages/sdk/src/client.ts";

type Relay2Handler = (request: Request) => Promise<Response> | Response;

function randomSecret(): string {
  return b64uEncode(crypto.getRandomValues(new Uint8Array(32)));
}

async function main(): Promise<void> {
  const relay1Keys = await generateKeyPair();
  const relay2Keys = await generateKeyPair();
  const relay2HmacSecret = randomSecret();
  const issuerSecret = randomSecret();

  let relay2Handler: Relay2Handler | undefined;
  const relay2Env = new Map<string, string>([
    ["RELAY2_PRIVATE_KEY_JWK", JSON.stringify(relay2Keys.privateKeyJwk)],
    ["RELAY2_PUBLIC_KEY_RAW", relay2Keys.publicKeyRaw],
    ["RELAY2_HPKE_PRIVATE_KEY_JWK", JSON.stringify(relay2Keys.privateKeyJwk)],
    ["RELAY2_HPKE_PUBLIC_KEY_RAW", relay2Keys.publicKeyRaw],
    ["RELAY2_HMAC_SECRET", relay2HmacSecret],
    ["BUNDLE_HASH", "local-test"],
  ]);

  const nativeFetch = globalThis.fetch.bind(globalThis);
  const originalDeno = (globalThis as typeof globalThis & { Deno?: unknown }).Deno;

  (globalThis as typeof globalThis & { Deno: unknown }).Deno = {
    env: {
      get(name: string): string | undefined {
        return relay2Env.get(name);
      },
    },
    serve(handler: Relay2Handler): { shutdown(): void } {
      relay2Handler = handler;
      return { shutdown() {} };
    },
  };

  const relay1Env = {
    RELAY1_PRIVATE_KEY_JWK: JSON.stringify(relay1Keys.privateKeyJwk),
    RELAY1_PUBLIC_KEY_RAW: relay1Keys.publicKeyRaw,
    RELAY2_URL: "https://relay2.local",
    RELAY2_HMAC_SECRET: relay2HmacSecret,
    ISSUER_SECRET: issuerSecret,
    ISSUER_URL: "https://issuer.local",
    REQUIRE_TOKEN: "false",
    TOKEN_MODE: "any",
    BUNDLE_HASH: "local-test",
  };

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);

    if (url.hostname === "relay1.local") {
      return relay1Worker.fetch(request, relay1Env);
    }

    if (url.hostname === "relay2.local") {
      if (!relay2Handler) throw new Error("relay2 handler was not registered");
      return relay2Handler(request);
    }

    if (url.hostname === "origin.example") {
      const body = JSON.stringify({
        ok: true,
        method: request.method,
        path: url.pathname + url.search,
        secretHeaderWasStripped: !request.headers.has("authorization"),
      });
      return new Response(body, {
        status: 200,
        headers: {
          "content-type": "application/json",
          "cache-control": "no-store",
        },
      });
    }

    return nativeFetch(request);
  };

  try {
    await import("../packages/relay2/src/main.ts");
    if (!relay2Handler) throw new Error("relay2 did not register a handler");

    const response = await shineRequest(
      {
        relay1Url: "https://relay1.local",
        relay2Url: "https://relay2.local",
        relay1PublicKey: relay1Keys.publicKeyRaw,
        relay2PublicKey: relay2Keys.publicKeyRaw,
      },
      "https://origin.example/private-relay-smoke?via=shine",
      {
        method: "GET",
        headers: {
          authorization: "Bearer should-not-reach-origin",
          "x-test": "local",
        },
      },
    );

    const text = new TextDecoder().decode(response.body);
    const payload = JSON.parse(text) as {
      ok: boolean;
      method: string;
      path: string;
      secretHeaderWasStripped: boolean;
    };

    if (response.status !== 200) throw new Error(`expected HTTP 200, got ${response.status}`);
    if (!payload.ok) throw new Error("origin payload did not report ok");
    if (payload.method !== "GET") throw new Error(`origin saw ${payload.method}, expected GET`);
    if (payload.path !== "/private-relay-smoke?via=shine") {
      throw new Error(`origin saw unexpected path: ${payload.path}`);
    }
    if (!payload.secretHeaderWasStripped) {
      throw new Error("origin received an identifying Authorization header");
    }

    console.log("local relay smoke test passed");
    console.log(`status=${response.status} body=${text}`);
  } finally {
    globalThis.fetch = nativeFetch;
    (globalThis as typeof globalThis & { Deno?: unknown }).Deno = originalDeno;
  }
}

await main();
