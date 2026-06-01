#!/usr/bin/env -S deno run --allow-net --allow-env
/// <reference lib="deno.ns" />

type RelayName = "relay1" | "relay2";

interface TransparencyEntry {
  relay: RelayName;
  url?: string;
  commit?: string;
  hash: string;
  hash_algorithm?: string;
  timestamp?: string;
}

interface RelayTarget {
  relay: RelayName;
  url: string;
}

function requiredEnv(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
}

async function verifyRelay(
  logUrl: string,
  target: RelayTarget,
  expectedCommit?: string,
): Promise<void> {
  const [logResp, healthResp] = await Promise.all([
    fetch(logUrl),
    fetch(`${target.url.replace(/\/$/, "")}/healthz`),
  ]);

  if (!logResp.ok) {
    throw new Error(`Transparency log fetch failed: ${logResp.status}`);
  }
  if (!healthResp.ok) {
    throw new Error(`${target.relay} healthz failed: ${healthResp.status}`);
  }

  const relayHash = ((await healthResp.json()) as { hash?: string }).hash;
  if (!relayHash) {
    throw new Error(`${target.relay} did not expose a healthz hash`);
  }

  const entries = (await logResp.text())
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as TransparencyEntry)
    .filter((entry) =>
      entry.relay === target.relay &&
      entry.url === target.url &&
      entry.hash === relayHash &&
      (expectedCommit === undefined || entry.commit === expectedCommit)
    );

  if (entries.length === 0) {
    throw new Error(
      `${target.relay} hash ${relayHash} is not logged for ${target.url}` +
        (expectedCommit ? ` at commit ${expectedCommit}` : ""),
    );
  }

  const entry = entries[entries.length - 1]!;
  console.log(
    `${target.relay}: verified ${relayHash}` +
      (entry.commit ? ` at ${entry.commit}` : "") +
      (entry.timestamp ? ` (${entry.timestamp})` : ""),
  );
}

const transparencyLogUrl = requiredEnv("SHINE_TRANSPARENCY_LOG_URL");
const expectedCommit = Deno.env.get("SHINE_EXPECTED_COMMIT") || undefined;

await verifyRelay(transparencyLogUrl, {
  relay: "relay1",
  url: Deno.env.get("SHINE_RELAY1_URL") ??
    "https://shine-relay1.ksb6007.workers.dev",
}, expectedCommit);

await verifyRelay(transparencyLogUrl, {
  relay: "relay2",
  url: Deno.env.get("SHINE_RELAY2_URL") ??
    "https://shine-relay2-live.karthiksbhattar.deno.net",
}, expectedCommit);
