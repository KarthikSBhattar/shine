// WebRTC privacy configuration for the Sunny browser.
//
// This module provides two things:
//   1. Real TURN credentials from the Shine issuer (WebRTC actually works)
//   2. iceTransportPolicy:"relay" enforcement (no local/STUN IP leaks)
//
// Architecture:
//   Browser ←─ ICE/TURN ─→ Shine TURN (Fly.io/coturn)
//                                │
//                         routes media to peers
//
// The TURN server uses a dedicated Fly.io IP — remote peers only see that IP,
// never the user's real IP. The TURN server itself egresses directly (not through
// relay1/relay2) because media relay through a privacy chain would add unacceptable
// latency. The privacy property here is: remote peers don't learn your IP.

export interface TurnCredentials {
  username: string;
  password: string;
  urls: string[];
  ttl: number;
}

export interface ShineRtcConfig {
  issuerUrl: string;   // e.g. "https://shine-issuer.workers.dev"
  authToken: string;   // bearer token for issuer (from obtainBlindToken or issueToken)
  identifier?: string; // optional per-user label (not used for tracking — issuer is blind)
}

// Fetches time-limited TURN credentials from the issuer and returns an
// RTCConfiguration that enforces relay-only ICE (no local/STUN IP leaks).
export async function getShineTurnConfig(config: ShineRtcConfig): Promise<RTCConfiguration> {
  const creds = await fetchTurnCredentials(config);
  return buildRtcConfig(creds);
}

export async function fetchTurnCredentials(config: ShineRtcConfig): Promise<TurnCredentials> {
  const resp = await fetch(`${config.issuerUrl}/turn-credentials`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${config.authToken}`,
    },
    body: JSON.stringify({ identifier: config.identifier ?? "anon" }),
  });
  if (!resp.ok) throw new Error(`Failed to fetch TURN credentials: ${resp.status}`);
  return resp.json() as Promise<TurnCredentials>;
}

export function buildRtcConfig(creds: TurnCredentials): RTCConfiguration {
  return {
    // relay-only: no host candidates (hides LAN IP), no STUN-derived candidates
    // (hides public IP from peers). Requires TURN to succeed for calls to work.
    iceTransportPolicy: "relay",
    iceServers: [
      {
        urls: creds.urls,
        username: creds.username,
        credential: creds.password,
      },
    ],
    // Reduce ICE gathering time for relay-only scenarios
    iceCandidatePoolSize: 2,
  };
}

// Patches the global RTCPeerConnection so every peer connection in this page
// uses Shine TURN — defense-in-depth for apps that create connections directly.
// Call once at browser startup before any WebRTC code runs.
//
// Note: this is NOT a complete substitute for proper RTCConfiguration in each
// RTCPeerConnection() call. Some browsers and frameworks bypass global patches.
// Always also pass the config explicitly where possible.
let _patched = false;

export async function enforceShineWebRtc(config: ShineRtcConfig): Promise<void> {
  if (_patched || typeof globalThis.RTCPeerConnection === "undefined") return;
  _patched = true;

  const shineRtcConfig = await getShineTurnConfig(config);
  const Original = globalThis.RTCPeerConnection;

  globalThis.RTCPeerConnection = class ShineRTCPeerConnection extends Original {
    constructor(pcConfig?: RTCConfiguration) {
      // Merge caller's ice servers AFTER Shine's — Shine TURN takes priority
      super({
        ...pcConfig,
        iceTransportPolicy: "relay",
        iceServers: [
          ...shineRtcConfig.iceServers!,
          ...(pcConfig?.iceServers ?? []),
        ],
      });
    }
  } as typeof RTCPeerConnection;
}

// Checks whether the current RTCConfiguration will expose the user's real IP.
// Returns an array of warning strings; empty array means the config is safe.
export function auditRtcConfig(config: RTCConfiguration): string[] {
  const warnings: string[] = [];
  if (config.iceTransportPolicy !== "relay") {
    warnings.push(
      `iceTransportPolicy is "${config.iceTransportPolicy ?? "all"}" — host and STUN candidates will expose your real IP`,
    );
  }
  if (!config.iceServers?.length) {
    warnings.push("No ICE servers configured — relay-only mode will fail");
  }
  return warnings;
}
