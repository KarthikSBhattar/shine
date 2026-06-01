// ── Legacy ECIES protocol ─────────────────────────────────────────────────────
export { shineRequest, verifyRelayIntegrity } from "./client.ts";
export type { ShineConfig, ShineRequestInit, ShineResponse } from "./client.ts";

// ── OHTTP + ODoH (preferred for new clients) ──────────────────────────────────
export { ohttpRequest, odohQuery, parseOhttpKeyConfig } from "./ohttp-client.ts";
export type {
  OhttpClientConfig,
  OhttpResponse,
  OdohClientConfig,
  OhttpKeyConfig,
} from "./ohttp-client.ts";

// ── RSA blind tokens (unlinkable issuance) ────────────────────────────────────
export { obtainBlindToken, fetchIssuerPublicKey, parseBlindToken } from "./blind-token.ts";
export type { BlindTokenConfig, BlindTokenParts } from "./blind-token.ts";

// ── TCP tunnel via WebSocket ──────────────────────────────────────────────────
export { openTunnel } from "./tunnel.ts";
export type { TunnelConfig } from "./tunnel.ts";

// ── WebRTC IP leak prevention (with real TURN credentials) ───────────────────
export {
  getShineTurnConfig,
  fetchTurnCredentials,
  buildRtcConfig,
  enforceShineWebRtc,
  auditRtcConfig,
} from "./webrtc.ts";
export type { ShineRtcConfig, TurnCredentials } from "./webrtc.ts";
