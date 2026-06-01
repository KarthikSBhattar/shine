import {
  MAX_DESTINATION_URL_LENGTH,
} from "../../shared/src/types.ts";

// SSRF protection: block private, loopback, link-local, and cloud-metadata addresses.
// NOTE: DNS rebinding is not mitigated here — we validate the URL hostname, not the
// resolved IP. Full protection would require post-resolution IP checks, which are not
// available in a serverless environment. This is a known accepted limitation.

const BLOCKED_HOSTNAMES: ReadonlySet<string> = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata.internal",
  // AWS/Alibaba metadata
  "169.254.169.254",
  "100.100.100.200",
]);

const BLOCKED_IPV4_PREFIXES: ReadonlyArray<RegExp> = [
  /^0\./,                          // 0.0.0.0/8
  /^10\./,                         // 10.0.0.0/8 private
  /^127\./,                        // 127.0.0.0/8 loopback
  /^169\.254\./,                   // 169.254.0.0/16 link-local / cloud metadata
  /^172\.(1[6-9]|2\d|3[01])\./,   // 172.16.0.0/12 private
  /^192\.168\./,                   // 192.168.0.0/16 private
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // 100.64.0.0/10 shared address space
  /^192\.0\.2\./,                  // TEST-NET-1
  /^198\.51\.100\./,               // TEST-NET-2
  /^203\.0\.113\./,                // TEST-NET-3
  /^240\./,                        // Reserved
  /^255\.255\.255\.255$/,          // Broadcast
];

const BLOCKED_IPV6_PREFIXES: ReadonlyArray<RegExp> = [
  /^::1$/,             // loopback
  /^::$/,              // unspecified
  /^fc[0-9a-f]{2}:/i, // fc00::/7 unique local
  /^fd[0-9a-f]{2}:/i,
  /^fe80:/i,           // fe80::/10 link-local
  /^::ffff:/i,         // IPv4-mapped — the mapped address still gets caught by IPv4 rules above
  /^64:ff9b:/i,        // NAT64
];

const TUNNEL_BLOCKED_PORTS: ReadonlySet<number> = new Set([
  11, 19, 25, 135, 137, 138, 139, 445, 465, 587, 1080, 1081, 3389,
]);

export function validateTcpDestination(hostname: string, port: number): void {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Port out of range");
  }
  if (TUNNEL_BLOCKED_PORTS.has(port)) throw new Error(`Blocked port: ${port}`);

  if (hostname.length === 0 || hostname.length > 253) {
    throw new Error("Invalid hostname length");
  }
  // Reject URL-injection characters
  if (/[\x00/\\@:?#]/.test(hostname)) {
    throw new Error("Invalid hostname characters");
  }

  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (BLOCKED_HOSTNAMES.has(h)) throw new Error("Blocked hostname");
  if (
    h === "localhost" ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h.endsWith(".corp")
  ) {
    throw new Error("Blocked hostname (internal TLD)");
  }

  for (const re of BLOCKED_IPV4_PREFIXES) {
    if (re.test(h)) throw new Error("Blocked: private IPv4");
  }
  for (const re of BLOCKED_IPV6_PREFIXES) {
    if (re.test(h)) throw new Error("Blocked: private IPv6");
  }
}

export function validateDestination(destination: string): void {
  if (destination.length > MAX_DESTINATION_URL_LENGTH) {
    throw new Error("Destination URL too long");
  }

  let url: URL;
  try {
    url = new URL(destination);
  } catch {
    throw new Error("Invalid destination URL");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http/https destinations allowed");
  }

  // Reject userinfo — prevents credential smuggling in the URL
  if (url.username || url.password) {
    throw new Error("Destination URL must not contain credentials");
  }

  // Strip IPv6 brackets for matching
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (BLOCKED_HOSTNAMES.has(hostname)) {
    throw new Error("Blocked destination hostname");
  }

  for (const re of BLOCKED_IPV4_PREFIXES) {
    if (re.test(hostname)) {
      throw new Error("Blocked destination: private/reserved IPv4");
    }
  }

  for (const re of BLOCKED_IPV6_PREFIXES) {
    if (re.test(hostname)) {
      throw new Error("Blocked destination: private/reserved IPv6");
    }
  }
}
