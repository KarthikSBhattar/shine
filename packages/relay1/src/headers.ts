const STRIP: ReadonlySet<string> = new Set([
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "cf-visitor",
  "cf-worker",
  "true-client-ip",
  "x-forwarded-for",
  "x-forwarded-proto",
  "x-forwarded-host",
  "x-real-ip",
  "x-client-ip",
  "x-cluster-client-ip",
  "forwarded",
  "via",
  "cookie",
  "set-cookie",
  "authorization",
]);

export function stripIdentifyingHeaders(headers: Headers): Headers {
  const clean = new Headers();
  headers.forEach((v, k) => {
    if (!STRIP.has(k.toLowerCase())) clean.set(k, v);
  });
  return clean;
}
