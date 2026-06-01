import { createRelay2Handler } from "../../packages/relay2/src/handler.ts";

declare const process: { env: Record<string, string | undefined> };

const RELAY2_BUILD_HASH = "__SHINE_RELAY2_BUILD_HASH__";

const handler = createRelay2Handler((name) => {
  if (name === "BUNDLE_HASH" && !process.env[name]) return RELAY2_BUILD_HASH;
  return process.env[name];
});

export default async function relay2(request: Request): Promise<Response> {
  return handler(request);
}

export const config = {
  path: "/*",
};
