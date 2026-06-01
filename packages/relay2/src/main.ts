/// <reference lib="deno.ns" />

import { createRelay2Handler } from "./handler.ts";
import { handleTunnel } from "./tunnel.ts";

const handler = createRelay2Handler((name) => Deno.env.get(name), {
  handleTunnel,
});

Deno.serve(handler);
