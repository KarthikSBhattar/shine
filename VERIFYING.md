# Verifying Shine Relays

Shine relays expose a deployment hash at `/healthz`. CI records the same hash in
the public `transparency-log` branch after the deployed relay has been checked.

Users can verify that the deployed relay is a publicly logged build:

```sh
SHINE_TRANSPARENCY_LOG_URL="https://raw.githubusercontent.com/<owner>/<repo>/transparency-log/transparency-log.jsonl" \
deno run --allow-net --allow-env scripts/verify-relays.ts
```

To pin to the exact source commit your client was built against:

```sh
SHINE_EXPECTED_COMMIT="<git-sha>" \
SHINE_TRANSPARENCY_LOG_URL="https://raw.githubusercontent.com/<owner>/<repo>/transparency-log/transparency-log.jsonl" \
deno run --allow-net --allow-env scripts/verify-relays.ts
```

The transparency entry format is JSON Lines:

```json
{"relay":"relay1","url":"https://shine-relay1.ksb6007.workers.dev","commit":"<git-sha>","hash":"<sha256>","hash_algorithm":"sha256","source_repository":"<owner/repo>","workflow_run_id":"<run-id>","timestamp":"<iso-8601>"}
```

This proves only that the relay reports a hash that CI logged for a source
commit. It does not prove the hosting provider keeps no logs, and it does not
prevent traffic correlation if one operator controls both relays.
