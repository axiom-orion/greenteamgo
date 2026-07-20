# @vorionsys/greenteamgo-api

The GreenTeamGo **inbox API** — the request lifecycle behind the phone. An agent asks; the human decides; the decision becomes a signed, hash-linked receipt.

- **Create → poll → decide** lifecycle with **fail-closed expiry** (no decision by the deadline = deny, surfaced as `expired`).
- **Signed, chained receipts** on every decision via [`@vorionsys/greenteamgo-core`](../core) — one receipt chain per workspace.
- **Bearer api-key auth** with product-prefixed scopes (`green:create`, `green:read`, `green:decide`).
- **Idempotent creation** (idempotency-key) so agent retries never duplicate a request.
- **Framework-agnostic**: the service talks to a `Store` interface and exposes a plain `(req,res)` handler. The in-memory store + Node handler here run and test fully offline; a **Postgres store** and a **Next.js/Vercel** route wrapper drop in without touching the service.

## Routes

| Method | Path | Who | Purpose |
|---|---|---|---|
| POST | `/v1/requests` | agent (`green:create`) | create an approval request |
| GET | `/v1/requests?status=pending` | agent/app (`green:read`) | list pending |
| GET | `/v1/requests/:id` | agent (`green:read`) | poll a decision (fail-closed expiry) |
| POST | `/v1/requests/:id/decision` | app (`green:decide`) | record the human's verdict → receipt |
| GET | `/v1/receipts` | agent/app (`green:read`) | export the workspace chain (verify-CLI input) |
| GET | `/v1/keys` | agent/app (`green:read`) | the workspace's signing **public** key |

## Usage

```ts
import { createServer } from "node:http";
import { generateSignerKeyPair } from "@vorionsys/greenteamgo-core";
import { InMemoryStore, RequestService, createHandler } from "@vorionsys/greenteamgo-api";

const store = new InMemoryStore();
store.seedWorkspace("ws1",
  { api_key: "sk_agent", workspace_id: "ws1", scopes: ["green:create", "green:read"] },
  generateSignerKeyPair("ws1_key"));
store.addApiKey({ api_key: "sk_app", workspace_id: "ws1", scopes: ["green:read", "green:decide"] });

const service = new RequestService({ store /*, notifier: new FcmNotifier(...) */ });
createServer(createHandler(service, store)).listen(3000);
```

The `Notifier` interface is where FCM push wires in (default is a no-op). Clock and id generator are injectable for deterministic tests.

## Status

Built: lifecycle, fail-closed expiry **sealed into the chain as receipts**, signed receipts on every terminal state, auth/scopes, content-fingerprinted idempotency (colliding keys 409), server-side `payload_sha256` verification, policy auto-decisions (via `@vorionsys/greenteamgo-policy`, with `policy_id`/`policy_version` in the sealed receipt), chain + public-key export routes, HTTP handler, in-memory store.
Next: Postgres `Store` adapter (must implement the atomicity contract documented in `store.ts`), `apps/api` Next.js/Vercel wrapper, FCM `Notifier`, per-workspace policy storage.

## License

MIT © Vorion
