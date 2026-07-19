# GreenTeamGo

Human approval gate for AI agents — push notification to your phone when your agent wants to do something risky; approve or deny; every decision becomes a signed, hash-linked receipt. **Unanswered requests fail closed.**

Part of **Newnansville Agent Teams** (with RedTeamGo). Built on Vorion (BASIS / RFC-0002).

## Repo layout

- `packages/mcp` — `@vorionsys/greenteamgo-mcp`, the stdio MCP server agents install. Open-source surface; extracted to the public tier at publish time.
- `packages/core` — `@vorionsys/greenteamgo-core`, the **Verdict Core**: RFC-0002 canonical serialization + Ed25519 signed, hash-linked **receipts** with a verify CLI. Envelope is suite-wide (Green + Red). *(receipts module built; identity/policy/lifecycle/notify still to come.)*
- `packages/api` — `@vorionsys/greenteamgo-api`, the **inbox API**: create → poll → decide lifecycle, fail-closed expiry, signed chained receipts, api-key scopes, idempotency, **policy-driven auto-decisions**. Framework-agnostic (in-memory store + Node handler today; Postgres + Next.js/Vercel adapters slot in). *(lifecycle + policy wired; FCM notify, Postgres/Vercel adapters to come.)*
- `packages/policy` — `@vorionsys/greenteamgo-policy`, versioned **policy** rules: allow / deny / gate / challenge before a human is paged. Wired into the API so only judgment calls reach your phone.
- `packages/identity` — `@vorionsys/greenteamgo-identity`, agent **identity**: API key minting + **hashed** storage (SHA-256, never plaintext) + scope resolution. Wired into the API store.
- `packages/notify` — `@vorionsys/greenteamgo-notify`, the **notify** module: inbox-item schema + pluggable delivery (`WebhookNotifier` now, FCM later). Composes into the API's `Notifier`.
- (planned) `apps/api` — Next.js/Vercel wrapper over `packages/api` + Postgres store.
- (planned) `apps/mobile` — Capacitor app.

## Dev

```
npm install
npm run build
npm test
```

Spec: `countersign-spec-v0.1.md` + `greenteamgo-redteamgo-suite.md` (D:\projects). Receipt envelope must follow RFC-0002 canonical serialization — see the W1 deltas in the suite doc before touching receipt shapes.
