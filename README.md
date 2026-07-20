# GreenTeamGo

Human approval gate for AI agents — push notification to your phone when your agent wants to do something risky; approve or deny; every decision becomes a signed, hash-linked receipt. **Unanswered requests fail closed.**

Part of **Newnansville Agent Teams** (with RedTeamGo). Built on Vorion (BASIS / RFC-0002).

## Repo layout

- `packages/mcp` — `@vorionsys/greenteamgo-mcp`, the stdio MCP server agents install. Open-source surface; extracted to the public tier at publish time. Hash-only mode, fail-closed polling, side-effect-free library entry + separate bin.
- `packages/core` — `@vorionsys/greenteamgo-core`, the **Verdict Core**: RFC-0002 canonical serialization (golden-vectored) + Ed25519 signed, hash-linked **receipts** with a verify CLI. Envelope is suite-wide (Green + Red) — see `docs/receipt-envelope.md` before touching receipt shapes.
- `packages/api` — `@vorionsys/greenteamgo-api`, the **inbox API**: create → poll → decide lifecycle, fail-closed expiry **sealed into the chain**, api-key scopes, fingerprinted idempotency, **policy-driven auto-decisions**, chain/public-key export for independent verification. Framework-agnostic (in-memory store + Node handler today; Postgres + Next.js/Vercel adapters slot in). *(FCM notify, Postgres/Vercel adapters to come.)*
- `packages/policy` — `@vorionsys/greenteamgo-policy`, versioned **policy** rules: allow / deny / gate / challenge before a human is paged, with `tags` for extra match dimensions (Red's agent classes, HTTP methods) and the shared effect→receipt mapping.
- `packages/identity` — `@vorionsys/greenteamgo-identity`, agent **identity**: API key minting + **hashed** storage (SHA-256, never plaintext) + scope resolution.
- `packages/notify` — `@vorionsys/greenteamgo-notify`, the **notify** module: inbox-item schema + pluggable delivery (`WebhookNotifier` now, FCM later). Delivery failure never touches the lifecycle.
- `packages/redteamgo` — `@vorionsys/redteamgo`, **RedTeamGo**: the agent guest list. Edge middleware that classifies inbound agents (Web Bot Auth / declared / suspected / human), applies per-path policy, escalates gray cases to your phone through Green's rails, and seals every enforcement decision into the same chain.
- `apps/console` — local demo console: the inbox API + a web approval page in one process (the "phone" stand-in).
- (planned) `apps/api` — Next.js/Vercel wrapper over `packages/api` + Postgres store.
- (planned) `apps/mobile` — Capacitor app.

## Dev

```
npm install
npm run build
npm test
```

**Receipt envelope:** the constraints that keep Green + Red on one format live in [`docs/receipt-envelope.md`](docs/receipt-envelope.md). Read it before touching receipt shapes.

Product/strategy docs (private, not in this repo): `greenteamgo-redteamgo-suite.md` + `countersign-open-questions-decisions.md` in `D:\projects`.
