# GreenTeamGo

Human approval gate for AI agents — push notification to your phone when your agent wants to do something risky; approve or deny; every decision becomes a signed, hash-linked receipt. **Unanswered requests fail closed.**

Part of **Newnansville Agent Teams** (with RedTeamGo). Built on Vorion (BASIS / RFC-0002).

## Repo layout

- `packages/mcp` — `@vorionsys/greenteamgo-mcp`, the stdio MCP server agents install. Open-source surface; extracted to the public tier at publish time.
- (planned) `packages/core` — verdict core modules: identity, policy, lifecycle, receipts, notify.
- (planned) `apps/api` — hosted inbox API (Next.js on Vercel).
- (planned) `apps/mobile` — Capacitor app.

## Dev

```
npm install
npm run build
npm test
```

Spec: `countersign-spec-v0.1.md` + `greenteamgo-redteamgo-suite.md` (D:\projects). Receipt envelope must follow RFC-0002 canonical serialization — see the W1 deltas in the suite doc before touching receipt shapes.
