# @vorionsys/redteamgo

**The agent guest list.** Cloudflare blocks bots. RedTeamGo decides which agents get in — with a human on the hook and a signed logbook.

Edge middleware for your site or API that:

1. **Classifies** every inbound request: `verified_agent` (Web Bot Auth signature that cryptographically verifies) / `declared_bot` (User-Agent registry, optionally IP-confirmed) / `suspected_agent` (automation UAs, honeypot hits, browser-UA-without-browser-headers) / `human`.
2. **Applies per-path policy** (`@vorionsys/greenteamgo-policy`): allow / block / challenge / **escalate to a human's phone**. Rules match on path plus tags like `class:suspected_agent`, `method:POST`, `agent:gptbot`.
3. **Escalates gray cases through GreenTeamGo's approval rails** — "Unknown agent wants `GET /api/orders` — allow?" on your phone. Challenged (fail closed) until you answer; your answer becomes a **standing allow/block** so you're paged once per agent, not once per request.
4. **Seals every enforcement decision** into the same Ed25519 signed, hash-linked receipt chain GreenTeamGo writes (`@vorionsys/greenteamgo-core`): `actor.type "observed"`, machine verdicts as `decider.method "policy"/"auto"`, human escalation outcomes attributed to the decision that made them. One workspace, one chain, one logbook.

**Product invariants** (tested):

- **Humans always pass in v1.** A middleware bug must never block your human customers; only agent-classified traffic is gated.
- **Fail closed.** Classifier errors, escalator outages, unverifiable signatures — anything unknown on agent-shaped traffic disposes as `challenge`, never allow-by-crash.
- **No detection arms race.** The registry is small and factual; unknown automation falls to heuristics; the differentiator is the guest list + human escalation + portable receipts, not out-detecting Cloudflare.

## Usage

Next.js middleware / Cloudflare Workers (web-standard):

```ts
import { createFetchGate, GreenInboxEscalator } from "@vorionsys/redteamgo";

const guard = createFetchGate({
  workspace_id: "ws_1",
  policy: {
    id: "pol_red", workspace_id: "ws_1", version: 1,
    default_effect: "allow",
    rules: [
      { id: "r1", action_type: "/api/*", tags: ["class:suspected_agent"], effect: "gate" },
      { id: "r2", action_type: "*", tags: ["agent:bytespider"], effect: "deny" },
    ],
  },
  signing: { key_id, privateKeyPem, chain },   // omit for receipt-less dev mode
  escalator: new GreenInboxEscalator({ apiUrl, apiKey }),
  honeypots: ["/wp-admin/*"],
  // monitor: true,  // report-only: verdicts + receipts, but always allow
});

export async function middleware(req: Request) {
  const res = await guard(req);
  if (res) return res;          // blocked or challenged
  return NextResponse.next();   // allowed
}
```

Express / Connect / bare node:

```ts
import { createNodeGate } from "@vorionsys/redteamgo";
app.use(createNodeGate({ workspace_id, policy /* , signing, escalator */ }));
```

`chain` is any `ChainStore` — point it at the same store your GreenTeamGo inbox API uses and both products write **one** chain per workspace (`@vorionsys/greenteamgo-api`'s `Store` satisfies it directly).

## Web Bot Auth

The classifier parses HTTP Message Signature headers (`Signature-Agent` / `Signature-Input` / `Signature`, RFC 9421 profile) structurally: expired signatures are discarded, and a signature only produces `verified_agent` when your injected `webBotAuthVerifier` cryptographically passes it (key-directory fetch is deliberately out of core). **No verifier configured → signed requests classify as `suspected_agent`, never verified.** Fail closed.

## Part of the suite

GreenTeamGo gates your agents (outbound); RedTeamGo screens everyone else's (inbound). Same Verdict Core, same policy engine, same receipt chain, same phone. See `docs/receipt-envelope.md` at the repo root before touching receipt shapes.

## License

MIT © Vorion
