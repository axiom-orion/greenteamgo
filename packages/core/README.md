# @vorionsys/greenteamgo-core

**Verdict Core** — signed, hash-linked approval receipts for GreenTeamGo (and, by design, RedTeamGo). Every decision an agent asks for becomes a tamper-evident, independently verifiable receipt.

- **RFC-0002 canonical serialization** — deterministic bytes, so hashes and signatures agree across runtimes (compatible with Vorion BASIS canonicalization).
- **Ed25519 signatures** over the canonical bytes (via `node:crypto`, zero runtime deps).
- **Hash-linked chain** — each receipt's `prev_hash` is the previous receipt's `receipt_hash`; reordering or editing any receipt breaks verification.
- **Fail-closed verification** — `verifyChain` stops at the first broken link, bad signature, or unknown key.

```ts
import { generateSignerKeyPair, seal, verifyChain } from "@vorionsys/greenteamgo-core";

const key = generateSignerKeyPair("ws_1_key");

const r1 = seal(
  {
    request_id: "req_1",
    workspace_id: "ws_1",
    actor: { type: "agent_key", id: "agent_1" },
    action_type: "git_push",
    verdict: "approve",
    status: "approved",
    risk: "high",
    payload_sha256: "…",
    decider: { method: "app", id: "user_1" },
    created_at: "2026-07-19T12:00:00.000Z",
    decided_at: "2026-07-19T12:00:05.000Z",
  },
  { keyId: key.key_id, privateKeyPem: key.privateKeyPem },
);

const r2 = seal(nextBody, { keyId: key.key_id, privateKeyPem: key.privateKeyPem, prevHash: r1.receipt_hash });

verifyChain([r1, r2], (id) => (id === key.key_id ? key.publicKeyPem : undefined));
// { ok: true }
```

## Verify CLI

Verify a chain offline — it is tamper-evident (any alteration, deletion, or reordering is detectable):

```bash
greenteamgo-verify receipts.json pubkeys.json
# OK: 2 receipt(s) verified — chain intact, signatures valid.
```

`receipts.json` is a single receipt or an ordered array (a chain); `pubkeys.json` maps `key_id → public key PEM`. Exit code 0 = verified, 1 = failed.

## Envelope

The receipt envelope is intentionally wide enough for both directions of the suite, so RedTeamGo never forces a format v2 (suite W1 deltas):

| Field | Notes |
|---|---|
| `actor` | `{ type: "agent_key" \| "observed", id?, evidence? }` — Red subjects are observed, not registered |
| `verdict` | `approve \| deny \| gate \| challenge` (full core enum) |
| `status` | `approved \| denied \| expired \| blocked \| challenged` |
| `decider.method` | `app \| biometric \| policy \| auto` (+ reserved `device_attestation`; absent = server-signed) |
| `policy_id` / `policy_version` | versioned reference to the policy that produced the decision |
| `prev_hash` / `receipt_hash` / `sig` / `signer` | the chain + signature |

**v1 claim is exactly "signed, hash-linked receipts."** Device-bound (human non-repudiation) signing is a later, non-breaking append via `decider.device_attestation` — reserved now.

## What this does and does not prove (honest threat model)

Receipts are **tamper-evident**: once a chain is exported, anyone can detect — offline, without the server — if any receipt was **altered, deleted, or reordered**, because that breaks a hash link or an Ed25519 signature.

What it is **not**, in v1: tamper-*proof* against a compromised server. The workspace signing key is held server-side, so a fully compromised server could sign a *false* history from the start. Detecting that is what **device-bound countersigning** (a human's device co-signs the decision) is for — the envelope already reserves `decider.device_attestation` so it's a non-breaking upgrade. We say **tamper-evident**, never "trustless."

## License

MIT © Vorion
