# The receipt envelope — suite-wide constraints

_The load-bearing rules for anyone touching receipt shapes. Vendored from the
suite architecture doc (private: `D:\projects\greenteamgo-redteamgo-suite.md`)
so the constraints travel with the code._

One envelope serves both products — GreenTeamGo (outbound, cooperative:
"may my agent do this?") and RedTeamGo (inbound, adversarial: "should this
foreign agent get in?") — writing ONE hash-linked chain per workspace. These
five properties are what keep Red from ever forcing a format v2:

1. **`actor` is an object**, never a bare key id:
   `{ type: "agent_key" | "observed", id?, evidence? }`. Red's subjects are
   observed/claimed identities (Web Bot Auth evidence, UA claims), not
   registered keys.
2. **`decider.method`** spans `app | biometric` (human) and `policy | auto`
   (machine) — most Red verdicts are machine-made. The human-facing decision
   endpoint MUST NOT accept `policy`/`auto` (enforced at the HTTP layer and in
   the service). The optional `decider.device_attestation` is reserved for
   device-bound signing: absent = server-signed, present = device-signed, no
   chain break either way.
3. **Status space** is `approved | denied | expired | blocked | challenged`;
   the verdict enum is `approve | deny | gate | challenge`. Green uses
   approved/denied/expired; Red uses approved/blocked/challenged. Statuses are
   NEVER coerced at sealing time — an unmapped status is an error, not an
   "approved".
4. **Versioned policy references**: receipts carry `policy_id` AND
   `policy_version` — a policy's id is stable across edits, so the id alone
   cannot prove which rules were in force.
5. **API key scopes are product-prefixed** (`green:create`, `red:report`) so
   one workspace spans both products.

Two byte-level invariants, enforced in `@vorionsys/greenteamgo-core`:

- **Canonicalization is the RFC-0002 byte contract** (sorted keys, arrays in
  order, no whitespace; golden vectors in `packages/core/test`). It must stay
  byte-identical with the Vorion BASIS canonicalizer. Changing any golden
  vector is a format v2, not a refactor.
- **Sealed bytes = wire bytes.** `seal()` JSON-round-trips the body before
  hashing, so values with `toJSON` (Dates) or non-plain-JSON shapes inside
  `actor.evidence` can never produce a receipt that verifies in memory but
  fails after transport. Non-finite numbers refuse to canonicalize.

Related decisions (private: `D:\projects\countersign-open-questions-decisions.md`):
device-bound keys wait for a revenue signal (the envelope is already shaped for
them); hash-only mode (payload never uploaded, only its SHA-256) is a v1
feature; denials and expiries are free forever in billing terms.
