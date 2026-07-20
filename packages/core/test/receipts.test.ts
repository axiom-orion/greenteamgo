import { describe, expect, it } from "vitest";

import { canonicalize } from "../src/canonical.js";
import {
  GENESIS_PREV_HASH,
  generateSignerKeyPair,
  seal,
  verifyChain,
  verifyReceipt,
  type ReceiptBody,
} from "../src/receipts.js";

const key = generateSignerKeyPair("ws_test_key_1");
// what seal() takes: the signer options bag
const signer = { keyId: key.key_id, privateKeyPem: key.privateKeyPem };

function body(over: Partial<ReceiptBody> = {}): ReceiptBody {
  return {
    request_id: "req_1",
    workspace_id: "ws_1",
    actor: { type: "agent_key", id: "agent_1" },
    action_type: "git_push",
    verdict: "approve",
    status: "approved",
    risk: "high",
    payload_sha256: "a".repeat(64),
    policy_id: "pol_1",
    decider: { method: "app", id: "user_1" },
    created_at: "2026-07-19T12:00:00.000Z",
    decided_at: "2026-07-19T12:00:05.000Z",
    ...over,
  };
}

describe("canonical serialization", () => {
  it("is independent of key insertion order", () => {
    expect(canonicalize({ b: 1, a: 2, c: { y: 1, x: 2 } })).toBe(
      canonicalize({ c: { x: 2, y: 1 }, a: 2, b: 1 }),
    );
  });
  it("preserves array order", () => {
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
  });

  // Golden vectors: these strings are the RFC-0002 byte contract. If any of
  // them changes, existing receipt hashes/signatures break — that is a format
  // v2, not a refactor. Must stay byte-identical with the BASIS canonicalizer.
  it("matches the golden vectors byte-for-byte", () => {
    const vectors: Array<[unknown, string]> = [
      [{}, "{}"],
      [[], "[]"],
      [{ b: 2, a: 1 }, '{"a":1,"b":2}'],
      [{ nested: { z: [1, { b: 2, a: 1 }], a: "x" } }, '{"nested":{"a":"x","z":[1,{"a":1,"b":2}]}}'],
      [{ s: "héllo ✓" }, '{"s":"héllo ✓"}'], // raw UTF-8, no \u escapes
      [{ n: 1e21 }, '{"n":1e+21}'],
      [{ n: -0 }, '{"n":0}'],
      [{ u: undefined, k: 1 }, '{"k":1}'], // undefined keys drop
      [{ a: [undefined, 1] }, '{"a":[null,1]}'], // undefined in arrays → null
      [{ "ä": 1, a: 2 }, '{"a":2,"ä":1}'], // non-ASCII key ordering (UTF-16 sort)
      [{ t: true, f: false, z: null }, '{"f":false,"t":true,"z":null}'],
    ];
    for (const [value, expected] of vectors) {
      expect(canonicalize(value)).toBe(expected);
    }
  });

  it("refuses non-finite numbers instead of silently nulling them", () => {
    expect(() => canonicalize({ n: NaN })).toThrow(/non-finite/);
    expect(() => canonicalize({ n: Infinity })).toThrow(/non-finite/);
    expect(() => canonicalize([1, -Infinity])).toThrow(/non-finite/);
  });
});

describe("seal + verifyReceipt", () => {
  it("round-trips: a sealed receipt verifies under its signer's public key", () => {
    const r = seal(body(), signer);
    expect(r.v).toBe(1);
    expect(r.prev_hash).toBe(GENESIS_PREV_HASH);
    expect(r.signer.key_id).toBe("ws_test_key_1");
    expect(verifyReceipt(r, key.publicKeyPem)).toEqual({ ok: true });
  });

  it("detects content tampering (hash mismatch)", () => {
    const r = seal(body({ verdict: "approve", status: "approved" }), signer);
    const tampered = { ...r, verdict: "deny" as const, status: "denied" as const };
    const res = verifyReceipt(tampered, key.publicKeyPem);
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/hash mismatch/);
  });

  it("detects signature tampering", () => {
    const r = seal(body(), signer);
    const forged = Buffer.from(r.sig, "base64");
    forged[0] ^= 0xff;
    const res = verifyReceipt({ ...r, sig: forged.toString("base64") }, key.publicKeyPem);
    expect(res.ok).toBe(false);
  });

  it("rejects a valid receipt under the wrong public key", () => {
    const r = seal(body(), signer);
    const other = generateSignerKeyPair("other");
    expect(verifyReceipt(r, other.publicKeyPem).ok).toBe(false);
  });

  it("is deterministic: identical bodies seal to the identical hash", () => {
    // Same logical content sealed twice must hash-match (no time/nonce inside).
    const a = seal(body(), signer);
    const b = seal(body(), signer);
    expect(a.receipt_hash).toBe(b.receipt_hash);
  });

  it("seals and verifies with the reserved device_attestation present", () => {
    const r = seal(body({ decider: { method: "biometric", id: "user_1", device_attestation: "att_blob" } }), signer);
    expect(verifyReceipt(r, key.publicKeyPem)).toEqual({ ok: true });
    expect(r.decider.device_attestation).toBe("att_blob");
  });
});

describe("verifyChain (hash-linked)", () => {
  const resolve = (id: string) => (id === key.key_id ? key.publicKeyPem : undefined);

  it("verifies a 3-receipt chain where each links to the previous", () => {
    const r1 = seal(body({ request_id: "r1" }), signer);
    const r2 = seal(body({ request_id: "r2" }), { ...signer, prevHash: r1.receipt_hash });
    const r3 = seal(body({ request_id: "r3" }), { ...signer, prevHash: r2.receipt_hash });
    expect(verifyChain([r1, r2, r3], resolve)).toEqual({ ok: true });
  });

  it("fails closed on a broken link (reordered chain)", () => {
    const r1 = seal(body({ request_id: "r1" }), signer);
    const r2 = seal(body({ request_id: "r2" }), { ...signer, prevHash: r1.receipt_hash });
    const res = verifyChain([r2, r1], resolve);
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/chain break/);
  });

  it("fails on an unknown signer key", () => {
    const r1 = seal(body(), signer);
    expect(verifyChain([r1], () => undefined).ok).toBe(false);
  });

  it("catches a tampered MIDDLE receipt even though all prev_hash links are intact", () => {
    const r1 = seal(body({ request_id: "r1" }), signer);
    const r2 = seal(body({ request_id: "r2" }), { ...signer, prevHash: r1.receipt_hash });
    const r3 = seal(body({ request_id: "r3" }), { ...signer, prevHash: r2.receipt_hash });
    // edit r2's content but KEEP its stored receipt_hash — the links r1→r2→r3
    // still line up, so only per-receipt verification can catch this
    const tampered = { ...r2, reason: "retroactively justified" };
    const res = verifyChain([r1, tampered, r3], resolve);
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/index 1:.*hash mismatch/);
  });
});

describe("W1 forward-compat (RedTeamGo direction)", () => {
  it("seals and verifies an observed-actor challenge verdict", () => {
    const r = seal(
      body({
        actor: { type: "observed", evidence: { web_bot_auth: false, ua: "curl/8" } },
        verdict: "challenge",
        status: "challenged",
        decider: { method: "policy", id: "pol_red_1" },
      }),
      signer,
    );
    expect(verifyReceipt(r, key.publicKeyPem)).toEqual({ ok: true });
    expect(r.status).toBe("challenged");
  });

  it("seals a machine 'blocked' verdict (decider.method auto)", () => {
    const r = seal(body({ verdict: "deny", status: "blocked", decider: { method: "auto" } }), signer);
    expect(verifyReceipt(r, key.publicKeyPem)).toEqual({ ok: true });
  });

  it("survives the wire: a receipt with rich evidence verifies after JSON round-trip", () => {
    // Date has toJSON; without seal()'s normalization this receipt would
    // verify in memory but fail forever once it crossed HTTP/Postgres.
    const r = seal(
      body({
        actor: {
          type: "observed",
          id: "gptbot",
          evidence: { seen_at: new Date("2026-07-20T00:00:00Z") as unknown as string, ua: "GPTBot/1.1" },
        },
      }),
      signer,
    );
    const overWire = JSON.parse(JSON.stringify(r));
    expect(verifyReceipt(overWire, key.publicKeyPem)).toEqual({ ok: true });
    expect(verifyReceipt(r, key.publicKeyPem)).toEqual({ ok: true });
  });

  it("refuses to seal without a key id", () => {
    expect(() => seal(body(), { keyId: "", privateKeyPem: signer.privateKeyPem })).toThrow(/keyId/);
  });
});
