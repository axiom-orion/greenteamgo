import { describe, expect, it } from "vitest";

import { generateSignerKeyPair, verifyChain } from "@vorionsys/greenteamgo-core";
import type { Policy } from "@vorionsys/greenteamgo-policy";

import { Gate, InMemoryChainStore, type GateOptions } from "../src/gate.js";
import { InMemoryAllowStore, type Escalation, type Escalator } from "../src/escalate.js";
import type { InboundRequest } from "../src/classify.js";

const key = generateSignerKeyPair("red_ws_key");

const POLICY: Policy = {
  id: "pol_red",
  workspace_id: "ws1",
  version: 1,
  default_effect: "allow",
  rules: [
    { id: "r_deny_train", action_type: "*", tags: ["agent:bytespider"], effect: "deny" },
    { id: "r_challenge_sus", action_type: "/checkout*", tags: ["class:suspected_agent"], effect: "challenge" },
    { id: "r_gate_api", action_type: "/api/*", tags: ["class:suspected_agent"], effect: "gate" },
  ],
};

function gate(over: Partial<GateOptions> = {}, chain = new InMemoryChainStore()) {
  return {
    chain,
    gate: new Gate({
      workspace_id: "ws1",
      policy: POLICY,
      signing: { key_id: key.key_id, privateKeyPem: key.privateKeyPem, chain },
      now: () => 1_000_000,
      ...over,
    }),
  };
}

function inbound(over: Partial<InboundRequest> = {}): InboundRequest {
  return { method: "GET", path: "/", headers: { "user-agent": "curl/8.4.0" }, ip: "198.51.100.7", ...over };
}

const HUMAN = {
  "user-agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/126",
  "accept-language": "en-US",
  "sec-fetch-mode": "navigate",
};

type FakeEscalator = Escalator & { calls: number; resolution: "pending" | "approved" | "denied"; current: () => Escalation };
function fakeEscalator(): FakeEscalator {
  const esc: FakeEscalator = {
    calls: 0,
    resolution: "pending",
    async escalate(): Promise<Escalation> {
      esc.calls++;
      return esc.current();
    },
    async check(): Promise<Escalation> {
      return esc.current();
    },
    current(): Escalation {
      // a resolved escalation carries how it was decided; here, a human tap
      return {
        request_id: "req_esc_1",
        status: esc.resolution,
        decider_method: esc.resolution === "pending" ? undefined : "app",
      };
    },
  };
  return esc;
}

describe("Gate — product invariants", () => {
  it("humans always pass: no policy, no receipt", async () => {
    const { gate: g, chain } = gate();
    const r = await g.handle(inbound({ headers: { ...HUMAN } }));
    expect(r.disposition).toBe("allow");
    expect(r.receipt).toBeUndefined();
    expect(chain.listReceipts("ws1")).toHaveLength(0);
  });

  it("an allowed agent gets a signed approve/approved receipt with observed actor", async () => {
    const { gate: g } = gate();
    const r = await g.handle(inbound({ headers: { "user-agent": "GPTBot/1.1" }, path: "/blog" }));
    expect(r.disposition).toBe("allow");
    expect(r.receipt).toBeDefined();
    expect(r.receipt!.verdict).toBe("approve");
    expect(r.receipt!.status).toBe("approved");
    expect(r.receipt!.actor.type).toBe("observed");
    expect(r.receipt!.actor.id).toBe("gptbot");
    expect(r.receipt!.decider.method).toBe("policy");
    expect(r.receipt!.policy_id).toBe("pol_red");
    expect(r.receipt!.policy_version).toBe(1);
    expect(r.receipt!.action_type).toBe("/blog"); // bare path = what the policy evaluated
  });

  it("a denied agent is blocked with a deny/blocked receipt", async () => {
    const { gate: g } = gate();
    const r = await g.handle(inbound({ headers: { "user-agent": "Bytespider" }, path: "/anything" }));
    expect(r.disposition).toBe("block");
    expect(r.receipt!.verdict).toBe("deny");
    expect(r.receipt!.status).toBe("blocked");
  });

  it("a challenged agent gets a challenge/challenged receipt", async () => {
    const { gate: g } = gate();
    const r = await g.handle(inbound({ path: "/checkout" }));
    expect(r.disposition).toBe("challenge");
    expect(r.receipt!.verdict).toBe("challenge");
    expect(r.receipt!.status).toBe("challenged");
  });

  it("gate effect with NO escalator fails closed to challenge", async () => {
    const { gate: g } = gate();
    const r = await g.handle(inbound({ path: "/api/orders" }));
    expect(r.disposition).toBe("challenge");
    expect(r.reason).toMatch(/no escalator/);
  });

  it("receipts hash-link into one verifiable chain", async () => {
    const { gate: g, chain } = gate();
    await g.handle(inbound({ headers: { "user-agent": "GPTBot/1.1" }, path: "/a" }));
    await g.handle(inbound({ headers: { "user-agent": "Bytespider" }, path: "/b" }));
    await g.handle(inbound({ path: "/checkout" }));
    const receipts = chain.listReceipts("ws1");
    expect(receipts).toHaveLength(3);
    expect(verifyChain(receipts, (id) => (id === key.key_id ? key.publicKeyPem : undefined))).toEqual({ ok: true });
  });

  it("receipt_mode non_allow skips receipts for allows but keeps them for blocks", async () => {
    const { gate: g, chain } = gate({ receipt_mode: "non_allow" });
    const allow = await g.handle(inbound({ headers: { "user-agent": "GPTBot/1.1" }, path: "/x" }));
    const block = await g.handle(inbound({ headers: { "user-agent": "Bytespider" }, path: "/x" }));
    expect(allow.receipt).toBeUndefined();
    expect(block.receipt).toBeDefined();
    expect(chain.listReceipts("ws1")).toHaveLength(1);
  });

  it("monitor mode records the verdict + receipt but lets the request through", async () => {
    const { gate: g } = gate({ monitor: true });
    const r = await g.handle(inbound({ headers: { "user-agent": "Bytespider" }, path: "/y" }));
    expect(r.disposition).toBe("allow");
    expect(r.monitored).toBe(true);
    expect(r.receipt!.status).toBe("blocked"); // the receipt tells the truth
  });
});

describe("Gate — escalation loop", () => {
  it("pending escalation → challenged with a gate-verdict receipt; approval → standing allow", async () => {
    const escalator = fakeEscalator();
    const allowStore = new InMemoryAllowStore(() => 1_000_000);
    const { gate: g } = gate({ escalator, allowStore });

    const first = await g.handle(inbound({ path: "/api/orders" }));
    expect(first.disposition).toBe("challenge");
    expect(first.escalation).toEqual({ request_id: "req_esc_1", status: "pending" });
    expect(first.receipt!.verdict).toBe("gate");
    expect(first.receipt!.status).toBe("challenged");

    // the human approves on their phone
    escalator.resolution = "approved";
    const second = await g.handle(inbound({ path: "/api/orders" }));
    expect(second.disposition).toBe("allow");
    expect(second.receipt!.verdict).toBe("approve");
    expect(second.receipt!.decider.method).toBe("app"); // a human made this call
    expect(second.receipt!.decider.id).toBe("req_esc_1");

    // standing allow now short-circuits: no more escalator calls
    const callsBefore = escalator.calls;
    const third = await g.handle(inbound({ path: "/api/orders" }));
    expect(third.disposition).toBe("allow");
    expect(third.reason).toMatch(/standing allow/);
    expect(escalator.calls).toBe(callsBefore);
  });

  it("a human denial becomes a standing block", async () => {
    const escalator = fakeEscalator();
    escalator.resolution = "denied";
    const { gate: g } = gate({ escalator, allowStore: new InMemoryAllowStore(() => 1_000_000) });

    const first = await g.handle(inbound({ path: "/api/orders" }));
    expect(first.disposition).toBe("block");

    const second = await g.handle(inbound({ path: "/api/orders" }));
    expect(second.disposition).toBe("block");
    expect(second.reason).toMatch(/standing block/);
  });

  it("standing decisions expire after their TTL — the escalator is consulted again", async () => {
    let clock = 1_000_000;
    const escalator = fakeEscalator();
    escalator.resolution = "approved";
    const allowStore = new InMemoryAllowStore(() => clock);
    const { gate: g } = gate({ escalator, allowStore, standing_ttl_s: 60, now: () => clock });

    await g.handle(inbound({ path: "/api/orders" })); // creates standing allow
    await g.handle(inbound({ path: "/api/orders" })); // served from standing allow
    const callsBeforeExpiry = escalator.calls;
    expect(callsBeforeExpiry).toBe(1);
    clock += 61_000; // past TTL
    await g.handle(inbound({ path: "/api/orders" }));
    // TTL lapsed → back to the escalator, not the standing allow
    expect(escalator.calls).toBe(callsBeforeExpiry + 1);
  });

  it("an escalator crash fails closed to challenge, never allow", async () => {
    const escalator: Escalator = {
      escalate: () => {
        throw new Error("green api down");
      },
      check: async () => ({ request_id: "x", status: "pending" }),
    };
    const { gate: g } = gate({ escalator });
    const r = await g.handle(inbound({ path: "/api/orders" }));
    expect(r.disposition).toBe("challenge");
    expect(r.reason).toMatch(/fail closed/);
  });

  it("a machine-decided escalation (Green auto/expiry) is sealed as decider.method auto, not app", async () => {
    const escalator = fakeEscalator();
    escalator.resolution = "denied";
    // simulate Green's expiry (auto), not a human tap
    escalator.current = () => ({ request_id: "req_esc_1", status: "denied", decider_method: "auto" });
    const { gate: g } = gate({ escalator, allowStore: new InMemoryAllowStore(() => 1_000_000) });
    const r = await g.handle(inbound({ path: "/api/orders" }));
    expect(r.disposition).toBe("block");
    expect(r.receipt!.decider.method).toBe("auto");
  });

  it("a standing block applies on ANY path, not just the escalated one", async () => {
    const escalator = fakeEscalator();
    escalator.resolution = "denied";
    const { gate: g } = gate({ escalator, allowStore: new InMemoryAllowStore(() => 1_000_000) });
    await g.handle(inbound({ path: "/api/orders" })); // creates standing block
    const other = await g.handle(inbound({ path: "/blog", headers: { "user-agent": "curl/8.4.0" } }));
    expect(other.disposition).toBe("block");
    expect(other.receipt!.status).toBe("blocked");
    expect(other.reason).toMatch(/standing block/);
  });
});

describe("Gate — identity provenance (spoof isolation)", () => {
  it("humans always pass even under a deny-everything policy — no receipt, no block", async () => {
    const chain = new InMemoryChainStore();
    const hostile: Policy = {
      id: "pol_deny", workspace_id: "ws1", version: 1,
      default_effect: "deny", rules: [{ id: "r_all", action_type: "*", effect: "deny" }],
    };
    const g = new Gate({
      workspace_id: "ws1", policy: hostile,
      signing: { key_id: key.key_id, privateKeyPem: key.privateKeyPem, chain },
      now: () => 1_000_000,
    });
    const r = await g.handle(inbound({ headers: { ...HUMAN } }));
    expect(r.disposition).toBe("allow");
    expect(r.receipt).toBeUndefined();
    expect(chain.listReceipts("ws1")).toHaveLength(0);
  });

  it("a declared bot's standing allow is IP-scoped: a UA-spoofer from another IP cannot inherit it", async () => {
    const escalator = fakeEscalator();
    escalator.resolution = "approved";
    const allowStore = new InMemoryAllowStore(() => 1_000_000);
    // no ipVerifier → GPTBot is declared (not ip-confirmed), so its standing
    // identity is ip-scoped, NOT the forgeable agent id. policy gates it.
    const policy: Policy = {
      id: "pol", workspace_id: "ws1", version: 1, default_effect: "allow",
      rules: [{ id: "r", action_type: "/api/*", tags: ["class:declared_bot"], effect: "gate" }],
    };
    const g = new Gate({
      workspace_id: "ws1", policy, escalator, allowStore,
      signing: { key_id: key.key_id, privateKeyPem: key.privateKeyPem, chain: new InMemoryChainStore() },
      now: () => 1_000_000,
    });
    // real gptbot at 8.8.8.8 approved → standing allow keyed ip:8.8.8.8 (NOT agent:gptbot)
    await g.handle(inbound({ headers: { "user-agent": "GPTBot/1.1" }, path: "/api/x", ip: "8.8.8.8" }));
    expect(allowStore.get("agent:gptbot")).toBeUndefined(); // never keyed on the forgeable id
    expect(allowStore.get("ip:8.8.8.8")).toBeDefined();
    const callsAfterReal = escalator.calls;
    // a spoofer sends the same UA from a different IP → identity ip:6.6.6.6 → miss
    await g.handle(inbound({ headers: { "user-agent": "GPTBot/1.1" }, path: "/api/x", ip: "6.6.6.6" }));
    expect(escalator.calls).toBe(callsAfterReal + 1); // had to re-escalate, did not inherit
    expect(allowStore.get("ip:6.6.6.6")).toBeDefined(); // its own scoped allow, distinct from 8.8.8.8
  });

  it("distinct agents behind different IPs do not share a standing allow", async () => {
    const escalator = fakeEscalator();
    escalator.resolution = "approved";
    const { gate: g } = gate({ escalator, allowStore: new InMemoryAllowStore(() => 1_000_000) });
    await g.handle(inbound({ path: "/api/orders", ip: "1.1.1.1" })); // approve ip 1.1.1.1
    const callsAfterFirst = escalator.calls;
    await g.handle(inbound({ path: "/api/orders", ip: "2.2.2.2" }));
    // different IP → different identity → must escalate again, not inherit
    expect(escalator.calls).toBe(callsAfterFirst + 1);
  });

  it("a UA-only identity (no IP) never persists a standing ALLOW", async () => {
    const escalator = fakeEscalator();
    escalator.resolution = "approved";
    const allowStore = new InMemoryAllowStore(() => 1_000_000);
    const { gate: g } = gate({ escalator, allowStore });
    // no ip on the request → identity is ua:… (forgeable) → allow not persisted
    const first = await g.handle(inbound({ path: "/api/orders", ip: undefined }));
    expect(first.disposition).toBe("allow");
    expect(allowStore.get(`ua:curl/8.4.0`)).toBeUndefined();
  });
});

describe("Gate — fail-closed sealing + monitor truthfulness", () => {
  it("a throwing chain store still fails closed to challenge for agents (never allow)", async () => {
    const brokenChain = {
      getChainHead: () => undefined,
      appendReceipt: () => {
        throw new Error("chain store down");
      },
    };
    const g = new Gate({
      workspace_id: "ws1", policy: POLICY,
      signing: { key_id: key.key_id, privateKeyPem: key.privateKeyPem, chain: brokenChain },
      now: () => 1_000_000,
    });
    const r = await g.handle(inbound({ path: "/checkout" })); // policy → challenge, seal throws
    expect(r.disposition).toBe("challenge");
    // a human with the same broken chain still passes (never touches sealing)
    const human = await g.handle(inbound({ headers: { ...HUMAN } }));
    expect(human.disposition).toBe("allow");
  });

  it("a classifier crash disposes challenge with a classifier_error receipt, never allow", async () => {
    const g = new Gate({
      workspace_id: "ws1", policy: POLICY,
      signing: { key_id: key.key_id, privateKeyPem: key.privateKeyPem, chain: new InMemoryChainStore() },
      knownAgents: [{ id: "bad" } as never], // malformed registry entry → classify throws
      now: () => 1_000_000,
    });
    const r = await g.handle(inbound({ path: "/checkout" }));
    expect(r.disposition).toBe("challenge");
    expect(r.classification.signals).toContain("classifier_error");
  });

  it("monitor mode seals a truthful receipt (blocked verdict, marked monitored)", async () => {
    const { gate: g } = gate({ monitor: true });
    const r = await g.handle(inbound({ headers: { "user-agent": "Bytespider" }, path: "/z" }));
    expect(r.disposition).toBe("allow");
    expect(r.monitored).toBe(true);
    expect(r.receipt!.status).toBe("blocked"); // the policy verdict, truthfully
    expect(r.receipt!.reason).toMatch(/monitor: allowed through/);
    expect((r.receipt!.actor.evidence as Record<string, unknown>).monitor).toBe(true);
  });

  it("the sealed action_type is the bare path the policy evaluated (reproducible)", async () => {
    const { gate: g } = gate();
    const r = await g.handle(inbound({ method: "POST", headers: { "user-agent": "Bytespider" }, path: "/checkout" }));
    expect(r.receipt!.action_type).toBe("/checkout"); // not "POST /checkout"
  });
});
