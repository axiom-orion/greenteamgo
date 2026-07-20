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
    expect(r.receipt!.action_type).toBe("GET /blog");
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
  function fakeEscalator(): Escalator & { calls: number; resolution: "pending" | "approved" | "denied" } {
    const esc = {
      calls: 0,
      resolution: "pending" as "pending" | "approved" | "denied",
      async escalate(): Promise<Escalation> {
        esc.calls++;
        return { request_id: "req_esc_1", status: esc.resolution };
      },
      async check(): Promise<"pending" | "approved" | "denied"> {
        return esc.resolution;
      },
    };
    return esc;
  }

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
      check: async () => "pending",
    };
    const { gate: g } = gate({ escalator });
    const r = await g.handle(inbound({ path: "/api/orders" }));
    expect(r.disposition).toBe("challenge");
    expect(r.reason).toMatch(/fail closed/);
  });
});
