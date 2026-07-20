/**
 * Policy wired into the request lifecycle: auto-decisions produce receipts with
 * no human paged; only gated actions page. Uses the real @vorionsys/greenteamgo-policy.
 */
import { describe, expect, it } from "vitest";

import { generateSignerKeyPair, verifyReceipt } from "@vorionsys/greenteamgo-core";
import { evaluate, type Policy } from "@vorionsys/greenteamgo-policy";

import { RequestService, type CreateInput, type Notifier } from "../src/service.js";
import { InMemoryStore, type RequestRecord } from "../src/store.js";

const POLICY: Policy = {
  id: "pol_1",
  workspace_id: "ws1",
  version: 2,
  default_effect: "gate",
  rules: [
    { id: "r_read", action_type: "file_read", effect: "allow", risk_class: "low" },
    { id: "r_pay", action_type: "payment", effect: "deny" },
    // git_push has no rule → default gate (pages the human)
  ],
};

function seed() {
  const store = new InMemoryStore();
  const signing = generateSignerKeyPair("ws1_key");
  store.seedWorkspace(
    "ws1",
    { api_key: "sk_agent", workspace_id: "ws1", scopes: ["green:create", "green:read"] },
    signing,
  );
  const paged: RequestRecord[] = [];
  const notifier: Notifier = { notify: (r) => void paged.push(r) };
  const service = new RequestService({
    store,
    notifier,
    policy: { evaluate: (e) => evaluate(POLICY, e) },
  });
  const agentKey = store.resolveApiKey("sk_agent")!;
  return { store, service, agentKey, signing, paged };
}

const base: CreateInput = { action_type: "x", summary: "s", risk: "medium", timeout_s: 900, mode: "block" };

describe("policy-driven lifecycle", () => {
  it("auto-APPROVES a policy-allowed action with a signed receipt, no human paged", async () => {
    const { service, agentKey, signing, paged } = seed();
    const rec = await service.create(agentKey, { ...base, action_type: "file_read" });
    expect(rec.status).toBe("approved");
    expect(rec.receipt).toBeDefined();
    expect(rec.receipt!.decider).toEqual({ method: "policy", id: "pol_1" });
    expect(rec.receipt!.policy_id).toBe("pol_1");
    expect(rec.receipt!.policy_version).toBe(2);
    expect(rec.risk).toBe("low"); // reclassified by the rule
    expect(verifyReceipt(rec.receipt!, signing.publicKeyPem)).toEqual({ ok: true });
    expect(paged).toHaveLength(0);
  });

  it("auto-DENIES a policy-denied action, no human paged — full decider provenance on the receipt", async () => {
    const { service, agentKey, paged } = seed();
    const rec = await service.create(agentKey, { ...base, action_type: "payment", risk: "critical" });
    expect(rec.status).toBe("denied");
    expect(rec.receipt!.verdict).toBe("deny");
    expect(rec.receipt!.status).toBe("denied");
    expect(rec.receipt!.decider).toEqual({ method: "policy", id: "pol_1" });
    expect(rec.receipt!.policy_id).toBe("pol_1");
    expect(rec.receipt!.policy_version).toBe(2);
    expect(paged).toHaveLength(0);
  });

  it("GATES an un-ruled action: stays pending, pages the human, carries policy provenance", async () => {
    const { service, agentKey, paged } = seed();
    const rec = await service.create(agentKey, { ...base, action_type: "git_push", risk: "high" });
    expect(rec.status).toBe("pending");
    expect(rec.receipt).toBeUndefined();
    expect(rec.policy_id).toBe("pol_1");
    expect(rec.policy_version).toBe(2);
    expect(rec.policy_effect).toBe("gate");
    expect(paged).toHaveLength(1);
  });

  it("replaying an auto-decided create returns the SAME receipt without re-sealing", async () => {
    const { service, store, agentKey, paged } = seed();
    const a = await service.create(agentKey, { ...base, action_type: "file_read", idempotency_key: "k1" });
    const b = await service.create(agentKey, { ...base, action_type: "file_read", idempotency_key: "k1" });
    expect(b.receipt!.receipt_hash).toBe(a.receipt!.receipt_hash);
    expect(store.listReceipts("ws1")).toHaveLength(1); // chain advanced exactly once
    expect(paged).toHaveLength(0);
  });

  it("chains an auto-decision and a later human decision into one chain", async () => {
    const { service, store, agentKey, signing } = seed();
    const auto = await service.create(agentKey, { ...base, action_type: "file_read" });
    const gated = await service.create(agentKey, { ...base, action_type: "git_push" });
    // add a decide-capable key and approve the gated one
    store.addApiKey({ api_key: "sk_app", workspace_id: "ws1", scopes: ["green:decide"] });
    const appKey = store.resolveApiKey("sk_app")!;
    const human = await service.decide(appKey, gated.request_id, "approved", { deciderId: "u1" });
    expect(human.receipt!.prev_hash).toBe(auto.receipt!.receipt_hash);
    expect(human.receipt!.policy_id).toBe("pol_1"); // the gate decision keeps its policy provenance
    expect(human.receipt!.policy_version).toBe(2);
    expect(verifyReceipt(human.receipt!, signing.publicKeyPem)).toEqual({ ok: true });
  });
});
