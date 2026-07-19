/**
 * Policy wired into the request lifecycle: auto-decisions produce receipts with
 * no human paged; only gated actions page. Uses the real @vorionsys/greenteamgo-policy.
 */
import { describe, expect, it } from "vitest";

import { generateSignerKeyPair, verifyReceipt } from "@vorionsys/greenteamgo-core";
import { evaluate, type Policy } from "@vorionsys/greenteamgo-policy";

import { RequestService, type CreateInput, type Notifier } from "../src/service.js";
import { InMemoryStore, type ApiKeyRecord, type RequestRecord } from "../src/store.js";

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
  const agentKey: ApiKeyRecord = { api_key: "sk_agent", workspace_id: "ws1", scopes: ["green:create", "green:read"] };
  store.seedWorkspace("ws1", agentKey, signing);
  const paged: RequestRecord[] = [];
  const notifier: Notifier = { notify: (r) => void paged.push(r) };
  const service = new RequestService({
    store,
    notifier,
    policy: { evaluate: (e) => evaluate(POLICY, e) },
  });
  return { service, agentKey, signing, paged };
}

const base: CreateInput = { action_type: "x", summary: "s", risk: "medium", timeout_s: 900, mode: "block" };

describe("policy-driven lifecycle", () => {
  it("auto-APPROVES a policy-allowed action with a signed receipt, no human paged", async () => {
    const { service, agentKey, signing, paged } = seed();
    const rec = await service.create(agentKey, { ...base, action_type: "file_read" });
    expect(rec.status).toBe("approved");
    expect(rec.receipt).toBeDefined();
    expect(rec.receipt!.decider.method).toBe("policy");
    expect(rec.receipt!.policy_id).toBe("pol_1");
    expect(rec.risk).toBe("low"); // reclassified by the rule
    expect(verifyReceipt(rec.receipt!, signing.publicKeyPem)).toEqual({ ok: true });
    expect(paged).toHaveLength(0);
  });

  it("auto-DENIES a policy-denied action, no human paged", async () => {
    const { service, agentKey, paged } = seed();
    const rec = await service.create(agentKey, { ...base, action_type: "payment", risk: "critical" });
    expect(rec.status).toBe("denied");
    expect(rec.receipt!.verdict).toBe("deny");
    expect(paged).toHaveLength(0);
  });

  it("GATES an un-ruled action: stays pending and pages the human", async () => {
    const { service, agentKey, paged } = seed();
    const rec = await service.create(agentKey, { ...base, action_type: "git_push", risk: "high" });
    expect(rec.status).toBe("pending");
    expect(rec.receipt).toBeUndefined();
    expect(paged).toHaveLength(1);
  });

  it("chains an auto-decision and a later human decision into one chain", async () => {
    const { service, agentKey, signing } = seed();
    const auto = await service.create(agentKey, { ...base, action_type: "file_read" });
    const gated = await service.create(agentKey, { ...base, action_type: "git_push" });
    // add a decide-capable key and approve the gated one
    // (reuse the service's store via a decide scope)
    const appKey: ApiKeyRecord = { api_key: "sk_app", workspace_id: "ws1", scopes: ["green:decide"] };
    (service as unknown as { store: InMemoryStore }).store.addApiKey(appKey);
    const human = await service.decide(appKey, gated.request_id, "approved", { deciderId: "u1" });
    expect(human.receipt!.prev_hash).toBe(auto.receipt!.receipt_hash);
    expect(verifyReceipt(human.receipt!, signing.publicKeyPem)).toEqual({ ok: true });
  });
});
