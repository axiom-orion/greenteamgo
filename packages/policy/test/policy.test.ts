import { describe, expect, it } from "vitest";

import { evaluate, isTerminal, type Policy } from "../src/policy.js";

const policy: Policy = {
  id: "pol_1",
  workspace_id: "ws1",
  version: 3,
  default_effect: "gate",
  rules: [
    { id: "r_read", action_type: "file_read", effect: "allow", risk_class: "low" },
    { id: "r_pay", action_type: "payment", effect: "deny" },
    { id: "r_shell_hi", action_type: "shell_*", min_risk: "high", effect: "gate" },
    { id: "r_shell_lo", action_type: "shell_*", effect: "allow", risk_class: "low" },
    { id: "r_observed", actor_type: "observed", effect: "challenge" },
  ],
};

describe("policy.evaluate", () => {
  it("auto-allows a matched low-risk read", () => {
    const d = evaluate(policy, { action_type: "file_read" });
    expect(d.effect).toBe("allow");
    expect(d.risk).toBe("low");
    expect(d.matched_rule_id).toBe("r_read");
    expect(d.policy_version).toBe(3);
    expect(isTerminal(d.effect)).toBe(true);
  });

  it("auto-denies a blocked action type", () => {
    expect(evaluate(policy, { action_type: "payment", risk: "critical" }).effect).toBe("deny");
  });

  it("first match wins: high-risk shell gates, low-risk shell auto-allows", () => {
    expect(evaluate(policy, { action_type: "shell_exec", risk: "critical" }).matched_rule_id).toBe("r_shell_hi");
    expect(evaluate(policy, { action_type: "shell_exec", risk: "low" }).matched_rule_id).toBe("r_shell_lo");
  });

  it("respects the min_risk threshold", () => {
    // medium-risk shell falls THROUGH r_shell_hi (needs >= high) to r_shell_lo
    const d = evaluate(policy, { action_type: "shell_exec", risk: "medium" });
    expect(d.matched_rule_id).toBe("r_shell_lo");
    expect(d.effect).toBe("allow");
  });

  it("challenges an observed (Red) actor regardless of action", () => {
    expect(evaluate(policy, { action_type: "GET /api/orders", actor_type: "observed" }).effect).toBe("challenge");
  });

  it("falls back to default_effect (gate) with no matched rule id", () => {
    const d = evaluate(policy, { action_type: "git_push", risk: "high" });
    expect(d.effect).toBe("gate");
    expect(d.matched_rule_id).toBeUndefined();
    expect(isTerminal(d.effect)).toBe(false);
  });

  it("carries the declared risk when no rule assigns a class", () => {
    expect(evaluate(policy, { action_type: "git_push", risk: "high" }).risk).toBe("high");
  });
});
