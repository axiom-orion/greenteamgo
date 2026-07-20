import { describe, expect, it } from "vitest";

import { evaluate, isTerminal, receiptOutcome, type Policy } from "../src/policy.js";

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

describe("action_type glob semantics", () => {
  const p = (rules: Policy["rules"]): Policy => ({
    id: "pol_g",
    workspace_id: "ws1",
    version: 1,
    default_effect: "gate",
    rules,
  });

  it('a bare "*" rule matches any action', () => {
    const d = evaluate(p([{ id: "r", action_type: "*", effect: "deny" }]), { action_type: "anything" });
    expect(d.matched_rule_id).toBe("r");
  });

  it("an exact pattern must NOT prefix-match", () => {
    const d = evaluate(p([{ id: "r", action_type: "shell", effect: "deny" }]), { action_type: "shell_exec" });
    expect(d.matched_rule_id).toBeUndefined();
  });

  it('prefix glob boundaries: "shell_*" matches "shell_" but not "shellx"', () => {
    const rules = p([{ id: "r", action_type: "shell_*", effect: "deny" }]);
    expect(evaluate(rules, { action_type: "shell_" }).matched_rule_id).toBe("r");
    expect(evaluate(rules, { action_type: "shellx" }).matched_rule_id).toBeUndefined();
  });

  it('an empty-string pattern matches only the empty action, not everything', () => {
    const rules = p([{ id: "r", action_type: "", effect: "deny" }]);
    expect(evaluate(rules, { action_type: "" }).matched_rule_id).toBe("r");
    expect(evaluate(rules, { action_type: "x" }).matched_rule_id).toBeUndefined();
  });
});

describe("tags (Red's extra match dimensions)", () => {
  const redPolicy: Policy = {
    id: "pol_red",
    workspace_id: "ws1",
    version: 1,
    default_effect: "allow",
    rules: [
      // "unverified agent on /checkout → challenge"
      { id: "r_checkout", action_type: "/checkout*", tags: ["class:suspected_agent"], effect: "challenge" },
      { id: "r_api_post", action_type: "/api/*", tags: ["method:POST", "class:declared_bot"], effect: "gate" },
    ],
  };

  it("matches when every rule tag is present on the event", () => {
    const d = evaluate(redPolicy, {
      action_type: "/checkout",
      actor_type: "observed",
      tags: ["class:suspected_agent", "method:GET"],
    });
    expect(d.effect).toBe("challenge");
    expect(d.matched_rule_id).toBe("r_checkout");
  });

  it("does not match when any rule tag is missing (AND semantics)", () => {
    const d = evaluate(redPolicy, {
      action_type: "/api/orders",
      tags: ["method:GET", "class:declared_bot"], // wrong method
    });
    expect(d.matched_rule_id).toBeUndefined();
    expect(d.effect).toBe("allow"); // default
  });

  it("a rule without tags ignores event tags (Green events unaffected)", () => {
    const d = evaluate(policy, { action_type: "file_read", tags: ["anything:at_all"] });
    expect(d.matched_rule_id).toBe("r_read");
  });

  it("a tagged rule never matches a tagless event", () => {
    const d = evaluate(redPolicy, { action_type: "/checkout" });
    expect(d.matched_rule_id).toBeUndefined();
  });
});

describe("receiptOutcome (the shared effect→receipt mapping)", () => {
  it("maps identically for both products except deny's status", () => {
    expect(receiptOutcome("allow", "outbound")).toEqual({ verdict: "approve", status: "approved" });
    expect(receiptOutcome("allow", "inbound")).toEqual({ verdict: "approve", status: "approved" });
    expect(receiptOutcome("deny", "outbound")).toEqual({ verdict: "deny", status: "denied" });
    expect(receiptOutcome("deny", "inbound")).toEqual({ verdict: "deny", status: "blocked" });
    expect(receiptOutcome("challenge", "outbound")).toEqual({ verdict: "challenge", status: "challenged" });
    expect(receiptOutcome("challenge", "inbound")).toEqual({ verdict: "challenge", status: "challenged" });
  });
});
