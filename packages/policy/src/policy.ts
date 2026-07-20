/**
 * Policy module — versioned rules that decide an event's fate before a human is
 * ever paged: allow (auto-approve), deny (auto-block), gate (ask the human), or
 * challenge (Red's inbound equivalent). First matching rule wins; if none
 * matches, the policy's `default_effect` applies.
 *
 * The safe default is `gate` for GreenTeamGo (cooperative/outbound — when in
 * doubt, ask) and would be `challenge` for RedTeamGo (adversarial/inbound).
 * Auto-decisions still produce a signed receipt (decider.method "policy"/"auto")
 * so the audit chain is complete whether or not a human was involved.
 */
import type { ActorType, Risk } from "@vorionsys/greenteamgo-core";

/** allow == auto-approve, deny == auto-block, gate == ask human, challenge (Red). */
export type Effect = "allow" | "deny" | "gate" | "challenge";

const RISK_ORDER: Record<Risk, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export interface PolicyEvent {
  action_type: string;
  /** caller-declared risk hint (a rule may override via risk_class) */
  risk?: Risk;
  actor_type?: ActorType;
  /** free-form dimensions beyond action_type, e.g. Red's inbound traffic
   * tags: "class:suspected_agent", "method:POST", "agent:gptbot" */
  tags?: string[];
}

export interface Rule {
  id: string;
  /** exact ("git_push"), wildcard ("*"), or prefix glob ("shell_*") */
  action_type?: string;
  /** event risk must be at least this */
  min_risk?: Risk;
  actor_type?: ActorType;
  /** every listed tag must be present on the event (AND semantics) */
  tags?: string[];
  effect: Effect;
  /** assign/override the risk class carried into the receipt */
  risk_class?: Risk;
}

export interface Policy {
  id: string;
  workspace_id: string;
  version: number;
  default_effect: Effect;
  rules: Rule[];
}

export interface PolicyDecision {
  effect: Effect;
  risk: Risk;
  policy_id: string;
  policy_version: number;
  /** id of the rule that matched; undefined means the default_effect applied */
  matched_rule_id?: string;
}

function actionMatches(pattern: string | undefined, actionType: string): boolean {
  if (pattern === undefined || pattern === "*") return true;
  if (pattern.endsWith("*")) return actionType.startsWith(pattern.slice(0, -1));
  return pattern === actionType;
}

function ruleMatches(rule: Rule, event: PolicyEvent): boolean {
  if (!actionMatches(rule.action_type, event.action_type)) return false;
  if (rule.actor_type && rule.actor_type !== (event.actor_type ?? "agent_key")) return false;
  if (rule.min_risk) {
    const eventRisk = event.risk ?? "medium";
    if (RISK_ORDER[eventRisk] < RISK_ORDER[rule.min_risk]) return false;
  }
  if (rule.tags && !rule.tags.every((t) => event.tags?.includes(t))) return false;
  return true;
}

/** Evaluate an event against a policy. First matching rule wins. */
export function evaluate(policy: Policy, event: PolicyEvent): PolicyDecision {
  for (const rule of policy.rules) {
    if (ruleMatches(rule, event)) {
      return {
        effect: rule.effect,
        risk: rule.risk_class ?? event.risk ?? "medium",
        policy_id: policy.id,
        policy_version: policy.version,
        matched_rule_id: rule.id,
      };
    }
  }
  return {
    effect: policy.default_effect,
    risk: event.risk ?? "medium",
    policy_id: policy.id,
    policy_version: policy.version,
  };
}

/** True when the effect is terminal (auto-decided, no human needed). */
export function isTerminal(effect: Effect): boolean {
  return effect === "allow" || effect === "deny";
}

/**
 * The ONE mapping from a machine-decided effect to the receipt (verdict,
 * status) both products seal. Green is "outbound" (deny → denied), Red is
 * "inbound" (deny → blocked). `gate` is deliberately absent: it is not
 * terminal — its receipt shape depends on the product's escalation lifecycle.
 */
export function receiptOutcome(
  effect: "allow" | "deny" | "challenge",
  direction: "outbound" | "inbound",
): { verdict: "approve" | "deny" | "challenge"; status: "approved" | "denied" | "blocked" | "challenged" } {
  switch (effect) {
    case "allow":
      return { verdict: "approve", status: "approved" };
    case "deny":
      return { verdict: "deny", status: direction === "inbound" ? "blocked" : "denied" };
    case "challenge":
      return { verdict: "challenge", status: "challenged" };
  }
}
