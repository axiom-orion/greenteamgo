/** Compile plain-English workspace rules into the existing policy format. */
import type { ActorType, Risk } from "@vorionsys/greenteamgo-core";

import type { Effect, Policy, Rule } from "./policy.js";

const OPENAI_URL = "https://api.openai.com/v1/chat/completions";
const MODEL = process.env.OPENAI_MODEL ?? "gpt-5.6-luna";

const EFFECTS = new Set<Effect>(["allow", "deny", "gate", "challenge"]);
const RISKS = new Set<Risk>(["low", "medium", "high", "critical"]);
const ACTOR_TYPES = new Set<ActorType>(["agent_key", "observed"]);
const RULE_KEYS = new Set(["id", "action_type", "min_risk", "actor_type", "tags", "effect", "risk_class"]);

const SYSTEM = `You translate a workspace owner's natural-language rules into policy rules.
Return ONLY a JSON array. Each item must have this exact shape:
{"id": string, "action_type"?: string, "min_risk"?: "low"|"medium"|"high"|"critical", "actor_type"?: "agent_key"|"observed", "tags"?: string[], "effect": "allow"|"deny"|"gate"|"challenge", "risk_class"?: "low"|"medium"|"high"|"critical"}.
Use concise, stable rule IDs. Do not include markdown, explanations, policy metadata, or fields not listed above.`;

export interface CompilePolicyOptions {
  /** Metadata for the policy candidate; it is not persisted or activated. */
  id?: string;
  workspace_id?: string;
  version?: number;
  /** Allows callers and tests to provide a compatible fetch implementation. */
  fetchFn?: typeof fetch;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function invalidRule(index: number, message: string): never {
  throw new Error(`Invalid policy rule at index ${index}: ${message}`);
}

function validateRule(value: unknown, index: number): Rule {
  if (!isRecord(value)) invalidRule(index, "must be an object");
  for (const key of Object.keys(value)) {
    if (!RULE_KEYS.has(key)) invalidRule(index, `unexpected field ${key}`);
  }
  if (typeof value.id !== "string" || value.id.trim() === "") invalidRule(index, "id must be a non-empty string");
  if (!EFFECTS.has(value.effect as Effect)) invalidRule(index, "effect must be allow, deny, gate, or challenge");

  if (value.action_type !== undefined && typeof value.action_type !== "string") {
    invalidRule(index, "action_type must be a string");
  }
  if (value.min_risk !== undefined && !RISKS.has(value.min_risk as Risk)) {
    invalidRule(index, "min_risk must be low, medium, high, or critical");
  }
  if (value.risk_class !== undefined && !RISKS.has(value.risk_class as Risk)) {
    invalidRule(index, "risk_class must be low, medium, high, or critical");
  }
  if (value.actor_type !== undefined && !ACTOR_TYPES.has(value.actor_type as ActorType)) {
    invalidRule(index, "actor_type must be agent_key or observed");
  }
  if (value.tags !== undefined && (!Array.isArray(value.tags) || value.tags.some((tag) => typeof tag !== "string"))) {
    invalidRule(index, "tags must be an array of strings");
  }

  return {
    id: value.id,
    effect: value.effect as Effect,
    ...(value.action_type === undefined ? {} : { action_type: value.action_type }),
    ...(value.min_risk === undefined ? {} : { min_risk: value.min_risk as Risk }),
    ...(value.actor_type === undefined ? {} : { actor_type: value.actor_type as ActorType }),
    ...(value.tags === undefined ? {} : { tags: value.tags as string[] }),
    ...(value.risk_class === undefined ? {} : { risk_class: value.risk_class as Risk }),
  };
}

/**
 * Ask GPT-5.6 to compile a policy candidate. The returned Policy is validated
 * locally and is never persisted or connected to the request pipeline.
 */
export async function compilePolicy(text: string, opts: CompilePolicyOptions = {}): Promise<Policy> {
  if (typeof text !== "string" || text.trim() === "") throw new Error("Policy text must be a non-empty string");
  const key = process.env.OPENAI_API_KEY;
  if (!key) throw new Error("OPENAI_API_KEY is required to compile a policy");

  const fetchFn = opts.fetchFn ?? fetch;
  const response = await fetchFn(OPENAI_URL, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify({
      model: MODEL,
      messages: [
        { role: "system", content: SYSTEM },
        { role: "user", content: text },
      ],
      max_completion_tokens: 800,
    }),
  });
  if (!response.ok) throw new Error(`OpenAI policy compilation failed (${response.status})`);

  const data = await response.json() as { choices?: { message?: { content?: string } }[] };
  const content = data.choices?.[0]?.message?.content?.trim();
  if (!content) throw new Error("OpenAI policy compilation returned no JSON");

  let candidate: unknown;
  try {
    candidate = JSON.parse(content);
  } catch {
    throw new Error("OpenAI policy compilation returned invalid JSON");
  }
  if (!Array.isArray(candidate)) throw new Error("OpenAI policy compilation must return a JSON array of rules");

  const rules = candidate.map(validateRule);
  return {
    id: opts.id ?? "pol_nl",
    workspace_id: opts.workspace_id ?? "default",
    version: opts.version ?? 1,
    default_effect: "gate",
    rules,
  };
}
