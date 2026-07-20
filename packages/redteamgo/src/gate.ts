/**
 * The gate — RedTeamGo's pipeline: classify → standing decisions → policy →
 * verdict → signed receipt → disposition.
 *
 * Product rules the code must never drift from:
 *   - Humans always pass in v1. Red gates agent-classified traffic only; a
 *     middleware bug must not be able to block human customers.
 *   - Fail closed: an error anywhere in the pipeline disposes as `challenge`
 *     for agent-shaped traffic — never allow-by-crash. (Classification
 *     errors dispose as challenge too: we could not establish "human".)
 *   - Every enforcement decision on an agent is sealed into the same
 *     hash-linked receipt chain Green writes (actor.type "observed",
 *     decider.method "policy"/"auto").
 *   - `gate` means a human decides once per agent, not once per request:
 *     escalate via Green's rails, challenge while pending, then store the
 *     human's answer as a standing allow/block.
 */
import {
  seal,
  type ChainStore,
  type Receipt,
  type Risk,
} from "@vorionsys/greenteamgo-core";
import {
  evaluate,
  receiptOutcome,
  type Policy,
  type PolicyDecision,
} from "@vorionsys/greenteamgo-policy";

import { classify, type Classification, type ClassifyOptions, type InboundRequest } from "./classify.js";
import {
  InMemoryAllowStore,
  type AllowStore,
  type Escalation,
  type Escalator,
} from "./escalate.js";

/** What the middleware should do with the request. */
export type Disposition = "allow" | "block" | "challenge";

/** In-memory implementation of core's ChainStore (dev/test); production
 * points at the same store Green uses (its Store satisfies ChainStore) so
 * both products write ONE chain per workspace. */
export class InMemoryChainStore implements ChainStore {
  private heads = new Map<string, string>();
  private logs = new Map<string, Receipt[]>();
  getChainHead(ws: string): string | undefined {
    return this.heads.get(ws);
  }
  appendReceipt(ws: string, receipt: Receipt): void {
    this.heads.set(ws, receipt.receipt_hash);
    const log = this.logs.get(ws) ?? [];
    log.push(receipt);
    this.logs.set(ws, log);
  }
  listReceipts(ws: string): Receipt[] {
    return [...(this.logs.get(ws) ?? [])];
  }
}

export interface ReceiptSigning {
  key_id: string;
  privateKeyPem: string;
  chain: ChainStore;
}

export interface GateOptions extends ClassifyOptions {
  workspace_id: string;
  /** versioned policy from @vorionsys/greenteamgo-policy; rules match on
   * action_type = path, plus tags like "class:suspected_agent", "method:POST" */
  policy: Policy;
  /** receipts are sealed when present; omit for receipt-less dev mode */
  signing?: ReceiptSigning;
  /** which decisions get receipts: "agents" = every verdict on agent-classified
   * traffic (default), "non_allow" = only block/challenge, "off" = none */
  receipt_mode?: "agents" | "non_allow" | "off";
  /** human-decides transport; without one, `gate` effects challenge (fail closed) */
  escalator?: Escalator;
  /** standing allow/block decisions from resolved escalations */
  allowStore?: AllowStore;
  /** standing-allow lifetime in seconds (default 24h) */
  standing_ttl_s?: number;
  /** report-only mode: classify, evaluate, seal receipts — but always allow */
  monitor?: boolean;
  now?: () => number;
}

export interface GateResult {
  disposition: Disposition;
  classification: Classification;
  /** policy decision that produced the disposition (absent on fast paths) */
  policy?: PolicyDecision;
  receipt?: Receipt;
  escalation?: Escalation;
  /** why this disposition, in one line — for logs and challenge bodies */
  reason: string;
  /** true when monitor mode overrode a block/challenge to allow */
  monitored?: boolean;
}

const CLASS_RISK: Record<Classification["class"], Risk> = {
  verified_agent: "low",
  declared_bot: "medium",
  suspected_agent: "high",
  human: "low",
};

export class Gate {
  private allowStore: AllowStore;
  private now: () => number;

  constructor(private opts: GateOptions) {
    this.now = opts.now ?? (() => Date.now());
    this.allowStore = opts.allowStore ?? new InMemoryAllowStore(this.now);
  }

  async handle(req: InboundRequest): Promise<GateResult> {
    let cls: Classification;
    try {
      cls = await classify(req, this.opts);
    } catch (err) {
      // Cannot establish what this is → treat as an unidentified agent.
      cls = {
        class: "suspected_agent",
        confidence: "heuristic",
        signals: ["classifier_error"],
        evidence: { error: (err as Error).message },
      };
    }

    try {
      return await this.decide(req, cls);
    } catch (err) {
      // Pipeline failure on agent traffic: challenge, never allow-by-crash.
      const result: GateResult = {
        disposition: cls.class === "human" ? "allow" : "challenge",
        classification: cls,
        reason: `gate error (fail closed): ${(err as Error).message}`,
      };
      return this.applyMonitor(result);
    }
  }

  private async decide(req: InboundRequest, cls: Classification): Promise<GateResult> {
    // Humans always pass — no policy, no receipt, no exceptions in v1.
    if (cls.class === "human") {
      return { disposition: "allow", classification: cls, reason: "human traffic passes" };
    }

    const identity = this.identityOf(req, cls);

    // A human already ruled on this agent — honor the standing decision.
    const standing = this.allowStore.get(identity);
    if (standing) {
      const disposition = standing.effect === "allow" ? "allow" : "block";
      const reason = `standing ${standing.effect} from human decision`;
      const receipt = this.maybeSeal(req, cls, disposition, {
        verdict: standing.effect === "allow" ? "approve" : "deny",
        method: "auto",
        deciderId: standing.source_request_id,
        reason,
      });
      return this.applyMonitor({ disposition, classification: cls, receipt, reason });
    }

    const decision = evaluate(this.opts.policy, {
      action_type: req.path,
      risk: CLASS_RISK[cls.class],
      actor_type: "observed",
      tags: [
        `class:${cls.class}`,
        `method:${req.method.toUpperCase()}`,
        `confidence:${cls.confidence}`,
        ...(cls.agent_id ? [`agent:${cls.agent_id}`] : []),
      ],
    });

    if (decision.effect === "gate") {
      return this.applyMonitor(await this.escalate(req, cls, identity, decision));
    }

    // allow / deny / challenge: machine-decided, one shared mapping (the same
    // one Green uses) from effect to the sealed (verdict, status).
    const outcome = receiptOutcome(decision.effect, "inbound");
    const disposition: Disposition =
      decision.effect === "allow" ? "allow" : decision.effect === "deny" ? "block" : "challenge";
    const receipt = this.maybeSeal(req, cls, disposition, {
      verdict: outcome.verdict,
      method: "policy",
      deciderId: decision.policy_id,
      reason: reasonFor(decision),
      policy: decision,
    });
    return this.applyMonitor({
      disposition,
      classification: cls,
      policy: decision,
      receipt,
      reason: reasonFor(decision),
    });
  }

  /** `gate`: page the human through Green once per identity; challenged until
   * they answer; their answer becomes a standing decision. */
  private async escalate(
    req: InboundRequest,
    cls: Classification,
    identity: string,
    decision: PolicyDecision,
  ): Promise<GateResult> {
    if (!this.opts.escalator) {
      const reason = "policy gates this path but no escalator is configured (fail closed)";
      const receipt = this.maybeSeal(req, cls, "challenge", {
        verdict: "challenge",
        method: "auto",
        reason,
        policy: decision,
      });
      return { disposition: "challenge", classification: cls, policy: decision, receipt, reason };
    }

    const escalation = await this.opts.escalator.escalate({
      identity,
      method: req.method,
      path: req.path,
      workspace_id: this.opts.workspace_id,
      evidence: cls.evidence,
      signals: cls.signals,
    });

    if (escalation.status === "pending") {
      const reason = "escalated to human; challenged until decided (fail closed)";
      const receipt = this.maybeSeal(req, cls, "challenge", {
        verdict: "gate",
        method: "auto",
        deciderId: escalation.request_id,
        reason,
        policy: decision,
      });
      return {
        disposition: "challenge",
        classification: cls,
        policy: decision,
        receipt,
        escalation,
        reason,
      };
    }

    const approved = escalation.status === "approved";
    this.allowStore.put(identity, {
      effect: approved ? "allow" : "block",
      expires_at: this.now() + (this.opts.standing_ttl_s ?? 86400) * 1000,
      source_request_id: escalation.request_id,
    });
    const reason = approved
      ? "human approved this agent (standing allow created)"
      : "human denied this agent (standing block created)";
    const receipt = this.maybeSeal(req, cls, approved ? "allow" : "block", {
      verdict: approved ? "approve" : "deny",
      method: "app",
      deciderId: escalation.request_id,
      reason,
      policy: decision,
    });
    return {
      disposition: approved ? "allow" : "block",
      classification: cls,
      policy: decision,
      receipt,
      escalation,
      reason,
    };
  }

  /** Stable identity for standing decisions and escalation dedup. */
  private identityOf(req: InboundRequest, cls: Classification): string {
    if (cls.agent_id) return cls.agent_id;
    if (req.ip) return `ip:${req.ip}`;
    return `ua:${req.headers["user-agent"] ?? "unknown"}`;
  }

  private maybeSeal(
    req: InboundRequest,
    cls: Classification,
    disposition: Disposition,
    d: {
      verdict: "approve" | "deny" | "gate" | "challenge";
      method: "app" | "policy" | "auto";
      deciderId?: string;
      reason?: string;
      policy?: PolicyDecision;
    },
  ): Receipt | undefined {
    const mode = this.opts.receipt_mode ?? "agents";
    if (!this.opts.signing || mode === "off") return undefined;
    if (mode === "non_allow" && disposition === "allow") return undefined;

    const nowIso = new Date(this.now()).toISOString();
    const status =
      disposition === "allow" ? "approved" : disposition === "block" ? "blocked" : "challenged";
    const receipt = seal(
      {
        request_id: `red_${cryptoRandomId()}`,
        workspace_id: this.opts.workspace_id,
        actor: { type: "observed", id: cls.agent_id, evidence: { ...cls.evidence, signals: cls.signals } },
        action_type: `${req.method.toUpperCase()} ${req.path}`,
        verdict: d.verdict,
        status,
        risk: d.policy?.risk ?? CLASS_RISK[cls.class],
        policy_id: d.policy?.policy_id,
        policy_version: d.policy?.policy_version,
        decider: { method: d.method, id: d.deciderId },
        reason: d.reason,
        created_at: nowIso,
        decided_at: nowIso,
      },
      {
        keyId: this.opts.signing.key_id,
        privateKeyPem: this.opts.signing.privateKeyPem,
        prevHash: this.opts.signing.chain.getChainHead(this.opts.workspace_id),
      },
    );
    this.opts.signing.chain.appendReceipt(this.opts.workspace_id, receipt);
    return receipt;
  }

  /** Monitor mode: keep the verdict + receipt, but let the request through. */
  private applyMonitor(result: GateResult): GateResult {
    if (this.opts.monitor && result.disposition !== "allow") {
      return { ...result, disposition: "allow", monitored: true };
    }
    return result;
  }
}

function reasonFor(d: PolicyDecision): string {
  return d.matched_rule_id
    ? `policy ${d.policy_id} v${d.policy_version} rule ${d.matched_rule_id}: ${d.effect}`
    : `policy ${d.policy_id} v${d.policy_version} default: ${d.effect}`;
}

function cryptoRandomId(): string {
  return globalThis.crypto.randomUUID();
}
