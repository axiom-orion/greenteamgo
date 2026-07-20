/**
 * Escalation — the suite's selling loop. A `gate` effect means "a human
 * decides": the access request rides GreenTeamGo's approval rails to the
 * phone, and until the human answers, the agent stays challenged (fail
 * closed). The human's approval becomes a STANDING allow; a denial becomes a
 * standing block — either way the phone is paged once per agent, not once
 * per request.
 *
 * No background timers: like Green's lazy expiry, resolution is checked
 * lazily on the next request from the same agent. Middleware must not own
 * long-lived processes.
 */

export type EscalationStatus = "pending" | "approved" | "denied";

export interface EscalationRequest {
  /** stable identity being escalated (agent_id or ip:<addr> fallback) */
  identity: string;
  /** what they were trying to reach, for the human's context */
  method: string;
  path: string;
  workspace_id: string;
  /** classifier evidence, shown to the human and recorded in the receipt */
  evidence: Record<string, unknown>;
  signals: string[];
}

export interface Escalation {
  request_id: string;
  status: EscalationStatus;
}

/** Pluggable escalation transport. GreenInboxEscalator is the real one;
 * tests use an in-memory fake. */
export interface Escalator {
  /** Create (or return the existing) escalation for this identity. */
  escalate(req: EscalationRequest): Promise<Escalation>;
  /** Lazily re-check a pending escalation's status. */
  check(requestId: string): Promise<EscalationStatus>;
}

/** Standing decisions produced by resolved escalations. */
export interface StandingDecision {
  effect: "allow" | "block";
  /** ms epoch after which the standing decision lapses */
  expires_at: number;
  /** receipt/request id of the human decision that created it */
  source_request_id?: string;
}

export interface AllowStore {
  get(identity: string): StandingDecision | undefined;
  put(identity: string, decision: StandingDecision): void;
}

/** In-memory AllowStore with lazy TTL expiry (test/dev backend; Redis/Postgres
 * adapters slot in behind the same interface). */
export class InMemoryAllowStore implements AllowStore {
  private map = new Map<string, StandingDecision>();
  constructor(private now: () => number = () => Date.now()) {}

  get(identity: string): StandingDecision | undefined {
    const d = this.map.get(identity);
    if (!d) return undefined;
    if (this.now() > d.expires_at) {
      this.map.delete(identity);
      return undefined;
    }
    return d;
  }
  put(identity: string, decision: StandingDecision): void {
    this.map.set(identity, decision);
  }
}

export interface GreenInboxEscalatorOptions {
  /** Green inbox API base, e.g. "https://api.greenteamgo.app" */
  apiUrl: string;
  /** api key with green:create + green:read (red:escalate rides green rails) */
  apiKey: string;
  /** seconds before an unanswered escalation expires (expiry = deny) */
  timeoutS?: number;
  fetchFn?: typeof fetch;
}

/**
 * Escalates through GreenTeamGo's inbox API: POST /v1/requests with
 * mode:"async", then lazy GET /v1/requests/:id checks. An expired request is
 * a deny — Green's fail-closed expiry does the bookkeeping for us.
 */
export class GreenInboxEscalator implements Escalator {
  private fetchFn: typeof fetch;
  private byIdentity = new Map<string, Escalation>();

  constructor(private opts: GreenInboxEscalatorOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  private headers(): Record<string, string> {
    return {
      authorization: `Bearer ${this.opts.apiKey}`,
      "content-type": "application/json",
    };
  }

  async escalate(req: EscalationRequest): Promise<Escalation> {
    const existing = this.byIdentity.get(req.identity);
    if (existing) {
      if (existing.status === "pending") {
        existing.status = await this.check(existing.request_id);
      }
      return existing;
    }
    const res = await this.fetchFn(`${this.opts.apiUrl}/v1/requests`, {
      method: "POST",
      headers: { ...this.headers(), "idempotency-key": `red:${req.identity}` },
      body: JSON.stringify({
        action_type: "red:access_request",
        summary: `Unknown agent wants ${req.method} ${req.path} — allow?`,
        detail: `identity: ${req.identity}\nsignals: ${req.signals.join(", ")}`,
        payload: JSON.stringify(req.evidence),
        risk: "high",
        timeout_s: this.opts.timeoutS ?? 86400,
        mode: "async",
        // the receipt for the human's decision should attribute the OBSERVED
        // foreign agent, not Red's own api key
        actor: { type: "observed", id: req.identity, evidence: req.evidence },
      }),
    });
    if (!res.ok) throw new Error(`escalation create failed: ${res.status}`);
    const body = (await res.json()) as { request_id: string; status: string };
    const esc: Escalation = {
      request_id: body.request_id,
      status: toEscalationStatus(body.status),
    };
    this.byIdentity.set(req.identity, esc);
    return esc;
  }

  async check(requestId: string): Promise<EscalationStatus> {
    const res = await this.fetchFn(
      `${this.opts.apiUrl}/v1/requests/${encodeURIComponent(requestId)}`,
      { headers: this.headers() },
    );
    if (!res.ok) return "pending"; // cannot tell → stay challenged (fail closed)
    const body = (await res.json()) as { status: string };
    return toEscalationStatus(body.status);
  }
}

function toEscalationStatus(green: string): EscalationStatus {
  if (green === "approved") return "approved";
  if (green === "denied" || green === "expired") return "denied"; // expiry = deny
  return "pending";
}
