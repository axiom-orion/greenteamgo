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
  /** how the resolving decision was made, once known: "app"/"biometric" = a
   * human tapped it; "auto"/"policy" = Green auto-decided or the request
   * expired. Lets the gate seal the truthful decider on the enforcement side. */
  decider_method?: "app" | "biometric" | "policy" | "auto";
}

/** Pluggable escalation transport. GreenInboxEscalator is the real one;
 * tests use an in-memory fake. */
export interface Escalator {
  /** Create (or return the existing) escalation for this identity. */
  escalate(req: EscalationRequest): Promise<Escalation>;
  /** Lazily re-check a pending escalation's status. */
  check(requestId: string): Promise<Escalation>;
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
  /**
   * Escalation window in seconds. One Green request is opened per identity per
   * window; a new window (e.g. after the standing decision lapses) opens a
   * fresh request so the human is re-paged instead of replaying a stale
   * answer forever. Defaults to `timeoutS`.
   */
  windowS?: number;
  now?: () => number;
  fetchFn?: typeof fetch;
}

/**
 * Escalates through GreenTeamGo's inbox API: POST /v1/requests with
 * mode:"async", then lazy GET /v1/requests/:id checks. An expired request is
 * a deny — Green's fail-closed expiry does the bookkeeping for us.
 *
 * The POST body is a pure function of (identity, window): constant summary and
 * detail, identity-only actor, no per-request path/evidence. That matters
 * because Green's idempotency is content-fingerprinted — a body that varied by
 * path would 409 on the same identity's next path across a fresh serverless
 * isolate (whose in-memory cache is empty), dead-ending the escalation. The
 * escalation is about the AGENT ("this thing wants in"), not the individual
 * request, which is exactly the once-per-agent contract.
 */
export class GreenInboxEscalator implements Escalator {
  private fetchFn: typeof fetch;
  private now: () => number;
  private byKey = new Map<string, Escalation>(); // key: `${identity}:${epoch}`

  constructor(private opts: GreenInboxEscalatorOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.now = opts.now ?? (() => Date.now());
  }

  private headers(): Record<string, string> {
    return {
      authorization: `Bearer ${this.opts.apiKey}`,
      "content-type": "application/json",
    };
  }

  private epoch(): number {
    const windowS = this.opts.windowS ?? this.opts.timeoutS ?? 86400;
    return Math.floor(this.now() / (windowS * 1000));
  }

  async escalate(req: EscalationRequest): Promise<Escalation> {
    const epoch = this.epoch();
    const cacheKey = `${req.identity}:${epoch}`;
    const existing = this.byKey.get(cacheKey);
    if (existing) {
      if (existing.status === "pending") return this.check(existing.request_id);
      return existing;
    }
    const res = await this.fetchFn(`${this.opts.apiUrl}/v1/requests`, {
      method: "POST",
      // idempotency scoped to the window: a new window opens a new request
      headers: { ...this.headers(), "idempotency-key": `red:${req.identity}:${epoch}` },
      body: JSON.stringify({
        action_type: "red:access_request",
        // stable per (identity, window) so cross-isolate creates replay, not 409
        summary: `Agent "${req.identity}" is requesting access — allow?`,
        detail: `identity: ${req.identity}`,
        risk: "high",
        timeout_s: this.opts.timeoutS ?? 86400,
        mode: "async",
        actor: { type: "observed", id: req.identity },
      }),
    });
    if (!res.ok) throw new Error(`escalation create failed: ${res.status}`);
    const body = (await res.json()) as { request_id: string; status: string; receipt?: Receiptish };
    const esc: Escalation = {
      request_id: body.request_id,
      status: toEscalationStatus(body.status),
      decider_method: deciderOf(body),
    };
    this.byKey.set(cacheKey, esc);
    return esc;
  }

  async check(requestId: string): Promise<Escalation> {
    const res = await this.fetchFn(
      `${this.opts.apiUrl}/v1/requests/${encodeURIComponent(requestId)}`,
      { headers: this.headers() },
    );
    // cannot tell → stay challenged (fail closed)
    if (!res.ok) return { request_id: requestId, status: "pending" };
    const body = (await res.json()) as { status: string; receipt?: Receiptish };
    return {
      request_id: requestId,
      status: toEscalationStatus(body.status),
      decider_method: deciderOf(body),
    };
  }
}

type Receiptish = { decider?: { method?: "app" | "biometric" | "policy" | "auto" } };

function deciderOf(body: { receipt?: Receiptish }): Escalation["decider_method"] {
  return body.receipt?.decider?.method;
}

function toEscalationStatus(green: string): EscalationStatus {
  if (green === "approved") return "approved";
  if (green === "denied" || green === "expired") return "denied"; // expiry = deny
  return "pending";
}
