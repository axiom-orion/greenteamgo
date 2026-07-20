import { createHash, randomUUID } from "node:crypto";

export type Risk = "low" | "medium" | "high" | "critical";
export type Status = "pending" | "approved" | "denied" | "expired";

const VALID_STATUSES: Status[] = ["pending", "approved", "denied", "expired"];

export const MAX_PAYLOAD_BYTES = 256 * 1024;

export interface Receipt {
  [k: string]: unknown;
}

export interface RequestState {
  request_id: string;
  status: Status;
  reason?: string;
  receipt?: Receipt;
  summary?: string;
  risk?: Risk;
  created_at?: string;
  expires_at?: string;
}

export interface CreateInput {
  action_type: string;
  summary: string;
  detail?: string;
  /** object or string; ≤256KB inline */
  payload?: unknown;
  /** hash-only mode: upload ONLY the payload's SHA-256, never the payload —
   * the reviewer sees summary/detail plus a hash the receipt commits to */
  hash_only?: boolean;
  risk: Risk;
  timeout_s: number;
  mode: "block" | "async";
}

export class PayloadTooLargeError extends Error {}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(`API ${status}: ${message}`);
  }
}

export interface ClientOptions {
  apiUrl: string;
  apiKey: string;
  fetchFn?: typeof fetch;
}

/** Serialize a payload and compute its SHA-256. Only the hash lands in the receipt. */
export function encodePayload(payload: unknown): { body: string; sha256: string } | undefined {
  if (payload === undefined || payload === null) return undefined;
  const body = typeof payload === "string" ? payload : JSON.stringify(payload);
  const bytes = Buffer.byteLength(body, "utf8");
  if (bytes > MAX_PAYLOAD_BYTES) {
    throw new PayloadTooLargeError(
      `payload is ${bytes} bytes; max inline is ${MAX_PAYLOAD_BYTES}. Pass a reference (URL/path) instead — and never include secrets.`,
    );
  }
  return { body, sha256: createHash("sha256").update(body, "utf8").digest("hex") };
}

export class GreenTeamGoClient {
  private fetchFn: typeof fetch;

  constructor(private opts: ClientOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    return {
      authorization: `Bearer ${this.opts.apiKey}`,
      "content-type": "application/json",
      ...extra,
    };
  }

  async createRequest(input: CreateInput): Promise<RequestState> {
    const enc = encodePayload(input.payload);
    const body = JSON.stringify({
      action_type: input.action_type,
      summary: input.summary,
      detail: input.detail,
      payload: input.hash_only ? undefined : enc?.body,
      payload_sha256: enc?.sha256,
      risk: input.risk,
      timeout_s: input.timeout_s,
      mode: input.mode,
      nonce: randomUUID(),
    });
    // Idempotency key makes retries safe against duplicate creation.
    const idempotencyKey = randomUUID();
    let lastErr: unknown;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const res = await this.fetchFn(`${this.opts.apiUrl}/v1/requests`, {
          method: "POST",
          headers: this.headers({ "idempotency-key": idempotencyKey }),
          body,
        });
        if (res.status >= 500) {
          lastErr = new ApiError(res.status, await res.text());
        } else if (!res.ok) {
          throw new ApiError(res.status, await res.text());
        } else {
          return (await res.json()) as RequestState;
        }
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err;
        lastErr = err;
      }
      await sleep(500 * 2 ** attempt);
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }

  async getRequest(requestId: string): Promise<RequestState> {
    const res = await this.fetchFn(
      `${this.opts.apiUrl}/v1/requests/${encodeURIComponent(requestId)}`,
      { headers: this.headers() },
    );
    if (!res.ok) throw new ApiError(res.status, await res.text());
    const state = (await res.json()) as RequestState;
    // A 200 with an unrecognizable body (a proxy error page, a load balancer
    // timeout JSON) must never read as a terminal decision. FAIL CLOSED.
    if (!VALID_STATUSES.includes(state?.status)) {
      throw new ApiError(res.status, `malformed response: status "${state?.status}"`);
    }
    return state;
  }

  async listPending(): Promise<RequestState[]> {
    const res = await this.fetchFn(`${this.opts.apiUrl}/v1/requests?status=pending`, {
      headers: this.headers(),
    });
    if (!res.ok) throw new ApiError(res.status, await res.text());
    return (await res.json()) as RequestState[];
  }

  /**
   * Poll until a decision or the deadline. Backoff: initial × factor, capped.
   * Network errors are tolerated until the deadline; the deadline itself is
   * absolute. No decision by deadline → "expired". FAIL CLOSED.
   */
  async waitForDecision(
    requestId: string,
    deadlineMs: number,
    poll: { initialMs?: number; maxMs?: number; factor?: number } = {},
  ): Promise<RequestState> {
    const max = poll.maxMs ?? 15000;
    const factor = poll.factor ?? 1.5;
    let interval = poll.initialMs ?? 2000;

    for (;;) {
      const remaining = deadlineMs - Date.now();
      if (remaining <= 0) break;
      await sleep(Math.min(interval, remaining));
      interval = Math.min(interval * factor, max);
      try {
        const state = await this.getRequest(requestId);
        if (state.status !== "pending") return state;
      } catch {
        // transient — keep polling until the deadline
      }
    }

    // One final check at/after the deadline (server may have decided just in time).
    try {
      const state = await this.getRequest(requestId);
      if (state.status !== "pending") return state;
    } catch {
      // API unreachable — still fail closed
    }
    return {
      request_id: requestId,
      status: "expired",
      reason: "no decision before deadline (fail closed: treat as deny)",
    };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, Math.max(0, ms)));
}
