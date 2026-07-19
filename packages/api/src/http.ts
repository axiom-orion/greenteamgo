/**
 * Framework-agnostic HTTP handler implementing the agent + app API contract.
 *
 * Routes (Bearer api-key auth on every route):
 *   POST /v1/requests                 agent creates an approval request
 *   GET  /v1/requests?status=pending  agent/app lists pending
 *   GET  /v1/requests/:id             agent polls a decision (fail-closed expiry)
 *   POST /v1/requests/:id/decision    app records the human's verdict → receipt
 *
 * Returned as a plain (req,res) Node handler so it drops into a test server, a
 * Next.js Route Handler, or a Vercel function unchanged.
 */
import type { IncomingMessage, ServerResponse } from "node:http";

import {
  ConflictError,
  NotFoundError,
  RequestService,
  ScopeError,
  ValidationError,
} from "./service.js";
import { toState, type Store } from "./store.js";

function send(res: ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(json);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function statusForError(err: unknown): number {
  if (err instanceof ScopeError) return 403;
  if (err instanceof NotFoundError) return 404;
  if (err instanceof ConflictError) return 409;
  if (err instanceof ValidationError) return 400;
  return 500;
}

export function createHandler(service: RequestService, store: Store) {
  return async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const auth = req.headers["authorization"];
      const apiKey = typeof auth === "string" && auth.startsWith("Bearer ")
        ? auth.slice("Bearer ".length)
        : undefined;
      const keyRec = apiKey ? store.resolveApiKey(apiKey) : undefined;
      if (!keyRec) return send(res, 401, { error: "unauthorized" });

      const url = new URL(req.url ?? "/", "http://localhost");
      const method = req.method ?? "GET";

      // POST /v1/requests
      if (method === "POST" && url.pathname === "/v1/requests") {
        const input = JSON.parse((await readBody(req)) || "{}");
        const idem = req.headers["idempotency-key"];
        const rec = await service.create(keyRec, {
          action_type: input.action_type,
          summary: input.summary,
          detail: input.detail,
          payload: input.payload,
          payload_sha256: input.payload_sha256,
          risk: input.risk,
          timeout_s: input.timeout_s,
          mode: input.mode,
          nonce: input.nonce,
          idempotency_key: typeof idem === "string" ? idem : undefined,
        });
        return send(res, 201, toState(rec));
      }

      // GET /v1/requests?status=pending
      if (method === "GET" && url.pathname === "/v1/requests") {
        const pending = service.listPending(keyRec).map(toState);
        return send(res, 200, pending);
      }

      const decisionMatch = url.pathname.match(/^\/v1\/requests\/([^/]+)\/decision$/);
      const getMatch = url.pathname.match(/^\/v1\/requests\/([^/]+)$/);

      // POST /v1/requests/:id/decision
      if (method === "POST" && decisionMatch) {
        const body = JSON.parse((await readBody(req)) || "{}");
        if (body.decision !== "approved" && body.decision !== "denied") {
          return send(res, 400, { error: 'decision must be "approved" or "denied"' });
        }
        const rec = await service.decide(keyRec, decodeURIComponent(decisionMatch[1]), body.decision, {
          reason: body.reason,
          deciderId: body.decider_id,
          deciderMethod: body.method,
        });
        return send(res, 200, toState(rec));
      }

      // GET /v1/requests/:id
      if (method === "GET" && getMatch) {
        const rec = service.get(keyRec, decodeURIComponent(getMatch[1]));
        return send(res, 200, toState(rec));
      }

      return send(res, 404, { error: "not found" });
    } catch (err) {
      const status = statusForError(err);
      send(res, status, { error: (err as Error).message });
    }
  };
}
