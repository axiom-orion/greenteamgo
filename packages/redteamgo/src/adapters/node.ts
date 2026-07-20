/**
 * Node adapter: (req, res, next) middleware over IncomingMessage /
 * ServerResponse. Structurally typed so it works with Express, Connect,
 * Fastify's raw hooks, or a bare node:http server — no framework dependency.
 */
import type { IncomingMessage, ServerResponse } from "node:http";

import type { InboundRequest } from "../classify.js";
import { Gate, type GateOptions, type GateResult } from "../gate.js";

export function toInboundNode(req: IncomingMessage): InboundRequest {
  const url = new URL(req.url ?? "/", "http://localhost");
  const headers: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    headers[k.toLowerCase()] = Array.isArray(v) ? v[0] : v;
  }
  return {
    method: req.method ?? "GET",
    path: url.pathname,
    headers,
    ip: req.socket?.remoteAddress ?? undefined,
  };
}

export interface NodeGateOptions extends GateOptions {
  /** override how block/challenge results are written to the response */
  respond?: (result: GateResult, res: ServerResponse) => void;
}

function defaultRespond(result: GateResult, res: ServerResponse): void {
  const body = JSON.stringify({
    error: result.disposition === "block" ? "agent_blocked" : "agent_challenge",
    reason: result.reason,
    receipt_hash: result.receipt?.receipt_hash,
    escalation: result.escalation
      ? { request_id: result.escalation.request_id, status: result.escalation.status }
      : undefined,
  });
  res.writeHead(403, {
    "content-type": "application/json",
    "x-redteamgo-disposition": result.disposition,
  });
  res.end(body);
}

/**
 * Build (req, res, next) middleware:
 *
 *   app.use(createNodeGate({ workspace_id, policy, ... }));
 */
export function createNodeGate(opts: NodeGateOptions) {
  const gate = new Gate(opts);
  const respond = opts.respond ?? defaultRespond;
  return async function middleware(
    req: IncomingMessage,
    res: ServerResponse,
    next: (err?: unknown) => void,
  ): Promise<void> {
    const result = await gate.handle(toInboundNode(req));
    if (result.disposition === "allow") return next();
    respond(result, res);
  };
}
