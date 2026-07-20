/**
 * Web-standard adapter: Request in, Response-or-null out. Drops into
 * Next.js middleware (`export function middleware(req)`) and Cloudflare
 * Workers unchanged — null means "proceed to your app."
 */
import type { InboundRequest } from "../classify.js";
import { Gate, type GateOptions, type GateResult } from "../gate.js";

export function toInbound(request: Request, ip?: string): InboundRequest {
  const url = new URL(request.url);
  const headers: Record<string, string | undefined> = {};
  request.headers.forEach((v, k) => {
    headers[k.toLowerCase()] = v;
  });
  return { method: request.method, path: url.pathname, headers, ip };
}

export interface FetchGateOptions extends GateOptions {
  /** derive the client IP (platform-specific header, e.g. cf-connecting-ip) */
  ipFrom?: (request: Request) => string | undefined;
  /** override the challenge/block responses */
  responseFor?: (result: GateResult) => Response | null;
}

function defaultResponse(result: GateResult): Response | null {
  if (result.disposition === "allow") return null;
  const status = result.disposition === "block" ? 403 : 403;
  return new Response(
    JSON.stringify({
      error: result.disposition === "block" ? "agent_blocked" : "agent_challenge",
      reason: result.reason,
      receipt_hash: result.receipt?.receipt_hash,
      escalation: result.escalation
        ? { request_id: result.escalation.request_id, status: result.escalation.status }
        : undefined,
    }),
    {
      status,
      headers: {
        "content-type": "application/json",
        "x-redteamgo-disposition": result.disposition,
      },
    },
  );
}

/**
 * Build the middleware. Usage (Next.js):
 *
 *   const guard = createFetchGate({ workspace_id, policy, ... });
 *   export async function middleware(req: Request) {
 *     const res = await guard(req);
 *     if (res) return res;            // blocked or challenged
 *     return NextResponse.next();     // allowed
 *   }
 */
export function createFetchGate(opts: FetchGateOptions) {
  const gate = new Gate(opts);
  return async function guard(request: Request): Promise<Response | null> {
    const ip = opts.ipFrom?.(request);
    const result = await gate.handle(toInbound(request, ip));
    const respond = opts.responseFor ?? defaultResponse;
    return respond(result);
  };
}

/** Same, but returns the full GateResult alongside the response — for callers
 * that want to log receipts or expose escalation state. */
export function createFetchGateWithResult(opts: FetchGateOptions) {
  const gate = new Gate(opts);
  return async function guard(
    request: Request,
  ): Promise<{ response: Response | null; result: GateResult }> {
    const ip = opts.ipFrom?.(request);
    const result = await gate.handle(toInbound(request, ip));
    const respond = opts.responseFor ?? defaultResponse;
    return { response: respond(result), result };
  };
}
