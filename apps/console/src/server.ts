/**
 * GreenTeamGo demo console — one process that runs:
 *   - the inbox API at /v1/*  (what greenteamgo-mcp / Codex talk to)
 *   - a web approval page at /  (the "phone" stand-in: see pending actions,
 *     approve/deny, watch the signed receipt appear)
 *
 * For the OpenAI Build Week demo: Codex, wired to greenteamgo-mcp, calls
 * request_approval before a risky action; it shows up here; you approve or deny;
 * a signed, hash-linked receipt is produced. No mobile app needed to demo.
 *
 * Run:  npm -w @vorionsys/greenteamgo-console start   (after building)
 */
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";

import { verifyReceipt } from "@vorionsys/greenteamgo-core";
import { generateSignerKeyPair } from "@vorionsys/greenteamgo-core";
import { evaluate, type Policy } from "@vorionsys/greenteamgo-policy";
import {
  InMemoryStore,
  RequestService,
  createHandler,
  type ApiKeySeed,
  type RequestRecord,
  type ResolvedKey,
} from "@vorionsys/greenteamgo-api";

const PORT = Number(process.env.PORT ?? 4000);
const WS = "ws_demo";
const AGENT_KEY = process.env.GREENTEAMGO_AGENT_KEY ?? "gtg_demo_agent_key";
const APP_KEY = "gtg_demo_app_key";

// Demo policy: reads auto-allow; everything else gates to the human.
const POLICY: Policy = {
  id: "pol_demo",
  workspace_id: WS,
  version: 1,
  default_effect: "gate",
  rules: [
    { id: "r_read", action_type: "file_read", effect: "allow", risk_class: "low" },
    { id: "r_list", action_type: "file_list", effect: "allow", risk_class: "low" },
  ],
};

const store = new InMemoryStore();
const signing = generateSignerKeyPair(`${WS}_key`);
const agent: ApiKeySeed = { api_key: AGENT_KEY, workspace_id: WS, scopes: ["green:create", "green:read"] };
const app: ApiKeySeed = { api_key: APP_KEY, workspace_id: WS, scopes: ["green:read", "green:decide"] };
store.seedWorkspace(WS, agent, signing);
store.addApiKey(app);

const service = new RequestService({ store, policy: { evaluate: (e) => evaluate(POLICY, e) } });
const apiHandler = createHandler(service, store);
const appKey: ResolvedKey = store.resolveApiKey(APP_KEY)!;

const INDEX = fileURLToPath(new URL("../public/index.html", import.meta.url));

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let d = "";
    req.on("data", (c) => (d += c));
    req.on("end", () => resolve(d));
    req.on("error", reject);
  });
}

function uiView(r: RequestRecord) {
  return {
    request_id: r.request_id,
    action_type: r.action_type,
    summary: r.summary,
    detail: r.detail,
    risk: r.risk,
    status: r.status,
    reason: r.reason,
    created_at: r.created_at,
    expires_at: r.expires_at,
    decided_at: r.decided_at,
    receipt: r.receipt,
    receipt_verified: r.receipt ? verifyReceipt(r.receipt, signing.publicKeyPem).ok : undefined,
  };
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", "http://localhost");
    const method = req.method ?? "GET";

    // The real inbox API (Codex / greenteamgo-mcp talk to this with the agent key).
    if (url.pathname.startsWith("/v1/")) return void apiHandler(req, res);

    // Keyless UI endpoints (local single-user demo; the server holds the app key).
    if (method === "GET" && url.pathname === "/ui/pending") {
      return json(res, 200, service.listPending(appKey).map(uiView));
    }
    if (method === "GET" && url.pathname === "/ui/history") {
      const decided = [
        ...store.listByStatus(WS, "approved"),
        ...store.listByStatus(WS, "denied"),
      ].sort((a, b) => (b.decided_at ?? "").localeCompare(a.decided_at ?? ""));
      return json(res, 200, decided.map(uiView));
    }
    if (method === "POST" && url.pathname === "/ui/decide") {
      const body = JSON.parse((await readBody(req)) || "{}");
      if (body.decision !== "approved" && body.decision !== "denied") {
        return json(res, 400, { error: "decision must be approved|denied" });
      }
      const rec = await service.decide(appKey, body.request_id, body.decision, {
        reason: body.reason,
        deciderId: "web-console",
        deciderMethod: "app",
      });
      return json(res, 200, uiView(rec));
    }

    if (method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      return void res.end(readFileSync(INDEX));
    }

    json(res, 404, { error: "not found" });
  } catch (err) {
    json(res, (err as { name?: string }).name === "ConflictError" ? 409 : 500, {
      error: (err as Error).message,
    });
  }
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`
GreenTeamGo console
  Approval UI:  http://localhost:${PORT}/
  Inbox API:    http://localhost:${PORT}/v1
  Agent key (for greenteamgo-mcp / Codex):  ${AGENT_KEY}

  Point Codex's greenteamgo MCP at:
    GREENTEAMGO_API_URL=http://localhost:${PORT}   GREENTEAMGO_API_KEY=${AGENT_KEY}
`);
});
