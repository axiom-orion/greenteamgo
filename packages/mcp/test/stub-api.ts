import http from "node:http";
import { randomUUID } from "node:crypto";

export interface StubRecord {
  request_id: string;
  status: "pending" | "approved" | "denied" | "expired";
  action_type: string;
  summary: string;
  detail?: string;
  payload?: string;
  payload_sha256?: string;
  risk: string;
  timeout_s: number;
  mode: string;
  nonce: string;
  reason?: string;
  receipt?: Record<string, unknown>;
  created_at: string;
  expires_at: string;
}

export interface StubOptions {
  apiKey?: string;
  /** if set, automatically decide each request after autoDelayMs */
  autoDecision?: "approved" | "denied";
  autoDelayMs?: number;
  denyReason?: string;
}

export interface Stub {
  url: string;
  requests: Map<string, StubRecord>;
  decide(id: string, decision: "approved" | "denied", reason?: string): void;
  close(): Promise<void>;
}

export function startStub(opts: StubOptions = {}): Promise<Stub> {
  const apiKey = opts.apiKey ?? "test-key";
  const requests = new Map<string, StubRecord>();
  const timers: NodeJS.Timeout[] = [];

  const decide = (id: string, decision: "approved" | "denied", reason?: string): void => {
    const r = requests.get(id);
    if (!r || r.status !== "pending") return;
    r.status = decision;
    if (reason) r.reason = reason;
    r.receipt = {
      v: 1,
      request_id: id,
      decision,
      payload_sha256: r.payload_sha256,
      prev_hash: "stub-prev",
      sig: "stub-ed25519",
    };
  };

  const server = http.createServer((req, res) => {
    if (req.headers["authorization"] !== `Bearer ${apiKey}`) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    const url = new URL(req.url ?? "/", "http://localhost");

    if (req.method === "POST" && url.pathname === "/v1/requests") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const parsed = JSON.parse(body) as Omit<StubRecord, "request_id" | "status" | "created_at" | "expires_at">;
        const id = randomUUID();
        const rec: StubRecord = {
          ...parsed,
          request_id: id,
          status: "pending",
          created_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + parsed.timeout_s * 1000).toISOString(),
        };
        requests.set(id, rec);
        const expireTimer = setTimeout(() => {
          if (rec.status === "pending") rec.status = "expired";
        }, parsed.timeout_s * 1000);
        timers.push(expireTimer);
        if (opts.autoDecision) {
          const t = setTimeout(
            () =>
              decide(
                id,
                opts.autoDecision as "approved" | "denied",
                opts.autoDecision === "denied" ? opts.denyReason : undefined,
              ),
            opts.autoDelayMs ?? 50,
          );
          timers.push(t);
        }
        res.writeHead(201, { "content-type": "application/json" });
        res.end(JSON.stringify({ request_id: id, status: "pending", expires_at: rec.expires_at }));
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/v1/requests") {
      const pending = [...requests.values()].filter((r) => r.status === "pending");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(pending));
      return;
    }

    const m = url.pathname.match(/^\/v1\/requests\/([^/]+)$/);
    if (req.method === "GET" && m) {
      const r = requests.get(decodeURIComponent(m[1]));
      if (!r) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "not found" }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(r));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as { port: number };
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        requests,
        decide,
        close: () =>
          new Promise<void>((r) => {
            timers.forEach(clearTimeout);
            server.close(() => r());
          }),
      });
    });
  });
}
