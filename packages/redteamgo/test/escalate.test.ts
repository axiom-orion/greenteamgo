import { describe, expect, it } from "vitest";

import { GreenInboxEscalator, type EscalationRequest } from "../src/escalate.js";

function stubFetch(handler: (url: string, init: RequestInit) => { status: number; body: unknown }) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchFn = (async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url);
    calls.push({ url: u, init: init ?? {} });
    const { status, body } = handler(u, init ?? {});
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () => JSON.stringify(body),
    } as Response;
  }) as typeof fetch;
  return { fetchFn, calls };
}

const req: EscalationRequest = {
  identity: "ip:203.0.113.9",
  method: "GET",
  path: "/api/orders",
  workspace_id: "ws1",
  evidence: { ua: "curl/8" },
  signals: ["automation_ua"],
};

describe("GreenInboxEscalator", () => {
  it("maps Green's expired status to denied (fail closed)", async () => {
    let created = false;
    const { fetchFn } = stubFetch((url) => {
      if (url.endsWith("/v1/requests")) {
        created = true;
        return { status: 201, body: { request_id: "r1", status: "pending" } };
      }
      return { status: 200, body: { status: "expired" } }; // deadline passed, nobody answered
    });
    const esc = new GreenInboxEscalator({ apiUrl: "http://x", apiKey: "k", fetchFn, now: () => 1_000_000 });
    const first = await esc.escalate(req);
    expect(created).toBe(true);
    expect(first.status).toBe("pending");
    const rechecked = await esc.check("r1");
    expect(rechecked.status).toBe("denied"); // expired → denied
  });

  it("treats an un-OK status GET as still-pending (cannot tell → fail closed)", async () => {
    const { fetchFn } = stubFetch((url) => {
      if (url.endsWith("/v1/requests")) return { status: 201, body: { request_id: "r1", status: "pending" } };
      return { status: 500, body: { error: "upstream" } };
    });
    const esc = new GreenInboxEscalator({ apiUrl: "http://x", apiKey: "k", fetchFn, now: () => 1_000_000 });
    await esc.escalate(req);
    expect((await esc.check("r1")).status).toBe("pending");
  });

  it("parses the resolving decider.method from Green's receipt", async () => {
    const { fetchFn } = stubFetch((url) => {
      if (url.endsWith("/v1/requests")) return { status: 201, body: { request_id: "r1", status: "pending" } };
      return { status: 200, body: { status: "approved", receipt: { decider: { method: "app" } } } };
    });
    const esc = new GreenInboxEscalator({ apiUrl: "http://x", apiKey: "k", fetchFn, now: () => 1_000_000 });
    await esc.escalate(req);
    const checked = await esc.check("r1");
    expect(checked.status).toBe("approved");
    expect(checked.decider_method).toBe("app");
  });

  it("uses a stable, window-scoped idempotency key and a path-independent body", async () => {
    const { fetchFn, calls } = stubFetch((url) => {
      if (url.endsWith("/v1/requests")) return { status: 201, body: { request_id: "r1", status: "pending" } };
      return { status: 200, body: { status: "pending" } };
    });
    // fresh escalator per call simulates a serverless isolate with no cache
    const mk = (now: number) => new GreenInboxEscalator({ apiUrl: "http://x", apiKey: "k", fetchFn, windowS: 3600, now: () => now });
    await mk(1_000_000).escalate({ ...req, path: "/api/orders" });
    await mk(1_000_000).escalate({ ...req, path: "/api/DIFFERENT" }); // same identity+window, different path

    const posts = calls.filter((c) => c.init.method === "POST");
    expect(posts).toHaveLength(2);
    const keyA = (posts[0].init.headers as Record<string, string>)["idempotency-key"];
    const keyB = (posts[1].init.headers as Record<string, string>)["idempotency-key"];
    // identical key + identical body → Green replays (no 409) despite different paths
    expect(keyA).toBe(keyB);
    expect(posts[0].init.body).toBe(posts[1].init.body);
    expect(String(posts[0].init.body)).not.toContain("/api/orders"); // path not in the body

    // a later window mints a fresh key so the human is re-paged
    await mk(1_000_000 + 3600_000).escalate({ ...req });
    const keyC = (calls.filter((c) => c.init.method === "POST")[2].init.headers as Record<string, string>)["idempotency-key"];
    expect(keyC).not.toBe(keyA);
  });
});
