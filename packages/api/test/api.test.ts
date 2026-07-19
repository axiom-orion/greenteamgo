import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";

import { generateSignerKeyPair, verifyChain, verifyReceipt } from "@vorionsys/greenteamgo-core";

import { createHandler } from "../src/http.js";
import {
  ConflictError,
  NoopNotifier,
  RequestService,
  ScopeError,
  type CreateInput,
  type Notifier,
} from "../src/service.js";
import { InMemoryStore, type ApiKeyRecord, type RequestRecord } from "../src/store.js";

function seed(now: () => number = () => Date.now(), notifier: Notifier = new NoopNotifier()) {
  const store = new InMemoryStore();
  const signing = generateSignerKeyPair("ws1_key");
  const agentKey: ApiKeyRecord = { api_key: "sk_agent", workspace_id: "ws1", scopes: ["green:create", "green:read"] };
  const appKey: ApiKeyRecord = { api_key: "sk_app", workspace_id: "ws1", scopes: ["green:read", "green:decide"] };
  store.seedWorkspace("ws1", agentKey, signing);
  store.addApiKey(appKey);
  let counter = 0;
  const service = new RequestService({ store, notifier, now, newId: () => `req_${++counter}` });
  return { store, service, signing, agentKey, appKey };
}

const baseInput: CreateInput = {
  action_type: "git_push",
  summary: "push 3 commits to main",
  risk: "high",
  timeout_s: 900,
  mode: "block",
};

describe("RequestService lifecycle", () => {
  it("creates a pending request and pages the human", async () => {
    const notified: RequestRecord[] = [];
    const { service, agentKey } = seed(() => 1_000_000, { notify: (r) => void notified.push(r) });
    const rec = await service.create(agentKey, baseInput);
    expect(rec.status).toBe("pending");
    expect(notified).toHaveLength(1);
    expect(notified[0].request_id).toBe(rec.request_id);
  });

  it("turns a human approval into a receipt that verifies under the workspace key", async () => {
    const { service, agentKey, appKey, signing } = seed();
    const req = await service.create(agentKey, baseInput);
    const decided = await service.decide(appKey, req.request_id, "approved", { reason: "looks fine", deciderId: "user_1" });
    expect(decided.status).toBe("approved");
    expect(decided.receipt).toBeDefined();
    expect(decided.receipt!.verdict).toBe("approve");
    expect(verifyReceipt(decided.receipt!, signing.publicKeyPem)).toEqual({ ok: true });
  });

  it("FAILS CLOSED: a request past its deadline reads as expired", async () => {
    let clock = 1_000_000;
    const { service, agentKey } = seed(() => clock);
    const req = await service.create(agentKey, { ...baseInput, timeout_s: 10 });
    clock += 11_000; // past the 10s deadline
    const polled = service.get(agentKey, req.request_id);
    expect(polled.status).toBe("expired");
    expect(polled.reason).toMatch(/fail closed/);
  });

  it("refuses to decide an already-expired request", async () => {
    let clock = 1_000_000;
    const { service, agentKey, appKey } = seed(() => clock);
    const req = await service.create(agentKey, { ...baseInput, timeout_s: 10 });
    clock += 11_000;
    await expect(service.decide(appKey, req.request_id, "approved")).rejects.toBeInstanceOf(ConflictError);
  });

  it("is idempotent: same idempotency key returns the same request", async () => {
    const { service, agentKey } = seed();
    const a = await service.create(agentKey, { ...baseInput, idempotency_key: "idem-1" });
    const b = await service.create(agentKey, { ...baseInput, idempotency_key: "idem-1" });
    expect(b.request_id).toBe(a.request_id);
  });

  it("enforces scopes: an agent key cannot decide", async () => {
    const { service, agentKey } = seed();
    const req = await service.create(agentKey, baseInput);
    await expect(service.decide(agentKey, req.request_id, "approved")).rejects.toBeInstanceOf(ScopeError);
  });

  it("chains receipts: the second decision links to the first", async () => {
    const { service, agentKey, appKey, signing } = seed();
    const r1 = await service.create(agentKey, baseInput);
    const d1 = await service.decide(appKey, r1.request_id, "approved");
    const r2 = await service.create(agentKey, { ...baseInput, summary: "second" });
    const d2 = await service.decide(appKey, r2.request_id, "denied", { reason: "no" });
    expect(d2.receipt!.prev_hash).toBe(d1.receipt!.receipt_hash);
    expect(verifyChain([d1.receipt!, d2.receipt!], () => signing.publicKeyPem)).toEqual({ ok: true });
  });
});

describe("HTTP handler (end-to-end over a real server)", () => {
  let server: Server | undefined;
  afterEach(() => new Promise<void>((r) => (server ? server.close(() => r()) : r())));

  async function listen(handler: (req: any, res: any) => void): Promise<string> {
    server = createServer(handler);
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
    const addr = server!.address() as { port: number };
    return `http://127.0.0.1:${addr.port}`;
  }

  it("rejects a missing/invalid api key with 401", async () => {
    const { service, store } = seed();
    const url = await listen(createHandler(service, store));
    const res = await fetch(`${url}/v1/requests`, { headers: { authorization: "Bearer nope" } });
    expect(res.status).toBe(401);
  });

  it("drives the full create → poll → approve → verify flow over HTTP", async () => {
    const { service, store, signing } = seed();
    const url = await listen(createHandler(service, store));

    // agent creates (mirrors the MCP client's exact request shape)
    const createRes = await fetch(`${url}/v1/requests`, {
      method: "POST",
      headers: { authorization: "Bearer sk_agent", "content-type": "application/json", "idempotency-key": "k1" },
      body: JSON.stringify({ action_type: "payment", summary: "send $200", payload_sha256: "b".repeat(64), risk: "critical", timeout_s: 900, mode: "block", nonce: "n1" }),
    });
    expect(createRes.status).toBe(201);
    const created = await createRes.json();
    expect(created.status).toBe("pending");

    // app approves
    const decideRes = await fetch(`${url}/v1/requests/${created.request_id}/decision`, {
      method: "POST",
      headers: { authorization: "Bearer sk_app", "content-type": "application/json" },
      body: JSON.stringify({ decision: "approved", reason: "ok", decider_id: "user_1" }),
    });
    expect(decideRes.status).toBe(200);

    // agent polls and gets a signed receipt
    const pollRes = await fetch(`${url}/v1/requests/${created.request_id}`, {
      headers: { authorization: "Bearer sk_agent" },
    });
    const polled = await pollRes.json();
    expect(polled.status).toBe("approved");
    expect(verifyReceipt(polled.receipt, signing.publicKeyPem)).toEqual({ ok: true });
    expect(polled.receipt.payload_sha256).toBe("b".repeat(64));
  });
});
