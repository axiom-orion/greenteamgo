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
import { InMemoryStore, type ApiKeySeed, type RequestRecord } from "../src/store.js";

function seed(now: () => number = () => Date.now(), notifier: Notifier = new NoopNotifier()) {
  const store = new InMemoryStore();
  const signing = generateSignerKeyPair("ws1_key");
  const agentSeed: ApiKeySeed = { api_key: "sk_agent", workspace_id: "ws1", scopes: ["green:create", "green:read"] };
  const appSeed: ApiKeySeed = { api_key: "sk_app", workspace_id: "ws1", scopes: ["green:read", "green:decide"] };
  store.seedWorkspace("ws1", agentSeed, signing);
  store.addApiKey(appSeed);
  let counter = 0;
  const service = new RequestService({ store, notifier, now, newId: () => `req_${++counter}` });
  const agentKey = store.resolveApiKey("sk_agent")!;
  const appKey = store.resolveApiKey("sk_app")!;
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

  it("FAILS CLOSED: a request past its deadline reads as expired — and the expiry is sealed into the chain", async () => {
    let clock = 1_000_000;
    const { service, store, agentKey, signing } = seed(() => clock);
    const req = await service.create(agentKey, { ...baseInput, timeout_s: 10 });
    clock += 11_000; // past the 10s deadline
    const polled = service.get(agentKey, req.request_id);
    expect(polled.status).toBe("expired");
    expect(polled.reason).toMatch(/fail closed/);
    // the fail-closed outcome is itself evidence: deny/expired, machine-decided
    expect(polled.receipt).toBeDefined();
    expect(polled.receipt!.verdict).toBe("deny");
    expect(polled.receipt!.status).toBe("expired");
    expect(polled.receipt!.decider).toEqual({ method: "auto", id: "timeout" });
    expect(polled.receipt!.decided_at).toBe(polled.expires_at);
    expect(verifyReceipt(polled.receipt!, signing.publicKeyPem)).toEqual({ ok: true });
    expect(store.getChainHead("ws1")).toBe(polled.receipt!.receipt_hash);
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

  it("409s an idempotency-key reuse with DIFFERENT content instead of replaying another action's state", async () => {
    const { service, agentKey } = seed();
    await service.create(agentKey, { ...baseInput, idempotency_key: "idem-x" });
    await expect(
      service.create(agentKey, { ...baseInput, action_type: "payment", summary: "wire $50k", idempotency_key: "idem-x" }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it("decisions are final: approving then denying throws and leaves the chain untouched", async () => {
    const { service, store, agentKey, appKey } = seed();
    const req = await service.create(agentKey, baseInput);
    const d = await service.decide(appKey, req.request_id, "approved");
    await expect(service.decide(appKey, req.request_id, "denied")).rejects.toBeInstanceOf(ConflictError);
    expect(store.getChainHead("ws1")).toBe(d.receipt!.receipt_hash);
    expect(store.listReceipts("ws1")).toHaveLength(1);
  });

  it("isolates workspaces: a ws2 key cannot see or decide a ws1 request", async () => {
    const { service, store, agentKey } = seed();
    const signing2 = generateSignerKeyPair("ws2_key");
    store.seedWorkspace("ws2", { api_key: "sk_ws2", workspace_id: "ws2", scopes: ["green:create", "green:read", "green:decide"] }, signing2);
    const ws2Key = store.resolveApiKey("sk_ws2")!;
    const req = await service.create(agentKey, baseInput);
    expect(() => service.get(ws2Key, req.request_id)).toThrow(/not found/);
    await expect(service.decide(ws2Key, req.request_id, "approved")).rejects.toThrow(/not found/);
    expect(service.listPending(ws2Key)).toHaveLength(0);
    // the same idempotency key in two workspaces creates two distinct requests
    const a = await service.create(agentKey, { ...baseInput, idempotency_key: "shared" });
    const b = await service.create(ws2Key, { ...baseInput, idempotency_key: "shared" });
    expect(b.request_id).not.toBe(a.request_id);
  });

  it("listPending drops requests that expired since the last poll", async () => {
    let clock = 1_000_000;
    const { service, agentKey } = seed(() => clock);
    await service.create(agentKey, { ...baseInput, timeout_s: 10 });
    expect(service.listPending(agentKey)).toHaveLength(1);
    clock += 11_000;
    expect(service.listPending(agentKey)).toHaveLength(0);
    expect(service.listPending(agentKey)).toHaveLength(0); // stable on re-poll
  });

  it("receipts attribute the actor to the requesting agent key, not the workspace", async () => {
    const { service, agentKey, appKey } = seed();
    const req = await service.create(agentKey, baseInput);
    const d = await service.decide(appKey, req.request_id, "approved");
    expect(d.receipt!.actor).toEqual({ type: "agent_key", id: agentKey.key_id });
    expect(d.receipt!.actor.id).not.toBe("ws1");
  });

  it("accepts an observed actor on create (Red escalations) and seals it into the receipt", async () => {
    const { service, agentKey, appKey } = seed();
    const req = await service.create(agentKey, {
      ...baseInput,
      action_type: "red:access_request",
      actor: { type: "observed", id: "gptbot", evidence: { ua: "GPTBot/1.0" } },
    });
    const d = await service.decide(appKey, req.request_id, "approved");
    expect(d.receipt!.actor).toEqual({ type: "observed", id: "gptbot", evidence: { ua: "GPTBot/1.0" } });
  });

  it("verifies an uploaded payload against payload_sha256 and rejects a mismatch", async () => {
    const { service, agentKey } = seed();
    await expect(
      service.create(agentKey, { ...baseInput, payload: "rm -rf /", payload_sha256: "a".repeat(64) }),
    ).rejects.toThrow(/does not match/);
    const ok = await service.create(agentKey, { ...baseInput, payload: "rm -rf /" });
    expect(ok.payload_sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("server-side validation: bad risk, non-positive timeout, malformed hash-only sha", async () => {
    const { service, agentKey } = seed();
    await expect(service.create(agentKey, { ...baseInput, risk: "extreme" as never })).rejects.toThrow(/invalid risk/);
    await expect(service.create(agentKey, { ...baseInput, timeout_s: 0 })).rejects.toThrow(/timeout_s/);
    await expect(service.create(agentKey, { ...baseInput, payload_sha256: "xyz" })).rejects.toThrow(/64 lowercase hex/);
  });

  it("does not fail create when the notifier throws; replay re-pages the human", async () => {
    let failNotify = true;
    let pages = 0;
    const notifier: Notifier = {
      notify: () => {
        pages++;
        if (failNotify) throw new Error("webhook 502");
      },
    };
    const { service, agentKey } = seed(() => Date.now(), notifier);
    const rec = await service.create(agentKey, { ...baseInput, idempotency_key: "idem-n" });
    expect(rec.status).toBe("pending");
    expect(rec.notify_error).toMatch(/502/);
    failNotify = false;
    const replay = await service.create(agentKey, { ...baseInput, idempotency_key: "idem-n" });
    expect(replay.request_id).toBe(rec.request_id);
    expect(replay.notify_error).toBeUndefined();
    expect(pages).toBe(2); // initial failed attempt + successful re-page
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

  it("rejects forged decider methods: only app/biometric over HTTP, and biometric lands in the receipt", async () => {
    const { service, store, signing } = seed();
    const url = await listen(createHandler(service, store));
    const create = async () => {
      const r = await fetch(`${url}/v1/requests`, {
        method: "POST",
        headers: { authorization: "Bearer sk_agent", "content-type": "application/json" },
        body: JSON.stringify({ action_type: "payment", summary: "s", risk: "critical", timeout_s: 900, mode: "block" }),
      });
      return (await r.json()).request_id as string;
    };

    const id1 = await create();
    for (const method of ["policy", "auto", "root"]) {
      const res = await fetch(`${url}/v1/requests/${id1}/decision`, {
        method: "POST",
        headers: { authorization: "Bearer sk_app", "content-type": "application/json" },
        body: JSON.stringify({ decision: "approved", method }),
      });
      expect(res.status).toBe(400);
    }

    const bio = await fetch(`${url}/v1/requests/${id1}/decision`, {
      method: "POST",
      headers: { authorization: "Bearer sk_app", "content-type": "application/json" },
      body: JSON.stringify({ decision: "approved", method: "biometric", decider_id: "user_1" }),
    });
    expect(bio.status).toBe(200);
    const decided = await bio.json();
    expect(decided.receipt.decider).toEqual({ method: "biometric", id: "user_1" });
    expect(verifyReceipt(decided.receipt, signing.publicKeyPem)).toEqual({ ok: true });
  });

  it("exports the chain and public key so the verify CLI can audit the chain offline (tamper-evident)", async () => {
    const { service, store, signing } = seed();
    const url = await listen(createHandler(service, store));

    // two decisions → two chained receipts
    for (const summary of ["one", "two"]) {
      const c = await fetch(`${url}/v1/requests`, {
        method: "POST",
        headers: { authorization: "Bearer sk_agent", "content-type": "application/json" },
        body: JSON.stringify({ action_type: "x", summary, risk: "low", timeout_s: 900, mode: "block" }),
      });
      const { request_id } = await c.json();
      await fetch(`${url}/v1/requests/${request_id}/decision`, {
        method: "POST",
        headers: { authorization: "Bearer sk_app", "content-type": "application/json" },
        body: JSON.stringify({ decision: "approved" }),
      });
    }

    const receipts = await (await fetch(`${url}/v1/receipts`, { headers: { authorization: "Bearer sk_agent" } })).json();
    const pub = await (await fetch(`${url}/v1/keys`, { headers: { authorization: "Bearer sk_agent" } })).json();
    expect(receipts).toHaveLength(2);
    expect(pub.key_id).toBe("ws1_key");
    expect(verifyChain(receipts, (id: string) => (id === pub.key_id ? pub.publicKeyPem : undefined))).toEqual({ ok: true });
    expect(receipts[1].prev_hash).toBe(receipts[0].receipt_hash);
    expect(signing.publicKeyPem).toBe(pub.publicKeyPem);
  });
});
