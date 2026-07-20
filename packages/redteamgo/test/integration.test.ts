/**
 * The suite's selling loop, end to end over real HTTP:
 *
 *   foreign agent hits a Red-protected property → challenged
 *   → the escalation rides Green's REAL inbox API (async request)
 *   → the human approves through Green's decision endpoint
 *   → Red creates a standing allow; the agent's next request passes
 *   → every step — Red's enforcement AND Green's human decision — is in
 *     ONE hash-linked, independently verifiable workspace chain.
 *
 * Red is the bouncer, Green is the guest list, the chain is the logbook.
 */
import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";

import { generateSignerKeyPair, verifyChain, type Receipt } from "@vorionsys/greenteamgo-core";
import {
  InMemoryStore,
  RequestService,
  createHandler,
} from "@vorionsys/greenteamgo-api";
import type { Policy } from "@vorionsys/greenteamgo-policy";

import { Gate } from "../src/gate.js";
import { GreenInboxEscalator, InMemoryAllowStore } from "../src/escalate.js";
import { createFetchGate } from "../src/adapters/fetch.js";
import { toInboundNode } from "../src/adapters/node.js";

const WS = "ws1";
let servers: Server[] = [];
afterEach(() => Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r())))));

function listen(handler: (req: any, res: any) => void): Promise<string> {
  const server = createServer(handler);
  servers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as { port: number };
      resolve(`http://127.0.0.1:${addr.port}`);
    });
  });
}

async function startGreen() {
  const store = new InMemoryStore();
  const signing = generateSignerKeyPair(`${WS}_key`);
  store.seedWorkspace(
    WS,
    { api_key: "sk_red", workspace_id: WS, scopes: ["green:create", "green:read"] },
    signing,
  );
  store.addApiKey({ api_key: "sk_app", workspace_id: WS, scopes: ["green:read", "green:decide"] });
  const service = new RequestService({ store });
  const url = await listen(createHandler(service, store));
  return { store, signing, url, service };
}

const RED_POLICY: Policy = {
  id: "pol_red",
  workspace_id: WS,
  version: 1,
  default_effect: "allow",
  rules: [{ id: "r_gate_api", action_type: "/api/*", tags: ["class:suspected_agent"], effect: "gate" }],
};

describe("RedTeamGo ↔ GreenTeamGo (the full suite loop)", () => {
  it("challenge → escalate through Green → human approves → standing allow — one verifiable chain", async () => {
    const green = await startGreen();

    // Red seals into GREEN's store: one workspace chain for both products.
    const gate = new Gate({
      workspace_id: WS,
      policy: RED_POLICY,
      signing: { key_id: `${WS}_key`, privateKeyPem: green.signing.privateKeyPem, chain: green.store },
      escalator: new GreenInboxEscalator({ apiUrl: green.url, apiKey: "sk_red" }),
      allowStore: new InMemoryAllowStore(),
    });

    // A protected app with the Red gate in front (node adapter's view of the request).
    const appUrl = await listen(async (req, res) => {
      const result = await gate.handle(toInboundNode(req));
      if (result.disposition !== "allow") {
        res.writeHead(403, { "content-type": "application/json", "x-redteamgo-disposition": result.disposition });
        res.end(JSON.stringify({ reason: result.reason, escalation: result.escalation }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ orders: [1, 2, 3] }));
    });

    // 1. The foreign agent (a script) hits the protected path → challenged.
    const first = await fetch(`${appUrl}/api/orders`, { headers: { "user-agent": "curl/8.4.0" } });
    expect(first.status).toBe(403);
    expect(first.headers.get("x-redteamgo-disposition")).toBe("challenge");
    const firstBody = (await first.json()) as { escalation?: { request_id: string; status: string } };
    expect(firstBody.escalation?.status).toBe("pending");
    const escalationId = firstBody.escalation!.request_id;

    // 2. The escalation is a REAL pending request in Green's inbox, with the
    //    observed foreign agent as the actor.
    const pending = await (
      await fetch(`${green.url}/v1/requests?status=pending`, { headers: { authorization: "Bearer sk_red" } })
    ).json();
    expect(pending).toHaveLength(1);
    expect(pending[0].request_id).toBe(escalationId);
    // the escalation is about the AGENT (once per agent), not the specific path
    expect(pending[0].summary).toMatch(/requesting access/);

    // 3. Still challenged while the human thinks (fail closed).
    const second = await fetch(`${appUrl}/api/orders`, { headers: { "user-agent": "curl/8.4.0" } });
    expect(second.status).toBe(403);

    // 4. The human approves on their phone (Green's decision endpoint).
    const decide = await fetch(`${green.url}/v1/requests/${escalationId}/decision`, {
      method: "POST",
      headers: { authorization: "Bearer sk_app", "content-type": "application/json" },
      body: JSON.stringify({ decision: "approved", reason: "known partner agent" }),
    });
    expect(decide.status).toBe(200);
    const decided = await decide.json();
    // Green's receipt attributes the OBSERVED foreign agent, not Red's key.
    expect(decided.receipt.actor.type).toBe("observed");

    // 5. The agent's next request passes (standing allow).
    const third = await fetch(`${appUrl}/api/orders`, { headers: { "user-agent": "curl/8.4.0" } });
    expect(third.status).toBe(200);
    expect(await third.json()).toEqual({ orders: [1, 2, 3] });

    // 6. And it keeps passing without re-paging the human.
    const fourth = await fetch(`${appUrl}/api/orders`, { headers: { "user-agent": "curl/8.4.0" } });
    expect(fourth.status).toBe(200);

    // 7. ONE chain, exported from Green, verifies end to end:
    //    challenge (Red, gate verdict) → human approval (Green) → allow (Red).
    const receipts = (await (
      await fetch(`${green.url}/v1/receipts`, { headers: { authorization: "Bearer sk_red" } })
    ).json()) as Receipt[];
    const pub = await (await fetch(`${green.url}/v1/keys`, { headers: { authorization: "Bearer sk_red" } })).json();
    expect(verifyChain(receipts, (id) => (id === pub.key_id ? pub.publicKeyPem : undefined))).toEqual({ ok: true });

    const timeline = receipts.map((r) => `${r.verdict}:${r.status}:${r.decider.method}`);
    expect(timeline).toEqual([
      "gate:challenged:auto", // Red: first hit, escalated, challenged
      "gate:challenged:auto", // Red: second hit while pending
      "approve:approved:app", // Green: the human's decision
      "approve:approved:app", // Red: escalation resolution → allow (human-attributed)
      "approve:approved:auto", // Red: later hit served from the standing allow
    ]);
    // detected → challenged → human-approved → allowed. The loop that sells the suite.
  });

  it("humans browse the protected property untouched the whole time", async () => {
    const green = await startGreen();
    const guard = createFetchGate({
      workspace_id: WS,
      policy: RED_POLICY,
      signing: { key_id: `${WS}_key`, privateKeyPem: green.signing.privateKeyPem, chain: green.store },
    });
    const humanReq = new Request("https://shop.example.com/api/orders", {
      headers: {
        "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1",
        "accept-language": "en-US",
        "sec-fetch-mode": "navigate",
      },
    });
    expect(await guard(humanReq)).toBeNull(); // null = proceed to the app
    expect(green.store.listReceipts(WS)).toHaveLength(0); // no receipt noise for humans
  });

  it("paged once per agent across serverless isolates: same identity, different paths, no 409 dead-end", async () => {
    const green = await startGreen();
    // each Gate+escalator pair is a fresh isolate with an empty in-memory cache
    const mkGate = () =>
      new Gate({
        workspace_id: WS,
        policy: {
          id: "pol_red", workspace_id: WS, version: 1, default_effect: "allow",
          rules: [{ id: "r", action_type: "/api/*", tags: ["class:suspected_agent"], effect: "gate" }],
        },
        signing: { key_id: `${WS}_key`, privateKeyPem: green.signing.privateKeyPem, chain: green.store },
        escalator: new GreenInboxEscalator({ apiUrl: green.url, apiKey: "sk_red" }),
        allowStore: new InMemoryAllowStore(),
      });

    const curl = { method: "GET", path: "/api/orders", headers: { "user-agent": "curl/8.4.0" }, ip: "9.9.9.9" };
    // isolate A escalates /api/orders
    const a = await mkGate().handle(curl);
    expect(a.disposition).toBe("challenge");
    // isolate B (cold cache) sees the SAME agent on a DIFFERENT path — must not 409
    const b = await mkGate().handle({ ...curl, path: "/api/customers" });
    expect(b.disposition).toBe("challenge");
    expect(b.escalation?.status).toBe("pending");

    // still exactly ONE pending escalation for this agent — paged once, not twice
    const pending = await (
      await fetch(`${green.url}/v1/requests?status=pending`, { headers: { authorization: "Bearer sk_red" } })
    ).json();
    expect(pending).toHaveLength(1);
  });
});
