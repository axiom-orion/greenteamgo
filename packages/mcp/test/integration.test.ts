/**
 * End-to-end interop: the REAL MCP client (client.ts) driving the REAL inbox
 * API (@vorionsys/greenteamgo-api) to a verified, signed receipt.
 *
 * This is the whole loop the product makes — agent asks → human decides →
 * signed receipt the agent can trust — exercised across the two packages that
 * were built to the same contract but otherwise never run together.
 */
import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";

import { generateSignerKeyPair, verifyReceipt } from "@vorionsys/greenteamgo-core";
import {
  InMemoryStore,
  RequestService,
  createHandler,
  type ApiKeySeed,
} from "@vorionsys/greenteamgo-api";

import { GreenTeamGoClient } from "../src/client.js";

let server: Server | undefined;
afterEach(() => new Promise<void>((r) => (server ? server.close(() => r()) : r())));

function startApi() {
  const store = new InMemoryStore();
  const signing = generateSignerKeyPair("ws1_key");
  const agentKey: ApiKeySeed = { api_key: "sk_agent", workspace_id: "ws1", scopes: ["green:create", "green:read"] };
  const appKey: ApiKeySeed = { api_key: "sk_app", workspace_id: "ws1", scopes: ["green:read", "green:decide"] };
  store.seedWorkspace("ws1", agentKey, signing);
  store.addApiKey(appKey);
  const service = new RequestService({ store });
  server = createServer(createHandler(service, store));
  return new Promise<{ url: string; signing: typeof signing }>((resolve) => {
    server!.listen(0, "127.0.0.1", () => {
      const addr = server!.address() as { port: number };
      resolve({ url: `http://127.0.0.1:${addr.port}`, signing });
    });
  });
}

/** Simulate the human tapping "approve" in the phone app. */
async function humanDecides(url: string, id: string, decision: "approved" | "denied", reason?: string) {
  const res = await fetch(`${url}/v1/requests/${id}/decision`, {
    method: "POST",
    headers: { authorization: "Bearer sk_app", "content-type": "application/json" },
    body: JSON.stringify({ decision, reason, decider_id: "user_1" }),
  });
  if (!res.ok) throw new Error(`decision failed: ${res.status}`);
}

describe("MCP client ↔ inbox API (full product loop)", () => {
  it("agent requests → human approves → agent receives a verifiable signed receipt", async () => {
    const { url, signing } = await startApi();
    const client = new GreenTeamGoClient({ apiUrl: url, apiKey: "sk_agent" });

    const created = await client.createRequest({
      action_type: "git_push",
      summary: "push 3 commits to main",
      payload: { branch: "main", commits: 3 },
      risk: "high",
      timeout_s: 900,
      mode: "block",
    });
    expect(created.status).toBe("pending");

    await humanDecides(url, created.request_id, "approved", "looks good");

    const decision = await client.waitForDecision(created.request_id, Date.now() + 5000, {
      initialMs: 20,
      maxMs: 50,
    });
    expect(decision.status).toBe("approved");
    expect(decision.receipt).toBeDefined();
    // The receipt the agent got back verifies under the workspace's key.
    expect(verifyReceipt(decision.receipt as never, signing.publicKeyPem)).toEqual({ ok: true });
  });

  it("FAILS CLOSED: no human decision before the deadline → expired (treat as deny)", async () => {
    const { url } = await startApi();
    const client = new GreenTeamGoClient({ apiUrl: url, apiKey: "sk_agent" });

    const created = await client.createRequest({
      action_type: "payment",
      summary: "send $500",
      risk: "critical",
      timeout_s: 1, // 1s deadline, nobody answers
      mode: "block",
    });

    const decision = await client.waitForDecision(created.request_id, Date.now() + 2500, {
      initialMs: 50,
      maxMs: 200,
    });
    expect(decision.status).toBe("expired");
  });
});
