import { afterEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildServer } from "../src/server.js";
import { encodePayload, MAX_PAYLOAD_BYTES } from "../src/client.js";
import type { Config } from "../src/config.js";
import { startStub, type Stub } from "./stub-api.js";

let stub: Stub | undefined;
let clients: Client[] = [];

afterEach(async () => {
  for (const c of clients) await c.close().catch(() => {});
  clients = [];
  await stub?.close();
  stub = undefined;
});

function cfgFor(s: Stub, overrides: Partial<Config> = {}): Config {
  return {
    apiUrl: s.url,
    apiKey: "test-key",
    defaultRisk: "medium",
    defaultBlockTimeoutS: 900,
    defaultAsyncTimeoutS: 86400,
    pollInitialMs: 25,
    ...overrides,
  };
}

async function connect(cfg: Config): Promise<Client> {
  const server = buildServer(cfg);
  const client = new Client({ name: "test-client", version: "0.0.0" });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(st), client.connect(ct)]);
  clients.push(client);
  return client;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parse(res: any): any {
  return JSON.parse(res.content[0].text);
}

describe("greenteamgo-mcp", () => {
  it("exposes the three spec tools", async () => {
    stub = await startStub();
    const client = await connect(cfgFor(stub));
    const tools = await client.listTools();
    const names = tools.tools.map((t) => t.name).sort();
    expect(names).toEqual(["get_decision", "list_pending", "request_approval"]);
  });

  it("block mode: returns approved with a receipt", async () => {
    stub = await startStub({ autoDecision: "approved", autoDelayMs: 60 });
    const client = await connect(cfgFor(stub));
    const res = await client.callTool({
      name: "request_approval",
      arguments: {
        action_type: "git_push",
        summary: "push 3 commits to main",
        payload: { branch: "main", commits: 3 },
        risk: "high",
        timeout_s: 30,
      },
    });
    const out = parse(res);
    expect(out.status).toBe("approved");
    expect(out.receipt).toBeDefined();
    expect(out.receipt.sig).toBe("stub-ed25519");
  });

  it("block mode: deny-with-reason propagates the reason", async () => {
    stub = await startStub({ autoDecision: "denied", autoDelayMs: 60, denyReason: "wrong branch — use a PR" });
    const client = await connect(cfgFor(stub));
    const res = await client.callTool({
      name: "request_approval",
      arguments: { action_type: "git_push", summary: "push to main", timeout_s: 30 },
    });
    const out = parse(res);
    expect(out.status).toBe("denied");
    expect(out.reason).toBe("wrong branch — use a PR");
  });

  it("block mode: no decision → expired, marked fail-closed", async () => {
    stub = await startStub(); // nobody ever decides
    const client = await connect(cfgFor(stub));
    const started = Date.now();
    const res = await client.callTool({
      name: "request_approval",
      arguments: { action_type: "shell_exec", summary: "rm -rf ./build", timeout_s: 1 },
    });
    const out = parse(res);
    expect(out.status).toBe("expired");
    expect(out.note).toContain("fail closed");
    expect(Date.now() - started).toBeLessThan(10000);
  });

  it("async mode: pending → decide → get_decision returns approved", async () => {
    stub = await startStub();
    const client = await connect(cfgFor(stub));
    const created = parse(
      await client.callTool({
        name: "request_approval",
        arguments: { action_type: "payment", summary: "pay invoice #42", mode: "async" },
      }),
    );
    expect(created.status).toBe("pending");
    expect(created.request_id).toBeTruthy();

    stub.decide(created.request_id, "approved");
    const decided = parse(
      await client.callTool({ name: "get_decision", arguments: { request_id: created.request_id } }),
    );
    expect(decided.status).toBe("approved");
    expect(decided.receipt).toBeDefined();
  });

  it("list_pending shows undecided requests", async () => {
    stub = await startStub();
    const client = await connect(cfgFor(stub));
    const created = parse(
      await client.callTool({
        name: "request_approval",
        arguments: { action_type: "file_write", summary: "overwrite prod config", mode: "async" },
      }),
    );
    const pending = parse(await client.callTool({ name: "list_pending", arguments: {} }));
    expect(pending.map((p: { request_id: string }) => p.request_id)).toContain(created.request_id);
    expect(pending[0].summary).toBe("overwrite prod config");
  });

  it("rejects payloads over 256KB before any network call", async () => {
    stub = await startStub();
    const client = await connect(cfgFor(stub));
    const res = await client.callTool({
      name: "request_approval",
      arguments: {
        action_type: "file_write",
        summary: "huge diff",
        payload: "x".repeat(MAX_PAYLOAD_BYTES + 1),
        timeout_s: 5,
      },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((res as any).isError).toBe(true);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((res as any).content[0].text).toContain("fail closed");
    expect(stub.requests.size).toBe(0);
  });

  it("sends the correct client-side SHA-256 of the payload", async () => {
    stub = await startStub({ autoDecision: "approved", autoDelayMs: 20 });
    const client = await connect(cfgFor(stub));
    const payload = { cmd: "rm", args: ["-rf", "build"] };
    await client.callTool({
      name: "request_approval",
      arguments: { action_type: "shell_exec", summary: "clean build dir", payload, timeout_s: 10 },
    });
    const rec = [...stub.requests.values()][0];
    const expected = encodePayload(payload);
    expect(rec.payload_sha256).toBe(expected?.sha256);
    expect(rec.receipt?.payload_sha256).toBe(expected?.sha256);
  });

  it("auth failure is an error, not an approval", async () => {
    stub = await startStub();
    const client = await connect(cfgFor(stub, { apiKey: "wrong-key" }));
    const res = await client.callTool({
      name: "request_approval",
      arguments: { action_type: "git_push", summary: "push", timeout_s: 5 },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((res as any).isError).toBe(true);
  });
});
