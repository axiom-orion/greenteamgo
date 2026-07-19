import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";

import { WebhookNotifier, buildInboxItem, type NotifiableRequest } from "../src/notify.js";

const req: NotifiableRequest = {
  request_id: "req_1",
  workspace_id: "ws1",
  action_type: "git_push",
  summary: "push 3 commits to main",
  detail: "diff…",
  risk: "high",
  created_at: "2026-07-19T12:00:00.000Z",
  expires_at: "2026-07-19T12:15:00.000Z",
};

describe("buildInboxItem", () => {
  it("produces a render-ready item with a deep link and the two actions", () => {
    const item = buildInboxItem(req, { deepLinkBase: "greenteamgo://requests" });
    expect(item.summary).toBe("push 3 commits to main");
    expect(item.risk).toBe("high");
    expect(item.deep_link).toBe("greenteamgo://requests/req_1");
    expect(item.actions).toEqual(["approve", "deny"]);
  });

  it("defaults the deep link base and encodes the id", () => {
    const item = buildInboxItem({ ...req, request_id: "a/b" });
    expect(item.deep_link).toBe("greenteamgo://requests/a%2Fb");
  });
});

describe("WebhookNotifier", () => {
  let server: Server | undefined;
  afterEach(() => new Promise<void>((r) => (server ? server.close(() => r()) : r())));

  function stub(onBody: (body: string, auth: string | undefined) => number) {
    return new Promise<string>((resolve) => {
      server = createServer((rq, rs) => {
        let body = "";
        rq.on("data", (c) => (body += c));
        rq.on("end", () => {
          const code = onBody(body, rq.headers["authorization"]);
          rs.writeHead(code);
          rs.end();
        });
      });
      server.listen(0, "127.0.0.1", () => {
        const addr = server!.address() as { port: number };
        resolve(`http://127.0.0.1:${addr.port}`);
      });
    });
  }

  it("POSTs the inbox item (with bearer token) to the webhook", async () => {
    let received: any;
    let auth: string | undefined;
    const url = await stub((body, a) => {
      received = JSON.parse(body);
      auth = a;
      return 200;
    });
    await new WebhookNotifier({ url, token: "hook-secret" }).notify(req);
    expect(received.request_id).toBe("req_1");
    expect(received.actions).toEqual(["approve", "deny"]);
    expect(auth).toBe("Bearer hook-secret");
  });

  it("throws when the webhook rejects (so paging failures surface)", async () => {
    const url = await stub(() => 500);
    await expect(new WebhookNotifier({ url }).notify(req)).rejects.toThrow(/webhook notify failed: 500/);
  });
});
