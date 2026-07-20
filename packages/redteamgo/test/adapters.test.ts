import { describe, expect, it } from "vitest";

import { generateSignerKeyPair } from "@vorionsys/greenteamgo-core";
import type { Policy } from "@vorionsys/greenteamgo-policy";

import { createFetchGate, createFetchGateWithResult } from "../src/adapters/fetch.js";
import { InMemoryChainStore } from "../src/gate.js";

const key = generateSignerKeyPair("ws1_key");
const DENY_BOTS: Policy = {
  id: "pol", workspace_id: "ws1", version: 1, default_effect: "allow",
  rules: [{ id: "r", action_type: "*", tags: ["class:suspected_agent"], effect: "deny" }],
};

function opts(extra: Record<string, unknown> = {}) {
  return {
    workspace_id: "ws1",
    policy: DENY_BOTS,
    signing: { key_id: key.key_id, privateKeyPem: key.privateKeyPem, chain: new InMemoryChainStore() },
    now: () => 1_000_000,
    ...extra,
  };
}

describe("fetch adapter", () => {
  it("returns a 403 JSON response with the disposition header for a blocked agent", async () => {
    const guard = createFetchGate(opts() as never);
    const res = await guard(new Request("https://x.example/api", { headers: { "user-agent": "curl/8" } }));
    expect(res).not.toBeNull();
    expect(res!.status).toBe(403);
    expect(res!.headers.get("x-redteamgo-disposition")).toBe("block");
    const body = await res!.json();
    expect(body.error).toBe("agent_blocked");
  });

  it("wires ipFrom into classification/identity (the derived IP reaches the gate)", async () => {
    let seenIp: string | undefined;
    const guard = createFetchGateWithResult(
      opts({
        ipFrom: () => "203.0.113.9",
        ipVerifier: (_agent: unknown, ip: string) => {
          seenIp = ip;
          return false;
        },
      }) as never,
    );
    // a registry UA so ipVerifier runs; the adapter must have supplied the IP
    const { result } = await guard(
      new Request("https://x.example/api", { headers: { "user-agent": "Googlebot/2.1" } }),
    );
    expect(seenIp).toBe("203.0.113.9");
    expect(result.classification.class).toBe("suspected_agent"); // ip mismatch
  });

  it("returns null (proceed) for allowed traffic", async () => {
    const guard = createFetchGate(opts() as never);
    const res = await guard(
      new Request("https://x.example/", {
        headers: { "user-agent": "Mozilla/5.0", "accept-language": "en", "sec-fetch-mode": "navigate" },
      }),
    );
    expect(res).toBeNull();
  });
});
