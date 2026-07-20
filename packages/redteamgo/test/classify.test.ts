import { describe, expect, it } from "vitest";

import { classify, type InboundRequest } from "../src/classify.js";

const BROWSER_HEADERS = {
  "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36",
  "accept-language": "en-US,en;q=0.9",
  "sec-fetch-mode": "navigate",
};

function req(over: Partial<InboundRequest> = {}): InboundRequest {
  return { method: "GET", path: "/", headers: { ...BROWSER_HEADERS }, ip: "203.0.113.9", ...over };
}

const SIGNED_HEADERS = {
  "signature-agent": '"https://agent.example.com"',
  "signature-input": 'sig1=("@authority" "signature-agent");created=1700000000;keyid="k1";tag="web-bot-auth"',
  signature: "sig1=:aGVsbG8=:",
};

describe("classify — Web Bot Auth", () => {
  it("classifies verified_agent ONLY when the verifier passes", async () => {
    const c = await classify(req({ headers: { ...SIGNED_HEADERS, "user-agent": "MyAgent/1.0" } }), {
      webBotAuthVerifier: () => true,
    });
    expect(c.class).toBe("verified_agent");
    expect(c.confidence).toBe("proof");
    expect(c.agent_id).toBe("https://agent.example.com");
    expect(c.signals).toContain("web_bot_auth_verified");
  });

  it("a signature that fails verification is suspected, never verified", async () => {
    const c = await classify(req({ headers: { ...SIGNED_HEADERS, "user-agent": "MyAgent/1.0" } }), {
      webBotAuthVerifier: () => false,
    });
    expect(c.class).toBe("suspected_agent");
    expect(c.signals).toContain("web_bot_auth_invalid");
  });

  it("a crashing verifier is non-proof (fail closed), not an exception", async () => {
    const c = await classify(req({ headers: { ...SIGNED_HEADERS, "user-agent": "MyAgent/1.0" } }), {
      webBotAuthVerifier: () => {
        throw new Error("network down");
      },
    });
    expect(c.class).toBe("suspected_agent");
  });

  it("signature headers with NO verifier configured are a claim → suspected", async () => {
    const c = await classify(req({ headers: { ...SIGNED_HEADERS, "user-agent": "MyAgent/1.0" } }));
    expect(c.class).toBe("suspected_agent");
    expect(c.signals).toContain("web_bot_auth_unverified");
  });

  it("an EXPIRED signature is no claim at all — falls through to other checks", async () => {
    const expired = {
      ...SIGNED_HEADERS,
      "signature-input": 'sig1=("@authority");created=1;keyid="k1";tag="web-bot-auth";expires=2',
      "user-agent": BROWSER_HEADERS["user-agent"],
      "accept-language": "en-US",
    };
    const c = await classify(req({ headers: expired }), { webBotAuthVerifier: () => true });
    expect(c.class).toBe("human"); // browser-shaped request, dead signature
  });
});

describe("classify — declared bots", () => {
  it("matches the registry by UA token", async () => {
    const c = await classify(req({ headers: { "user-agent": "Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)" } }));
    expect(c.class).toBe("declared_bot");
    expect(c.agent_id).toBe("gptbot");
    expect(c.confidence).toBe("declared");
  });

  it("upgrades to proof when the ipVerifier confirms the operator's IP", async () => {
    const c = await classify(req({ headers: { "user-agent": "GPTBot/1.1" } }), {
      ipVerifier: (agent, ip) => agent.id === "gptbot" && ip === "203.0.113.9",
    });
    expect(c.class).toBe("declared_bot");
    expect(c.confidence).toBe("proof");
    expect(c.signals).toContain("ip_confirmed");
  });

  it("downgrades a spoofed UA (ipVerifier says not the operator) to suspected", async () => {
    const c = await classify(req({ headers: { "user-agent": "Googlebot/2.1" } }), {
      ipVerifier: () => false,
    });
    expect(c.class).toBe("suspected_agent");
    expect(c.signals).toContain("ua_ip_mismatch");
    expect(c.evidence.claimed_agent).toBe("googlebot");
  });

  it("an inconclusive ipVerifier (undefined) keeps the declared classification", async () => {
    const c = await classify(req({ headers: { "user-agent": "ClaudeBot/1.0" } }), {
      ipVerifier: () => undefined,
    });
    expect(c.class).toBe("declared_bot");
    expect(c.confidence).toBe("declared");
  });

  it("custom registry entries extend and override the built-ins", async () => {
    const c = await classify(req({ headers: { "user-agent": "MyCorpAgent/2.0" } }), {
      knownAgents: [{ id: "mycorp", operator: "MyCorp", ua_tokens: ["MyCorpAgent"], category: "other" }],
    });
    expect(c.class).toBe("declared_bot");
    expect(c.agent_id).toBe("mycorp");
  });
});

describe("classify — heuristics", () => {
  it("flags automation UAs", async () => {
    for (const ua of ["curl/8.4.0", "python-requests/2.31", "Go-http-client/1.1", "node-fetch/3"]) {
      const c = await classify(req({ headers: { "user-agent": ua, "accept-language": "en" } }));
      expect(c.class).toBe("suspected_agent");
      expect(c.signals).toContain("automation_ua");
    }
  });

  it("flags an empty UA", async () => {
    const c = await classify(req({ headers: {} }));
    expect(c.class).toBe("suspected_agent");
    expect(c.signals).toContain("empty_ua");
  });

  it("flags a honeypot path hit even with a browser UA", async () => {
    const c = await classify(req({ path: "/wp-admin/setup.php" }), { honeypots: ["/wp-admin/*"] });
    expect(c.class).toBe("suspected_agent");
    expect(c.signals).toContain("honeypot_hit");
  });

  it("flags a browser UA that sends none of the browser headers", async () => {
    const c = await classify(req({ headers: { "user-agent": BROWSER_HEADERS["user-agent"] } }));
    expect(c.class).toBe("suspected_agent");
    expect(c.signals).toContain("browser_ua_without_browser_headers");
  });

  it("headless/driver markers classify as suspected", async () => {
    const c = await classify(
      req({ headers: { "user-agent": "Mozilla/5.0 HeadlessChrome/126", "accept-language": "en" } }),
    );
    expect(c.class).toBe("suspected_agent");
  });
});

describe("classify — humans", () => {
  it("a normal browser request is human", async () => {
    const c = await classify(req());
    expect(c.class).toBe("human");
    expect(c.confidence).toBe("default");
  });

  it("a browser with sec-fetch-* but no accept-language is still human (conservative)", async () => {
    const headers = { "user-agent": BROWSER_HEADERS["user-agent"], "sec-fetch-mode": "navigate" };
    const c = await classify(req({ headers }));
    expect(c.class).toBe("human");
  });
});
