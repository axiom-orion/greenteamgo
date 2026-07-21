import { afterEach, describe, expect, it, vi } from "vitest";

import { compilePolicy } from "../src/nl-policy.js";

const originalKey = process.env.OPENAI_API_KEY;

afterEach(() => {
  if (originalKey === undefined) delete process.env.OPENAI_API_KEY;
  else process.env.OPENAI_API_KEY = originalKey;
});

function mockOpenAi(content: string): typeof fetch {
  return vi.fn(async () => new Response(JSON.stringify({
    choices: [{ message: { content } }],
  }), { status: 200 })) as unknown as typeof fetch;
}

describe("compilePolicy", () => {
  it("returns a validated, safe-default Policy from model JSON", async () => {
    process.env.OPENAI_API_KEY = "test-key";
    const fetchFn = mockOpenAi(JSON.stringify([
      { id: "deny_payments", action_type: "payment*", effect: "deny", risk_class: "critical" },
      { id: "allow_reads", action_type: "file_read", effect: "allow", risk_class: "low" },
      { id: "gate_changes", action_type: "git_push", effect: "gate" },
    ]));

    await expect(compilePolicy("Protect payments", {
      id: "pol_workspace", workspace_id: "ws_1", version: 4, fetchFn,
    })).resolves.toEqual({
      id: "pol_workspace", workspace_id: "ws_1", version: 4, default_effect: "gate",
      rules: [
        { id: "deny_payments", action_type: "payment*", effect: "deny", risk_class: "critical" },
        { id: "allow_reads", action_type: "file_read", effect: "allow", risk_class: "low" },
        { id: "gate_changes", action_type: "git_push", effect: "gate" },
      ],
    });
    expect(fetchFn).toHaveBeenCalledWith("https://api.openai.com/v1/chat/completions", expect.objectContaining({
      method: "POST",
      body: expect.stringContaining("gpt-5.6-luna"),
    }));
  });

  it.each([
    JSON.stringify([{ id: "bad_effect", effect: "approve" }]),
    JSON.stringify([{ effect: "deny" }]),
  ])("rejects malformed model rules", async (content) => {
    process.env.OPENAI_API_KEY = "test-key";
    await expect(compilePolicy("Protect us", { fetchFn: mockOpenAi(content) })).rejects.toThrow("Invalid policy rule");
  });

  it.each([
    ["not JSON", "invalid JSON"],
    [JSON.stringify({ id: "not_an_array", effect: "deny" }), "JSON array of rules"],
  ])("rejects invalid model response content", async (content, error) => {
    process.env.OPENAI_API_KEY = "test-key";
    await expect(compilePolicy("Protect us", { fetchFn: mockOpenAi(content) })).rejects.toThrow(error);
  });

  it("rejects an unsuccessful OpenAI response", async () => {
    process.env.OPENAI_API_KEY = "test-key";
    const fetchFn = vi.fn(async () => new Response("rate limited", { status: 429 })) as unknown as typeof fetch;

    await expect(compilePolicy("Protect us", { fetchFn })).rejects.toThrow("failed (429)");
  });

  it("rejects an empty OpenAI response", async () => {
    process.env.OPENAI_API_KEY = "test-key";
    await expect(compilePolicy("Protect us", { fetchFn: mockOpenAi("") })).rejects.toThrow("returned no JSON");
  });
});
