/**
 * GPT-powered risk summary for the approval card (GreenCodex — OpenAI Build Week).
 *
 * When Codex asks to do something risky, a one-line, plain-English "here's what
 * this actually does and why it's risky" makes the human's approve/deny call
 * faster and better. This is a direct, meaningful use of the model (GPT) on top
 * of Codex (the coding agent).
 *
 * Dependency-light (fetch against the OpenAI API) and FAIL-SOFT: any error —
 * no key, wrong model, network — returns undefined so the demo still works; the
 * card just falls back to the raw summary.
 */
const OPENAI_URL = "https://api.openai.com/v1/chat/completions";
// GPT-5.6 family (on-theme for Build Week). Override via OPENAI_MODEL — e.g.
// "gpt-5-mini" for a cheaper/faster summary. 5.x may reason, so give token headroom.
const MODEL = process.env.OPENAI_MODEL ?? "gpt-5.6-luna";

export interface RiskInput {
  action_type: string;
  summary: string;
  detail?: string;
  payload?: string;
  risk: string;
}

const SYSTEM = `You brief a busy human who must approve or deny an AI coding agent's
action in one tap. In ONE sentence (max 25 words), plainly state what the action
does and the single biggest reason to be careful. No preamble, no markdown.`;

export async function summarizeRisk(
  input: RiskInput,
  fetchFn: typeof fetch = fetch,
): Promise<string | undefined> {
  const key = process.env.OPENAI_API_KEY;
  if (!key) return undefined;
  const user = [
    `Action type: ${input.action_type}`,
    `Risk: ${input.risk}`,
    `Summary: ${input.summary}`,
    input.detail ? `Detail: ${input.detail}` : "",
    input.payload ? `Payload (truncated): ${input.payload.slice(0, 800)}` : "",
  ].filter(Boolean).join("\n");

  try {
    const res = await fetchFn(OPENAI_URL, {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
      body: JSON.stringify({
        model: MODEL,
        messages: [
          { role: "system", content: SYSTEM },
          { role: "user", content: user },
        ],
        max_completion_tokens: 400,
      }),
    });
    if (!res.ok) return undefined;
    const data = (await res.json()) as { choices?: { message?: { content?: string } }[] };
    const text = data.choices?.[0]?.message?.content?.trim();
    return text || undefined;
  } catch {
    return undefined;
  }
}
