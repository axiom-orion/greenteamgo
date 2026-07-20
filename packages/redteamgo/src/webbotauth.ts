/**
 * Web Bot Auth — structural parsing of HTTP Message Signature headers
 * (RFC 9421 profile, draft-meunier-web-bot-auth-architecture).
 *
 * An agent that signs its requests sends three headers:
 *   Signature-Agent: "https://signer.example.com"      (its key directory)
 *   Signature-Input: sig1=("@authority" "signature-agent");created=...;
 *                    keyid="...";tag="web-bot-auth";expires=...
 *   Signature:       sig1=:BASE64:
 *
 * This module only PARSES — extracting the claim so the classifier can reason
 * about it. Actual cryptographic verification needs a network fetch of the
 * signer's key directory, so it is injected as a `WebBotAuthVerifier`; parse
 * results without a passing verifier are treated as claims, never proof.
 *
 * Presence vs validity are distinct on purpose. A request that carries the
 * signature headers has DECLARED itself an agent — even if the signature is
 * expired or malformed. We must not let a deliberately-expired signature erase
 * that declaration and fall through to the human default (fail-open). So parse
 * returns `undefined` ONLY when the headers are absent; a present-but-broken
 * claim comes back with `valid: false` so the classifier keeps it a suspected
 * agent.
 */
import type { InboundRequest } from "./classify.js";

export interface ParsedWebBotAuth {
  /** the headers were present (this request declared itself an agent) */
  present: true;
  /** structurally sound AND not expired — eligible for verification */
  valid: boolean;
  /** why it is invalid, when valid === false */
  reason?: string;
  /** the Signature-Agent value — the signer's key-directory URL/domain */
  signatureAgent?: string;
  /** signature label, e.g. "sig1" */
  label?: string;
  /** covered components, e.g. ["@authority", "signature-agent"] */
  components?: string[];
  keyid?: string;
  tag?: string;
  created?: number;
  expires?: number;
  /** raw header values, for a verifier that re-derives the signature base */
  raw: { signature: string; signatureInput: string; signatureAgent?: string };
}

/** Verifies a parsed signature (fetches the key directory, checks the RFC 9421
 * signature base). Must return the boolean literal `true` — and only that — on
 * a full cryptographic pass; the classifier accepts nothing looser. */
export type WebBotAuthVerifier = (
  parsed: ParsedWebBotAuth,
  req: InboundRequest,
) => boolean | Promise<boolean>;

/** Strip optional surrounding double quotes from a structured-field value. */
function unquote(v: string): string {
  return v.startsWith('"') && v.endsWith('"') && v.length >= 2 ? v.slice(1, -1) : v;
}

/**
 * Parse the three Web Bot Auth headers. Returns undefined ONLY when the request
 * carries no signature headers at all. A present-but-broken or expired claim
 * returns `{ present: true, valid: false, reason }` so it is never mistaken for
 * plain human traffic.
 */
export function parseWebBotAuth(
  headers: Record<string, string | undefined>,
  nowMs: number = Date.now(),
): ParsedWebBotAuth | undefined {
  const signature = headers["signature"];
  const signatureInput = headers["signature-input"];
  if (!signature || !signatureInput) return undefined; // truly absent

  const raw = { signature, signatureInput, signatureAgent: headers["signature-agent"] };
  const signatureAgent = headers["signature-agent"] ? unquote(headers["signature-agent"]) : undefined;
  const invalid = (reason: string): ParsedWebBotAuth => ({ present: true, valid: false, reason, signatureAgent, raw });

  // Signature-Input: label=("comp1" "comp2");param=value;param="value"
  const m = signatureInput.match(/^\s*([!#$%&'*+\-.^_`|~0-9a-zA-Z]+)=\(([^)]*)\)(.*)$/s);
  if (!m) return invalid("malformed Signature-Input");
  const [, label, componentsRaw, paramsRaw] = m;
  const components = componentsRaw.split(/\s+/).filter(Boolean).map(unquote);

  const params: Record<string, string> = {};
  for (const part of paramsRaw.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    params[part.slice(0, eq).trim()] = unquote(part.slice(eq + 1).trim());
  }

  const created = params["created"] !== undefined ? Number(params["created"]) : undefined;
  const expires = params["expires"] !== undefined ? Number(params["expires"]) : undefined;

  if (expires !== undefined) {
    // A present-but-non-numeric expires must fail closed, not be read as
    // "never expires". Number("abc") === NaN, isFinite(NaN) === false.
    if (!Number.isFinite(expires)) return invalid("non-numeric expires");
    if (nowMs / 1000 > expires) return invalid("expired signature");
  }
  if (created !== undefined && !Number.isFinite(created)) return invalid("non-numeric created");

  return {
    present: true,
    valid: true,
    signatureAgent,
    label,
    components,
    keyid: params["keyid"],
    tag: params["tag"],
    created,
    expires,
    raw,
  };
}
