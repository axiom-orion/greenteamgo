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
 * Expired signatures fail structural parsing outright (fail closed).
 */
import type { InboundRequest } from "./classify.js";

export interface ParsedWebBotAuth {
  /** the Signature-Agent value — the signer's key-directory URL/domain */
  signatureAgent?: string;
  /** signature label, e.g. "sig1" */
  label: string;
  /** covered components, e.g. ["@authority", "signature-agent"] */
  components: string[];
  keyid?: string;
  tag?: string;
  created?: number;
  expires?: number;
  /** raw header values, for a verifier that re-derives the signature base */
  raw: { signature: string; signatureInput: string; signatureAgent?: string };
}

/** Verifies a parsed signature (fetches the key directory, checks the RFC 9421
 * signature base). Return true only on a full cryptographic pass. */
export type WebBotAuthVerifier = (
  parsed: ParsedWebBotAuth,
  req: InboundRequest,
) => boolean | Promise<boolean>;

/** Strip optional surrounding double quotes from a structured-field value. */
function unquote(v: string): string {
  return v.startsWith('"') && v.endsWith('"') && v.length >= 2 ? v.slice(1, -1) : v;
}

/**
 * Parse the three Web Bot Auth headers. Returns undefined when the request is
 * not even claiming to be signed, or when the claim is structurally broken or
 * expired — the caller treats both the same way (no proof).
 */
export function parseWebBotAuth(
  headers: Record<string, string | undefined>,
  nowMs: number = Date.now(),
): ParsedWebBotAuth | undefined {
  const signature = headers["signature"];
  const signatureInput = headers["signature-input"];
  if (!signature || !signatureInput) return undefined;

  // Signature-Input: label=("comp1" "comp2");param=value;param="value"
  const m = signatureInput.match(/^\s*([!#$%&'*+\-.^_`|~0-9a-zA-Z]+)=\(([^)]*)\)(.*)$/s);
  if (!m) return undefined;
  const [, label, componentsRaw, paramsRaw] = m;
  const components = componentsRaw
    .split(/\s+/)
    .filter(Boolean)
    .map(unquote);

  const params: Record<string, string> = {};
  for (const part of paramsRaw.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    params[part.slice(0, eq).trim()] = unquote(part.slice(eq + 1).trim());
  }

  const created = params["created"] ? Number(params["created"]) : undefined;
  const expires = params["expires"] ? Number(params["expires"]) : undefined;
  if (expires !== undefined && Number.isFinite(expires) && nowMs / 1000 > expires) {
    return undefined; // expired signature = no claim at all
  }

  return {
    signatureAgent: headers["signature-agent"] ? unquote(headers["signature-agent"]) : undefined,
    label,
    components,
    keyid: params["keyid"],
    tag: params["tag"],
    created,
    expires,
    raw: {
      signature,
      signatureInput,
      signatureAgent: headers["signature-agent"],
    },
  };
}
