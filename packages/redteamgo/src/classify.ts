/**
 * Inbound classifier — "what is this thing and can it prove it."
 *
 * Four classes, checked in order of evidence strength (first match wins):
 *   1. verified_agent — Web Bot Auth signature that actually VERIFIES via the
 *      injected verifier. Presence of signature headers alone proves nothing:
 *      unverifiable/invalid signatures classify as suspected, never verified.
 *   2. declared_bot — User-Agent matches the known-agent registry. If an
 *      ipVerifier is configured and says the IP is NOT the operator's, the
 *      claim is treated as spoofed → suspected.
 *   3. suspected_agent — honeypot path hit, automation-tool UA, or a request
 *      shaped like a script pretending to be a browser.
 *   4. human — the default. RedTeamGo v1 never gates humans; getting this
 *      wrong in the strict direction is worse than letting a clever bot pass.
 *
 * This module is pure and synchronous except for the two injected verifiers;
 * it does no network I/O of its own.
 */
import { KNOWN_AGENTS, type KnownAgent } from "./known-agents.js";
import { parseWebBotAuth, type WebBotAuthVerifier } from "./webbotauth.js";

export type AgentClass = "verified_agent" | "declared_bot" | "suspected_agent" | "human";

/** How strongly we believe the classification. */
export type Confidence = "proof" | "declared" | "heuristic" | "default";

/** Framework-agnostic view of an inbound request. Adapters build this. */
export interface InboundRequest {
  method: string;
  /** path only, no query — policy rules match on this */
  path: string;
  /** lower-cased header names */
  headers: Record<string, string | undefined>;
  ip?: string;
}

export interface Classification {
  class: AgentClass;
  /** stable identity: registry id, Web Bot Auth key directory, or undefined */
  agent_id?: string;
  confidence: Confidence;
  /** which signals fired, for receipts and debugging */
  signals: string[];
  /** goes into the receipt's actor.evidence verbatim */
  evidence: Record<string, unknown>;
}

/** UA tokens that mean "a script, not a browser" (case-insensitive). */
const AUTOMATION_UA_TOKENS = [
  "curl/",
  "wget/",
  "python-requests",
  "python-httpx",
  "python-urllib",
  "aiohttp",
  "go-http-client",
  "okhttp",
  "java/",
  "node-fetch",
  "axios/",
  "undici",
  "libwww-perl",
  "headlesschrome",
  "playwright",
  "puppeteer",
  "phantomjs",
  "selenium",
];

export interface ClassifyOptions {
  /** paths (exact or prefix ending in *) that only a crawler would fetch */
  honeypots?: string[];
  /** verifies a parsed Web Bot Auth signature (network key fetch lives here) */
  webBotAuthVerifier?: WebBotAuthVerifier;
  /** extra registry entries merged over the built-ins (same id overrides) */
  knownAgents?: KnownAgent[];
  /**
   * Confirms a declared bot's source IP belongs to its operator.
   * Return true = confirmed, false = spoofed, undefined = cannot tell.
   */
  ipVerifier?: (agent: KnownAgent, ip: string) => boolean | undefined | Promise<boolean | undefined>;
}

function pathMatches(pattern: string, path: string): boolean {
  if (pattern.endsWith("*")) return path.startsWith(pattern.slice(0, -1));
  return pattern === path;
}

function findKnownAgent(ua: string, extra?: KnownAgent[]): KnownAgent | undefined {
  const uaLower = ua.toLowerCase();
  const merged = new Map<string, KnownAgent>();
  for (const a of KNOWN_AGENTS) merged.set(a.id, a);
  for (const a of extra ?? []) merged.set(a.id, a);
  for (const agent of merged.values()) {
    if (agent.ua_tokens.some((t) => uaLower.includes(t.toLowerCase()))) return agent;
  }
  return undefined;
}

/** Looks like a script wearing a browser UA: browser-ish UA but none of the
 * headers real browsers always send. Deliberately conservative — both
 * accept-language AND every sec-fetch-* header must be absent. */
function missingBrowserHeaders(req: InboundRequest): boolean {
  const ua = (req.headers["user-agent"] ?? "").toLowerCase();
  const claimsBrowser = ua.includes("mozilla/");
  if (!claimsBrowser) return false;
  const hasLang = req.headers["accept-language"] !== undefined;
  const hasSecFetch = Object.keys(req.headers).some((h) => h.startsWith("sec-fetch-"));
  return !hasLang && !hasSecFetch;
}

export async function classify(
  req: InboundRequest,
  opts: ClassifyOptions = {},
): Promise<Classification> {
  const ua = req.headers["user-agent"] ?? "";
  const signals: string[] = [];

  // 1. Web Bot Auth — cryptographic proof beats everything, but only if it
  // actually verifies. A signature we cannot verify is a claim, not proof.
  const wba = parseWebBotAuth(req.headers);
  if (wba) {
    if (opts.webBotAuthVerifier) {
      let ok = false;
      try {
        ok = await opts.webBotAuthVerifier(wba, req);
      } catch {
        ok = false; // verifier errors are non-proof, never trust-by-crash
      }
      if (ok) {
        return {
          class: "verified_agent",
          agent_id: wba.signatureAgent,
          confidence: "proof",
          signals: ["web_bot_auth_verified"],
          evidence: { signature_agent: wba.signatureAgent, keyid: wba.keyid, tag: wba.tag },
        };
      }
      signals.push("web_bot_auth_invalid");
    } else {
      signals.push("web_bot_auth_unverified");
    }
    // Signed-but-unproven falls through; the signature headers themselves are
    // an agent declaration, so at minimum this is not plain human traffic.
  }

  // 2. Declared bot — UA registry match, optionally IP-confirmed.
  const known = findKnownAgent(ua, opts.knownAgents);
  if (known) {
    if (opts.ipVerifier && req.ip) {
      let confirmed: boolean | undefined;
      try {
        confirmed = await opts.ipVerifier(known, req.ip);
      } catch {
        confirmed = undefined; // cannot tell ≠ spoofed
      }
      if (confirmed === false) {
        return {
          class: "suspected_agent",
          confidence: "heuristic",
          signals: [...signals, "ua_ip_mismatch"],
          evidence: { claimed_agent: known.id, ua, ip: req.ip },
        };
      }
      if (confirmed === true) {
        return {
          class: "declared_bot",
          agent_id: known.id,
          confidence: "proof",
          signals: [...signals, "ua_registry_match", "ip_confirmed"],
          evidence: { agent: known.id, operator: known.operator, ua, ip: req.ip },
        };
      }
    }
    return {
      class: "declared_bot",
      agent_id: known.id,
      confidence: "declared",
      signals: [...signals, "ua_registry_match"],
      evidence: { agent: known.id, operator: known.operator, ua },
    };
  }

  // Unverified/invalid Web Bot Auth with no registry match: an undeclared agent.
  if (wba) {
    return {
      class: "suspected_agent",
      agent_id: wba.signatureAgent,
      confidence: "heuristic",
      signals,
      evidence: { signature_agent: wba.signatureAgent, keyid: wba.keyid, ua },
    };
  }

  // 3. Heuristics.
  if (opts.honeypots?.some((p) => pathMatches(p, req.path))) {
    return {
      class: "suspected_agent",
      confidence: "heuristic",
      signals: [...signals, "honeypot_hit"],
      evidence: { path: req.path, ua },
    };
  }
  const uaLower = ua.toLowerCase();
  const automationToken = AUTOMATION_UA_TOKENS.find((t) => uaLower.includes(t));
  if (automationToken || ua === "") {
    return {
      class: "suspected_agent",
      confidence: "heuristic",
      signals: [...signals, ua === "" ? "empty_ua" : "automation_ua"],
      evidence: { ua, token: automationToken },
    };
  }
  if (missingBrowserHeaders(req)) {
    return {
      class: "suspected_agent",
      confidence: "heuristic",
      signals: [...signals, "browser_ua_without_browser_headers"],
      evidence: { ua },
    };
  }

  // 4. Default.
  return { class: "human", confidence: "default", signals, evidence: {} };
}
