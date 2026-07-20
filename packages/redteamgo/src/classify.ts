/**
 * Inbound classifier — "what is this thing and can it prove it."
 *
 * Four classes, checked in order of evidence strength (first match wins):
 *   1. verified_agent — Web Bot Auth signature that actually VERIFIES via the
 *      injected verifier (which must return the boolean `true`, nothing
 *      looser). Presence of signature headers alone proves nothing:
 *      unverifiable/invalid/expired signatures classify as suspected, never
 *      verified.
 *   2. declared_bot — User-Agent matches the known-agent registry. This is a
 *      CLAIM (the UA is attacker-controlled), so downstream trust decisions
 *      (see gate.ts identityOf) never grant a type-level standing allow to a
 *      declared bot that an ipVerifier has not positively confirmed.
 *   3. suspected_agent — honeypot path hit, automation-tool UA, a browser UA
 *      with none of the headers real browsers send, or any client that is not
 *      a browser and did not prove itself.
 *   4. human — the default, but only for requests that look like a browser.
 *      Getting this wrong in the strict direction (blocking a human) is worse
 *      than letting a clever bot through, so the browser test is generous; but
 *      a non-browser client with no browser signals is not a "human".
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
  const pat = pattern.toLowerCase();
  const p = path.toLowerCase();
  if (pat.endsWith("*")) return p.startsWith(pat.slice(0, -1));
  return pat === p;
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

function automationMarker(ua: string): string | undefined {
  const uaLower = ua.toLowerCase();
  return AUTOMATION_UA_TOKENS.find((t) => uaLower.includes(t));
}

/** True when the request carries evidence a real browser would send: a
 * Mozilla-token UA, or any of the fetch-metadata / language / client-hint
 * headers browsers attach. Absence of ALL of these means "not a browser". */
function looksLikeBrowser(req: InboundRequest): boolean {
  const ua = (req.headers["user-agent"] ?? "").toLowerCase();
  if (ua.includes("mozilla/")) return true;
  if (req.headers["accept-language"] !== undefined) return true;
  return Object.keys(req.headers).some((h) => h.startsWith("sec-fetch-") || h.startsWith("sec-ch-ua"));
}

/** Looks like a script wearing a browser UA: claims Mozilla but sends none of
 * the headers real browsers always send. Deliberately conservative — both
 * accept-language AND every sec-fetch-* header must be absent. */
function browserUaWithoutBrowserHeaders(req: InboundRequest): boolean {
  const ua = (req.headers["user-agent"] ?? "").toLowerCase();
  if (!ua.includes("mozilla/")) return false;
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
  if (wba && wba.valid) {
    if (opts.webBotAuthVerifier) {
      let ok: unknown = false;
      try {
        ok = await opts.webBotAuthVerifier(wba, req);
      } catch {
        ok = false; // verifier errors are non-proof, never trust-by-crash
      }
      // Strict: only the boolean `true` grants the highest trust class. A
      // truthy non-boolean (a key object, a JWK, a non-empty string) does not.
      if (ok === true) {
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
  } else if (wba) {
    // present but expired/malformed: still an agent declaration, not a human
    signals.push(`web_bot_auth_${wba.reason === "expired signature" ? "expired" : "malformed"}`);
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
      evidence: { signature_agent: wba.signatureAgent, keyid: wba.keyid, ua, wba_reason: wba.reason },
    };
  }

  // 3. Heuristics.
  if (opts.honeypots?.some((p) => pathMatches(p, req.path))) {
    return {
      class: "suspected_agent",
      confidence: "heuristic",
      signals: [...signals, "honeypot_hit"],
      evidence: { path: req.path, ua, ip: req.ip },
    };
  }
  const automationToken = automationMarker(ua);
  if (automationToken || ua === "") {
    return {
      class: "suspected_agent",
      confidence: "heuristic",
      signals: [...signals, ua === "" ? "empty_ua" : "automation_ua"],
      evidence: { ua, token: automationToken, ip: req.ip },
    };
  }
  if (browserUaWithoutBrowserHeaders(req)) {
    return {
      class: "suspected_agent",
      confidence: "heuristic",
      signals: [...signals, "browser_ua_without_browser_headers"],
      evidence: { ua, ip: req.ip },
    };
  }
  // A client that shows NO browser evidence at all (non-Mozilla UA, no
  // language, no fetch-metadata / client-hint headers) is some bespoke client,
  // not a human browser. Classify suspected so policy can target it; default
  // policy still lets it pass, so no human is ever blocked by this.
  if (!looksLikeBrowser(req)) {
    return {
      class: "suspected_agent",
      confidence: "heuristic",
      signals: [...signals, "no_browser_evidence"],
      evidence: { ua, ip: req.ip },
    };
  }

  // 4. Default.
  return { class: "human", confidence: "default", signals, evidence: {} };
}
