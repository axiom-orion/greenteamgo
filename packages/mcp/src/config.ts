import type { Risk } from "./client.js";

export interface Config {
  apiUrl: string;
  apiKey: string;
  defaultRisk: Risk;
  defaultBlockTimeoutS: number;
  defaultAsyncTimeoutS: number;
  /** initial poll interval; overridable for tests via GREENTEAMGO_POLL_MS */
  pollInitialMs: number;
}

const RISKS = ["low", "medium", "high", "critical"] as const;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const apiKey = env.GREENTEAMGO_API_KEY ?? env.COUNTERSIGN_API_KEY;
  if (!apiKey) {
    throw new Error(
      "GREENTEAMGO_API_KEY is required (workspace-scoped agent key from the GreenTeamGo app).",
    );
  }
  const apiUrl = (env.GREENTEAMGO_API_URL ?? "https://api.greenteamgo.app").replace(/\/+$/, "");
  const riskEnv = env.GREENTEAMGO_DEFAULT_RISK;
  const defaultRisk: Risk = (RISKS as readonly string[]).includes(riskEnv ?? "")
    ? (riskEnv as Risk)
    : "medium";
  return {
    apiUrl,
    apiKey,
    defaultRisk,
    defaultBlockTimeoutS: intOr(env.GREENTEAMGO_DEFAULT_TIMEOUT, 900),
    defaultAsyncTimeoutS: 86400,
    pollInitialMs: intOr(env.GREENTEAMGO_POLL_MS, 2000),
  };
}

function intOr(v: string | undefined, fallback: number): number {
  const n = v ? parseInt(v, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : fallback;
}
