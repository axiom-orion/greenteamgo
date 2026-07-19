/**
 * Identity module — agent API keys and scopes.
 *
 * API keys are high-entropy secrets, so we store only their SHA-256 hash and
 * resolve by hashing the presented key (never keep plaintext, never compare it
 * byte-by-byte). A raw key looks like `gtg_<key_id>_<secret>`: the `key_id`
 * prefix is a public handle (display, rotation, logs), the secret is what makes
 * it valid.
 *
 * (RedTeamGo's observed-actor identity — Web Bot Auth / signed-agent evidence —
 * layers on top later; this module is the registered-key half.)
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export type Scope = string; // e.g. "green:create", "green:decide", "red:report"

/** What a resolved key grants. Never carries the secret. */
export interface Identity {
  key_id: string;
  workspace_id: string;
  scopes: Scope[];
}

/** Stored form: identity + the key's hash (the only persisted secret material). */
export interface ApiKeyRecord extends Identity {
  key_hash: string;
}

/** SHA-256 hex of a raw key. */
export function hashApiKey(rawKey: string): string {
  return createHash("sha256").update(rawKey, "utf8").digest("hex");
}

/** Constant-time hex comparison (defense in depth; lookups are by hash). */
export function hashEquals(aHex: string, bHex: string): boolean {
  if (aHex.length !== bHex.length) return false;
  return timingSafeEqual(Buffer.from(aHex, "hex"), Buffer.from(bHex, "hex"));
}

export interface MintResult {
  /** Show this to the user exactly once — it is never recoverable after. */
  rawKey: string;
  record: ApiKeyRecord;
}

/** Mint a new API key. The raw key is returned once; only its hash is stored. */
export function mintApiKey(opts: { workspaceId: string; scopes: Scope[]; keyId?: string }): MintResult {
  const keyId = opts.keyId ?? "k_" + randomBytes(6).toString("hex");
  const secret = randomBytes(24).toString("base64url");
  const rawKey = `gtg_${keyId}_${secret}`;
  return {
    rawKey,
    record: {
      key_id: keyId,
      workspace_id: opts.workspaceId,
      scopes: [...opts.scopes],
      key_hash: hashApiKey(rawKey),
    },
  };
}

/** In-memory identity store: register key records, resolve a presented raw key. */
export class InMemoryIdentityStore {
  private byHash = new Map<string, ApiKeyRecord>();

  register(record: ApiKeyRecord): void {
    this.byHash.set(record.key_hash, record);
  }

  /** Mint + register in one step; returns the raw key (show once). */
  mint(opts: { workspaceId: string; scopes: Scope[]; keyId?: string }): string {
    const { rawKey, record } = mintApiKey(opts);
    this.register(record);
    return rawKey;
  }

  resolve(rawKey: string): Identity | undefined {
    const rec = this.byHash.get(hashApiKey(rawKey));
    if (!rec) return undefined;
    return { key_id: rec.key_id, workspace_id: rec.workspace_id, scopes: rec.scopes };
  }
}
