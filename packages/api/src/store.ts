/**
 * Storage + identity for the GreenTeamGo inbox API.
 *
 * The service talks only to the `Store` interface, so the in-memory
 * implementation used in tests and local dev swaps 1:1 for a Postgres adapter
 * (Vercel/Neon) later — no service changes. This mirrors the dual-backend
 * pattern used across the codebase (real vs mock).
 *
 * ATOMICITY CONTRACT: the in-memory store is synchronous, so appendReceipt
 * and request status transitions are race-free by construction. A persistent
 * adapter MUST keep them atomic — appendReceipt is a compare-and-swap on the
 * chain head plus an insert in one transaction, and updateRequest of a
 * decision must fail if the row is no longer pending — or concurrent
 * decisions fork the chain / double-decide a request.
 */
import type { Actor, Receipt, Risk } from "@vorionsys/greenteamgo-core";
import { hashApiKey } from "@vorionsys/greenteamgo-identity";

export type RequestStatus = "pending" | "approved" | "denied" | "expired";
export type Mode = "block" | "async";

/** Seed/registration input: a raw api key + what it may do (product-prefixed
 * scopes). The raw key is hashed on the way in; it is never retained. */
export interface ApiKeySeed {
  api_key: string;
  workspace_id: string;
  scopes: string[]; // e.g. ["green:create", "green:read", "green:decide"]
}

/** What `resolveApiKey` returns — the grant, never the secret. */
export interface ResolvedKey {
  key_id: string;
  workspace_id: string;
  scopes: string[];
}

export interface SigningKey {
  key_id: string;
  publicKeyPem: string;
  privateKeyPem: string;
}

export interface RequestRecord {
  request_id: string;
  workspace_id: string;
  /** who asked: the authenticated agent key, or (for Red escalations) the
   * observed foreign agent the request is about */
  actor: Actor;
  action_type: string;
  summary: string;
  detail?: string;
  payload?: string;
  payload_sha256?: string;
  risk: Risk;
  timeout_s: number;
  mode: Mode;
  nonce: string;
  status: RequestStatus;
  reason?: string;
  receipt?: Receipt;
  created_at: string; // ISO
  expires_at: string; // ISO
  decided_at?: string; // ISO
  idempotency_key?: string;
  /** content hash for idempotency-collision detection */
  fingerprint?: string;
  /** last notification delivery failure, if any (cleared on success) */
  notify_error?: string;
  // set when a policy evaluated this request (auto-decided or gated)
  policy_id?: string;
  policy_version?: number;
  policy_effect?: "allow" | "deny" | "gate" | "challenge";
  matched_rule_id?: string;
}

/** What the agent-facing endpoints return (never leaks internal-only columns). */
export interface RequestState {
  request_id: string;
  status: RequestStatus;
  reason?: string;
  receipt?: Receipt;
  summary?: string;
  risk?: Risk;
  created_at?: string;
  expires_at?: string;
}

export function toState(r: RequestRecord): RequestState {
  return {
    request_id: r.request_id,
    status: r.status,
    reason: r.reason,
    receipt: r.receipt,
    summary: r.summary,
    risk: r.risk,
    created_at: r.created_at,
    expires_at: r.expires_at,
  };
}

export interface Store {
  resolveApiKey(apiKey: string): ResolvedKey | undefined;
  getSigningKey(workspaceId: string): SigningKey | undefined;

  insertRequest(rec: RequestRecord): void;
  getRequest(workspaceId: string, requestId: string): RequestRecord | undefined;
  findByIdempotencyKey(workspaceId: string, key: string): RequestRecord | undefined;
  listByStatus(workspaceId: string, status: RequestStatus): RequestRecord[];
  updateRequest(rec: RequestRecord): void;

  /** receipt_hash of the workspace's latest receipt, for chain linking. */
  getChainHead(workspaceId: string): string | undefined;
  /** Append a sealed receipt: advance the chain head AND record the receipt
   * in the workspace's ordered log, atomically (see contract above). */
  appendReceipt(workspaceId: string, receipt: Receipt): void;
  /** The workspace's receipts in chain order — the verify CLI's input. */
  listReceipts(workspaceId: string): Receipt[];
}

/** Extract the public key_id handle from a `gtg_<key_id>_<secret>` raw key;
 * non-gtg keys (tests, custom seeds) fall back to a hash-derived handle so a
 * key_id always exists and never contains secret material. */
export function keyIdOf(rawKey: string): string {
  const m = rawKey.match(/^gtg_(.+)_[A-Za-z0-9_-]+$/);
  return m ? m[1] : "k_" + hashApiKey(rawKey).slice(0, 12);
}

/** In-memory Store — deterministic; the test/dev backend. API keys are stored
 * as SHA-256 hashes (never plaintext) and resolved by hashing the presented key. */
export class InMemoryStore implements Store {
  private keysByHash = new Map<string, ResolvedKey>();
  private signingKeys = new Map<string, SigningKey>();
  private requests = new Map<string, RequestRecord>(); // key: `${ws}:${id}`
  private chainHeads = new Map<string, string>();
  private receiptLogs = new Map<string, Receipt[]>();

  seedWorkspace(workspaceId: string, apiKey: ApiKeySeed, signing: SigningKey): void {
    this.addApiKey(apiKey);
    this.signingKeys.set(workspaceId, signing);
  }

  addApiKey(apiKey: ApiKeySeed): void {
    // Hash on the way in; the raw key is never retained.
    this.keysByHash.set(hashApiKey(apiKey.api_key), {
      key_id: keyIdOf(apiKey.api_key),
      workspace_id: apiKey.workspace_id,
      scopes: apiKey.scopes,
    });
  }

  resolveApiKey(apiKey: string): ResolvedKey | undefined {
    return this.keysByHash.get(hashApiKey(apiKey));
  }
  getSigningKey(workspaceId: string): SigningKey | undefined {
    return this.signingKeys.get(workspaceId);
  }
  insertRequest(rec: RequestRecord): void {
    this.requests.set(`${rec.workspace_id}:${rec.request_id}`, rec);
  }
  getRequest(workspaceId: string, requestId: string): RequestRecord | undefined {
    return this.requests.get(`${workspaceId}:${requestId}`);
  }
  findByIdempotencyKey(workspaceId: string, key: string): RequestRecord | undefined {
    for (const r of this.requests.values()) {
      if (r.workspace_id === workspaceId && r.idempotency_key === key) return r;
    }
    return undefined;
  }
  listByStatus(workspaceId: string, status: RequestStatus): RequestRecord[] {
    return [...this.requests.values()].filter(
      (r) => r.workspace_id === workspaceId && r.status === status,
    );
  }
  updateRequest(rec: RequestRecord): void {
    this.requests.set(`${rec.workspace_id}:${rec.request_id}`, rec);
  }
  getChainHead(workspaceId: string): string | undefined {
    return this.chainHeads.get(workspaceId);
  }
  appendReceipt(workspaceId: string, receipt: Receipt): void {
    this.chainHeads.set(workspaceId, receipt.receipt_hash);
    const log = this.receiptLogs.get(workspaceId) ?? [];
    log.push(receipt);
    this.receiptLogs.set(workspaceId, log);
  }
  listReceipts(workspaceId: string): Receipt[] {
    return [...(this.receiptLogs.get(workspaceId) ?? [])];
  }
}
