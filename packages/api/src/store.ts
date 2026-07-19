/**
 * Storage + identity for the GreenTeamGo inbox API.
 *
 * The service talks only to the `Store` interface, so the in-memory
 * implementation used in tests and local dev swaps 1:1 for a Postgres adapter
 * (Vercel/Neon) later — no service changes. This mirrors the dual-backend
 * pattern used across the codebase (real vs mock).
 */
import type { Receipt, Risk } from "@vorionsys/greenteamgo-core";
import { hashApiKey } from "@vorionsys/greenteamgo-identity";

export type RequestStatus = "pending" | "approved" | "denied" | "expired";
export type Mode = "block" | "async";

/** Seed/registration input: a raw api key + what it may do (product-prefixed scopes).
 * The raw key is hashed on the way in; it is never retained. */
export interface ApiKeyRecord {
  api_key: string;
  workspace_id: string;
  scopes: string[]; // e.g. ["green:create", "green:read", "green:decide"]
}

/** What `resolveApiKey` returns — the grant, never the secret. */
export interface ResolvedKey {
  key_id?: string;
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
  // set when a policy evaluated this request (auto-decided or gated)
  policy_id?: string;
  policy_version?: number;
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
  setChainHead(workspaceId: string, receiptHash: string): void;
}

/** In-memory Store — deterministic; the test/dev backend. API keys are stored
 * as SHA-256 hashes (never plaintext) and resolved by hashing the presented key. */
export class InMemoryStore implements Store {
  private keysByHash = new Map<string, ResolvedKey>();
  private signingKeys = new Map<string, SigningKey>();
  private requests = new Map<string, RequestRecord>(); // key: `${ws}:${id}`
  private chainHeads = new Map<string, string>();

  seedWorkspace(workspaceId: string, apiKey: ApiKeyRecord, signing: SigningKey): void {
    this.addApiKey(apiKey);
    this.signingKeys.set(workspaceId, signing);
  }

  addApiKey(apiKey: ApiKeyRecord): void {
    // Hash on the way in; the raw key is never retained.
    this.keysByHash.set(hashApiKey(apiKey.api_key), {
      key_id: apiKey.api_key.slice(0, 8),
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
  setChainHead(workspaceId: string, receiptHash: string): void {
    this.chainHeads.set(workspaceId, receiptHash);
  }
}
