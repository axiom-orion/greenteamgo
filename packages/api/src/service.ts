/**
 * Request lifecycle service — the heart of the inbox API.
 *
 *   create  → store a pending request, page the human (Notifier)
 *   get     → poll; a request past its deadline lazily flips to `expired`
 *             (FAIL CLOSED — no decision by the deadline is a deny)
 *   decide  → the human's verdict becomes a signed, hash-linked receipt
 *             (via @vorionsys/greenteamgo-core), chained per workspace
 *
 * Clock and id generator are injected so lifecycle/expiry is deterministic in
 * tests and this module carries no ambient time/uuid coupling.
 */
import { randomUUID } from "node:crypto";

import { GENESIS_PREV_HASH, seal, type Receipt, type Risk } from "@vorionsys/greenteamgo-core";

import {
  type ApiKeyRecord,
  type Mode,
  type RequestRecord,
  type Store,
} from "./store.js";

export interface Notifier {
  /** Page the human. Real impl = FCM; test/dev impl records or logs. */
  notify(request: RequestRecord): void | Promise<void>;
}

export class NoopNotifier implements Notifier {
  notify(): void {
    /* no-op: wire FCM here */
  }
}

export interface CreateInput {
  action_type: string;
  summary: string;
  detail?: string;
  payload?: string;
  payload_sha256?: string;
  risk: Risk;
  timeout_s: number;
  mode: Mode;
  nonce?: string;
  idempotency_key?: string;
}

export class ScopeError extends Error {}
export class NotFoundError extends Error {}
export class ConflictError extends Error {}
export class ValidationError extends Error {}

const RISKS: Risk[] = ["low", "medium", "high", "critical"];
const MAX_PAYLOAD_BYTES = 256 * 1024;

export interface ServiceOptions {
  store: Store;
  notifier?: Notifier;
  now?: () => number; // ms epoch
  newId?: () => string;
}

export class RequestService {
  private store: Store;
  private notifier: Notifier;
  private now: () => number;
  private newId: () => string;

  constructor(opts: ServiceOptions) {
    this.store = opts.store;
    this.notifier = opts.notifier ?? new NoopNotifier();
    this.now = opts.now ?? (() => Date.now());
    this.newId = opts.newId ?? (() => cryptoRandomId());
  }

  private require(key: ApiKeyRecord, scope: string): void {
    if (!key.scopes.includes(scope)) {
      throw new ScopeError(`api key lacks required scope "${scope}"`);
    }
  }

  async create(key: ApiKeyRecord, input: CreateInput): Promise<RequestRecord> {
    this.require(key, "green:create");
    if (!RISKS.includes(input.risk)) throw new ValidationError(`invalid risk "${input.risk}"`);
    if (!(input.timeout_s > 0)) throw new ValidationError("timeout_s must be > 0");
    if (input.payload && Buffer.byteLength(input.payload, "utf8") > MAX_PAYLOAD_BYTES) {
      throw new ValidationError(`payload exceeds ${MAX_PAYLOAD_BYTES} bytes`);
    }

    // Idempotency: replay returns the original request, never a duplicate.
    if (input.idempotency_key) {
      const existing = this.store.findByIdempotencyKey(key.workspace_id, input.idempotency_key);
      if (existing) return this.materialize(existing);
    }

    const nowMs = this.now();
    const rec: RequestRecord = {
      request_id: this.newId(),
      workspace_id: key.workspace_id,
      action_type: input.action_type,
      summary: input.summary,
      detail: input.detail,
      payload: input.payload,
      payload_sha256: input.payload_sha256,
      risk: input.risk,
      timeout_s: input.timeout_s,
      mode: input.mode,
      nonce: input.nonce ?? cryptoRandomId(),
      status: "pending",
      created_at: new Date(nowMs).toISOString(),
      expires_at: new Date(nowMs + input.timeout_s * 1000).toISOString(),
      idempotency_key: input.idempotency_key,
    };
    this.store.insertRequest(rec);
    await this.notifier.notify(rec);
    return rec;
  }

  get(key: ApiKeyRecord, requestId: string): RequestRecord {
    this.require(key, "green:read");
    const rec = this.store.getRequest(key.workspace_id, requestId);
    if (!rec) throw new NotFoundError(`request ${requestId} not found`);
    return this.materialize(rec);
  }

  listPending(key: ApiKeyRecord): RequestRecord[] {
    this.require(key, "green:read");
    return this.store
      .listByStatus(key.workspace_id, "pending")
      .map((r) => this.materialize(r));
  }

  /** The human's verdict. Produces the signed, chained receipt. */
  async decide(
    key: ApiKeyRecord,
    requestId: string,
    decision: "approved" | "denied",
    opts: { reason?: string; deciderId?: string; deciderMethod?: "app" | "biometric" } = {},
  ): Promise<RequestRecord> {
    this.require(key, "green:decide");
    let rec = this.store.getRequest(key.workspace_id, requestId);
    if (!rec) throw new NotFoundError(`request ${requestId} not found`);
    rec = this.materialize(rec); // expire first if past deadline
    if (rec.status !== "pending") {
      throw new ConflictError(`request is already ${rec.status}; decisions are final`);
    }

    const signing = this.store.getSigningKey(key.workspace_id);
    if (!signing) throw new Error(`no signing key for workspace ${key.workspace_id}`);

    const decidedAt = new Date(this.now()).toISOString();
    const receipt: Receipt = seal(
      {
        request_id: rec.request_id,
        workspace_id: rec.workspace_id,
        actor: { type: "agent_key", id: key.workspace_id },
        action_type: rec.action_type,
        verdict: decision === "approved" ? "approve" : "deny",
        status: decision,
        risk: rec.risk,
        payload_sha256: rec.payload_sha256,
        decider: { method: opts.deciderMethod ?? "app", id: opts.deciderId },
        reason: opts.reason,
        created_at: rec.created_at,
        decided_at: decidedAt,
      },
      {
        keyId: signing.key_id,
        privateKeyPem: signing.privateKeyPem,
        prevHash: this.store.getChainHead(key.workspace_id) ?? GENESIS_PREV_HASH,
      },
    );

    const updated: RequestRecord = {
      ...rec,
      status: decision,
      reason: opts.reason,
      decided_at: decidedAt,
      receipt,
    };
    this.store.updateRequest(updated);
    this.store.setChainHead(key.workspace_id, receipt.receipt_hash);
    return updated;
  }

  /** Apply lazy, fail-closed expiry: a pending request past its deadline is
   * treated as a deny. Returns the (possibly updated) record. */
  private materialize(rec: RequestRecord): RequestRecord {
    if (rec.status === "pending" && this.now() > Date.parse(rec.expires_at)) {
      const expired: RequestRecord = {
        ...rec,
        status: "expired",
        reason: "no decision before deadline (fail closed: treat as deny)",
      };
      this.store.updateRequest(expired);
      return expired;
    }
    return rec;
  }
}

function cryptoRandomId(): string {
  return "req_" + randomUUID();
}
