/**
 * Request lifecycle service — the heart of the inbox API.
 *
 *   create  → store a pending request, page the human (Notifier)
 *   get     → poll; a request past its deadline lazily flips to `expired`
 *             (FAIL CLOSED — no decision by the deadline is a deny) and the
 *             expiry itself is sealed into the chain like any other decision
 *   decide  → the human's verdict becomes a signed, hash-linked receipt
 *             (via @vorionsys/greenteamgo-core), chained per workspace
 *
 * Clock and id generator are injected so lifecycle/expiry is deterministic in
 * tests and this module carries no ambient time/uuid coupling.
 */
import { createHash, randomUUID } from "node:crypto";

import {
  canonicalize,
  seal,
  type Actor,
  type Receipt,
  type ReceiptStatus,
  type Risk,
  type Verdict,
} from "@vorionsys/greenteamgo-core";

import {
  type ResolvedKey,
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

/** Structural interface satisfied by @vorionsys/greenteamgo-policy's evaluate().
 * Kept structural so the API does not hard-depend on the policy package. */
export interface PolicyEvaluator {
  evaluate(event: {
    action_type: string;
    risk?: Risk;
    actor_type?: "agent_key" | "observed";
    tags?: string[];
  }): {
    effect: "allow" | "deny" | "gate" | "challenge";
    risk: Risk;
    policy_id: string;
    policy_version: number;
    matched_rule_id?: string;
  };
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
  /** who is asking. Defaults to the authenticated agent key; RedTeamGo
   * escalations pass the OBSERVED foreign agent so the human decision's
   * receipt attributes the right subject. */
  actor?: Actor;
}

export class ScopeError extends Error {}
export class NotFoundError extends Error {}
export class ConflictError extends Error {}
export class ValidationError extends Error {}

const RISKS: Risk[] = ["low", "medium", "high", "critical"];
const MAX_PAYLOAD_BYTES = 256 * 1024;
const SHA256_HEX = /^[0-9a-f]{64}$/;

export interface ServiceOptions {
  store: Store;
  notifier?: Notifier;
  policy?: PolicyEvaluator;
  now?: () => number; // ms epoch
  newId?: () => string;
}

export class RequestService {
  private store: Store;
  private notifier: Notifier;
  private policy?: PolicyEvaluator;
  private now: () => number;
  private newId: () => string;

  constructor(opts: ServiceOptions) {
    this.store = opts.store;
    this.notifier = opts.notifier ?? new NoopNotifier();
    this.policy = opts.policy;
    this.now = opts.now ?? (() => Date.now());
    this.newId = opts.newId ?? (() => cryptoRandomId());
  }

  private require(key: ResolvedKey, scope: string): void {
    if (!key.scopes.includes(scope)) {
      throw new ScopeError(`api key lacks required scope "${scope}"`);
    }
  }

  async create(key: ResolvedKey, input: CreateInput): Promise<RequestRecord> {
    this.require(key, "green:create");
    if (!RISKS.includes(input.risk)) throw new ValidationError(`invalid risk "${input.risk}"`);
    if (!(input.timeout_s > 0)) throw new ValidationError("timeout_s must be > 0");
    if (input.payload && Buffer.byteLength(input.payload, "utf8") > MAX_PAYLOAD_BYTES) {
      throw new ValidationError(`payload exceeds ${MAX_PAYLOAD_BYTES} bytes`);
    }

    // The receipt must actually commit to the payload: compute the hash
    // server-side when the payload is uploaded, and refuse a client hash that
    // does not match the bytes. Hash-only mode (payload never uploaded) sends
    // just payload_sha256, which must at least look like a SHA-256.
    let payloadSha256 = input.payload_sha256;
    if (input.payload !== undefined) {
      const actual = sha256Hex(input.payload);
      if (payloadSha256 !== undefined && payloadSha256 !== actual) {
        throw new ValidationError("payload_sha256 does not match the uploaded payload");
      }
      payloadSha256 = actual;
    } else if (payloadSha256 !== undefined && !SHA256_HEX.test(payloadSha256)) {
      throw new ValidationError("payload_sha256 must be 64 lowercase hex chars");
    }

    const actor: Actor = input.actor ?? { type: "agent_key", id: key.key_id };
    if (actor.type !== "agent_key" && actor.type !== "observed") {
      throw new ValidationError(`invalid actor.type "${(actor as Actor).type}"`);
    }

    // Idempotency: replay returns the original request, never a duplicate —
    // but only for the SAME content. A colliding key with different content
    // must conflict, or the caller reads another action's decision as its own.
    const fingerprint = requestFingerprint(input, actor, payloadSha256);
    if (input.idempotency_key) {
      const existing = this.store.findByIdempotencyKey(key.workspace_id, input.idempotency_key);
      if (existing) {
        if (existing.fingerprint !== fingerprint) {
          throw new ConflictError(
            "idempotency key was already used for a different request (fingerprint mismatch)",
          );
        }
        const replayed = this.materialize(existing);
        // The original create may have failed to page the human; a retry is
        // the natural moment to try delivery again.
        if (replayed.status === "pending" && replayed.notify_error) {
          await this.tryNotify(replayed);
        }
        return replayed;
      }
    }

    const nowMs = this.now();
    const rec: RequestRecord = {
      request_id: this.newId(),
      workspace_id: key.workspace_id,
      actor,
      action_type: input.action_type,
      summary: input.summary,
      detail: input.detail,
      payload: input.payload,
      payload_sha256: payloadSha256,
      risk: input.risk,
      timeout_s: input.timeout_s,
      mode: input.mode,
      nonce: input.nonce ?? cryptoRandomId(),
      status: "pending",
      created_at: new Date(nowMs).toISOString(),
      expires_at: new Date(nowMs + input.timeout_s * 1000).toISOString(),
      idempotency_key: input.idempotency_key,
      fingerprint,
    };

    // Policy pre-decision: auto-allow/deny produce a receipt with no human;
    // gate/challenge fall through to paging (Green pages for both — the
    // distinction is recorded in policy_effect and matters to Red, whose
    // middleware serves challenges itself). Risk may be reclassified.
    if (this.policy) {
      const d = this.policy.evaluate({
        action_type: input.action_type,
        risk: input.risk,
        actor_type: actor.type,
      });
      rec.risk = d.risk;
      rec.policy_id = d.policy_id;
      rec.policy_version = d.policy_version;
      rec.policy_effect = d.effect;
      rec.matched_rule_id = d.matched_rule_id;
      if (d.effect === "allow" || d.effect === "deny") {
        const decidedAt = new Date(nowMs).toISOString();
        const status = d.effect === "allow" ? "approved" : "denied";
        rec.receipt = this.sealFor(
          rec,
          d.effect === "allow" ? "approve" : "deny",
          status,
          { method: "policy", id: d.policy_id },
          `auto-decided by policy ${d.policy_id} v${d.policy_version}`,
          decidedAt,
        );
        rec.status = status;
        rec.decided_at = decidedAt;
        rec.reason = rec.receipt.reason;
        this.store.insertRequest(rec);
        return rec; // no human paged
      }
    }

    this.store.insertRequest(rec);
    // Delivery failure must not fail the create: the request exists, block
    // mode still fail-closes on timeout, and the app can always see it via
    // list_pending. Record the failure so a retry can re-page.
    await this.tryNotify(rec);
    return rec;
  }

  private async tryNotify(rec: RequestRecord): Promise<void> {
    try {
      await this.notifier.notify(rec);
      if (rec.notify_error) {
        rec.notify_error = undefined;
        this.store.updateRequest(rec);
      }
    } catch (err) {
      rec.notify_error = (err as Error).message;
      this.store.updateRequest(rec);
    }
  }

  /** Seal a decision into a chained receipt and advance the workspace chain.
   * The status is passed through EXACTLY — never coerced. A receipt that says
   * "approved" when the outcome was anything else is the one lie this system
   * exists to make impossible. */
  private sealFor(
    rec: RequestRecord,
    verdict: Verdict,
    status: ReceiptStatus,
    decider: { method: "app" | "biometric" | "policy" | "auto"; id?: string; device_attestation?: string },
    reason: string | undefined,
    decidedAt: string,
  ): Receipt {
    const signing = this.store.getSigningKey(rec.workspace_id);
    if (!signing) throw new Error(`no signing key for workspace ${rec.workspace_id}`);
    const receipt = seal(
      {
        request_id: rec.request_id,
        workspace_id: rec.workspace_id,
        actor: rec.actor,
        action_type: rec.action_type,
        verdict,
        status,
        risk: rec.risk,
        payload_sha256: rec.payload_sha256,
        policy_id: rec.policy_id,
        policy_version: rec.policy_version,
        decider,
        reason,
        created_at: rec.created_at,
        decided_at: decidedAt,
      },
      {
        keyId: signing.key_id,
        privateKeyPem: signing.privateKeyPem,
        prevHash: this.store.getChainHead(rec.workspace_id),
      },
    );
    this.store.appendReceipt(rec.workspace_id, receipt);
    return receipt;
  }

  get(key: ResolvedKey, requestId: string): RequestRecord {
    this.require(key, "green:read");
    const rec = this.store.getRequest(key.workspace_id, requestId);
    if (!rec) throw new NotFoundError(`request ${requestId} not found`);
    return this.materialize(rec);
  }

  listPending(key: ResolvedKey): RequestRecord[] {
    this.require(key, "green:read");
    return this.store
      .listByStatus(key.workspace_id, "pending")
      .map((r) => this.materialize(r))
      // materialize may just have expired some — an inbox that lists dead
      // requests as actionable gets the human a 409, so filter after.
      .filter((r) => r.status === "pending");
  }

  /** The workspace's receipt chain, in chain order — what the verify CLI eats. */
  listReceipts(key: ResolvedKey): Receipt[] {
    this.require(key, "green:read");
    return this.store.listReceipts(key.workspace_id);
  }

  /** The workspace's signing PUBLIC key, for independent verification. */
  publicKey(key: ResolvedKey): { key_id: string; publicKeyPem: string } {
    this.require(key, "green:read");
    const signing = this.store.getSigningKey(key.workspace_id);
    if (!signing) throw new NotFoundError(`no signing key for workspace ${key.workspace_id}`);
    return { key_id: signing.key_id, publicKeyPem: signing.publicKeyPem };
  }

  /** The human's verdict. Produces the signed, chained receipt. */
  async decide(
    key: ResolvedKey,
    requestId: string,
    decision: "approved" | "denied",
    opts: { reason?: string; deciderId?: string; deciderMethod?: "app" | "biometric" } = {},
  ): Promise<RequestRecord> {
    this.require(key, "green:decide");
    // decider.method "policy"/"auto" mean "no human involved" — only the
    // server's policy path may claim them. Enforced here as well as at the
    // HTTP layer so no future transport can forge a machine verdict.
    const method = opts.deciderMethod ?? "app";
    if (method !== "app" && method !== "biometric") {
      throw new ValidationError(`decider method must be "app" or "biometric", got "${method}"`);
    }
    let rec = this.store.getRequest(key.workspace_id, requestId);
    if (!rec) throw new NotFoundError(`request ${requestId} not found`);
    rec = this.materialize(rec); // expire first if past deadline
    if (rec.status !== "pending") {
      throw new ConflictError(`request is already ${rec.status}; decisions are final`);
    }

    const decidedAt = new Date(this.now()).toISOString();
    const receipt = this.sealFor(
      rec,
      decision === "approved" ? "approve" : "deny",
      decision,
      { method, id: opts.deciderId },
      opts.reason,
      decidedAt,
    );

    const updated: RequestRecord = {
      ...rec,
      status: decision,
      reason: opts.reason,
      decided_at: decidedAt,
      receipt,
    };
    this.store.updateRequest(updated);
    return updated;
  }

  /** Apply lazy, fail-closed expiry: a pending request past its deadline is
   * treated as a deny — and sealed into the chain like every other decision,
   * because unanswered requests are exactly the events the logbook is for. */
  private materialize(rec: RequestRecord): RequestRecord {
    if (rec.status === "pending" && this.now() > Date.parse(rec.expires_at)) {
      const reason = "no decision before deadline (fail closed: treat as deny)";
      const receipt = this.sealFor(
        rec,
        "deny",
        "expired",
        { method: "auto", id: "timeout" },
        reason,
        rec.expires_at, // decided the moment the deadline lapsed
      );
      const expired: RequestRecord = {
        ...rec,
        status: "expired",
        reason,
        decided_at: rec.expires_at,
        receipt,
      };
      this.store.updateRequest(expired);
      return expired;
    }
    return rec;
  }
}

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/** Content fingerprint for idempotency-collision detection (nonce excluded —
 * clients regenerate it per attempt). */
function requestFingerprint(input: CreateInput, actor: Actor, payloadSha256?: string): string {
  return sha256Hex(
    canonicalize({
      action_type: input.action_type,
      summary: input.summary,
      detail: input.detail,
      payload: input.payload,
      payload_sha256: payloadSha256,
      risk: input.risk,
      timeout_s: input.timeout_s,
      mode: input.mode,
      actor,
    }),
  );
}

function cryptoRandomId(): string {
  return "req_" + randomUUID();
}
