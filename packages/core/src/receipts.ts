/**
 * Signed, hash-linked approval receipts — GreenTeamGo's Verdict Core.
 *
 * Every decision (approve / deny / gate / challenge) becomes a receipt that is:
 *   - canonically serialized (RFC-0002, see ./canonical),
 *   - Ed25519-signed by the deciding key,
 *   - hash-linked to the previous receipt (tamper-evident chain).
 *
 * The envelope is deliberately wide enough for BOTH GreenTeamGo (outbound,
 * cooperative — "may my agent do this?") and RedTeamGo (inbound, adversarial —
 * "should this foreign agent get in?") per the suite W1 spec deltas, so Red
 * never forces a format v2:
 *   - `actor` is an object ({ type: "agent_key" | "observed", ... }), not a
 *     bare key id — Red's subjects are observed, not registered.
 *   - `verdict` reserves the full enum approve|deny|gate|challenge.
 *   - `status` reserves blocked|challenged alongside the Green statuses.
 *   - `decider.method` reserves policy|auto (machine verdicts) beside
 *     app|biometric, and an optional `device_attestation` (absent = server-signed).
 *   - `policy_id` references a versioned policy row.
 *
 * v1 claim is exactly "signed, hash-linked receipts" — device-bound
 * (non-repudiation) signing is a later append via `decider.device_attestation`,
 * reserved here so it is not a breaking migration.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

import { canonicalBytes } from "./canonical.js";

export type Verdict = "approve" | "deny" | "gate" | "challenge";
export type ReceiptStatus =
  | "approved"
  | "denied"
  | "expired"
  | "blocked"
  | "challenged";
export type Risk = "low" | "medium" | "high" | "critical";
export type ActorType = "agent_key" | "observed";
export type DeciderMethod = "app" | "biometric" | "policy" | "auto";

/** Genesis link for the first receipt in a workspace chain. */
export const GENESIS_PREV_HASH = "0".repeat(64);

export interface Actor {
  type: ActorType;
  /** registered key id (agent_key) or observed/claimed subject id */
  id?: string;
  /** Web Bot Auth / signed-agent evidence for observed actors (Red) */
  evidence?: Record<string, unknown>;
}

export interface Decider {
  method: DeciderMethod;
  /** user id (app/biometric) or policy id (policy/auto) that made the call */
  id?: string;
  /** reserved for v1.5 device-bound signing; absent = server-signed */
  device_attestation?: string;
}

export interface Signer {
  key_id: string;
  alg: "ed25519";
}

/** Caller-supplied fields. `seal()` adds prev_hash, signer, receipt_hash, sig. */
export interface ReceiptBody {
  request_id: string;
  workspace_id: string;
  actor: Actor;
  action_type: string;
  verdict: Verdict;
  status: ReceiptStatus;
  risk: Risk;
  /** SHA-256 of the (never-uploaded-in-hash-only-mode) payload */
  payload_sha256?: string;
  policy_id?: string;
  /** version of policy_id that produced this decision — the id stays stable
   * across edits, so a bare id cannot prove which rules were in force */
  policy_version?: number;
  decider: Decider;
  reason?: string;
  /** ISO-8601 request creation time */
  created_at: string;
  /** ISO-8601 decision time */
  decided_at: string;
}

/** The signed, chained receipt. */
export interface Receipt extends ReceiptBody {
  v: 1;
  /** receipt_hash of the previous receipt in the chain; GENESIS_PREV_HASH if first */
  prev_hash: string;
  signer: Signer;
  /** hex SHA-256 over the canonical serialization of everything above */
  receipt_hash: string;
  /** base64 Ed25519 signature over the same canonical bytes */
  sig: string;
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

/**
 * Where a workspace's chain lives. Green's inbox API and Red's edge
 * middleware append to the SAME per-workspace chain through this seam — one
 * logbook. The in-memory implementations are synchronous and race-free by
 * construction; a persistent implementation MUST make read-head → seal →
 * append atomic (compare-and-swap on the head), or two concurrent decisions
 * fork the chain.
 */
export interface ChainStore {
  /** receipt_hash of the latest receipt, for prev_hash linking. */
  getChainHead(workspaceId: string): string | undefined;
  /** Advance the head to this receipt AND record it in the ordered log. */
  appendReceipt(workspaceId: string, receipt: Receipt): void;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** The portion of a receipt that is hashed and signed (everything but the
 * derived receipt_hash and sig). Kept in one place so seal and verify agree. */
function signedContent(r: Omit<Receipt, "receipt_hash" | "sig">): Record<string, unknown> {
  return { ...r };
}

/** Generate an Ed25519 signing key pair for a workspace/decider. Field names
 * match the receipt envelope (`key_id`) so the result drops straight into a
 * store's SigningKey — a camelCase mismatch here once produced receipts whose
 * signer.key_id was silently dropped by canonicalization. */
export function generateSignerKeyPair(keyId: string): {
  key_id: string;
  publicKeyPem: string;
  privateKeyPem: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    key_id: keyId,
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }) as string,
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
  };
}

/**
 * Seal a decision into a signed, hash-linked receipt.
 *
 * @param body       the decision fields
 * @param opts.keyId, opts.privateKeyPem   the Ed25519 signer
 * @param opts.prevHash  receipt_hash of the previous receipt (omit for genesis)
 */
export function seal(
  body: ReceiptBody,
  opts: { keyId: string; privateKeyPem: string; prevHash?: string },
): Receipt {
  if (!opts.keyId) {
    throw new Error("seal: keyId is required — a receipt without signer.key_id is unverifiable");
  }
  const content: Omit<Receipt, "receipt_hash" | "sig"> = {
    v: 1,
    // JSON round-trip so the bytes we sign are EXACTLY the bytes a verifier
    // reconstructs from the wire form. Without this, values with toJSON
    // (Date) or non-plain-JSON shapes (Buffer/TypedArray, e.g. inside
    // actor.evidence) verify in memory but fail forever after transport.
    ...(JSON.parse(JSON.stringify(body)) as ReceiptBody),
    prev_hash: opts.prevHash ?? GENESIS_PREV_HASH,
    signer: { key_id: opts.keyId, alg: "ed25519" },
  };
  const bytes = canonicalBytes(signedContent(content));
  const receipt_hash = sha256Hex(bytes);
  const sig = cryptoSign(null, bytes, createPrivateKey(opts.privateKeyPem)).toString("base64");
  return { ...content, receipt_hash, sig };
}

/** Verify a single receipt's integrity and signature against a public key. */
export function verifyReceipt(receipt: Receipt, publicKeyPem: string): VerifyResult {
  const { receipt_hash, sig, ...content } = receipt;
  const bytes = canonicalBytes(signedContent(content as Omit<Receipt, "receipt_hash" | "sig">));
  if (sha256Hex(bytes) !== receipt_hash) {
    return { ok: false, reason: "receipt_hash mismatch — content was tampered" };
  }
  let sigOk = false;
  try {
    sigOk = cryptoVerify(null, bytes, createPublicKey(publicKeyPem), Buffer.from(sig, "base64"));
  } catch (err) {
    return { ok: false, reason: `signature check errored: ${(err as Error).message}` };
  }
  return sigOk ? { ok: true } : { ok: false, reason: "signature invalid for this key" };
}

/**
 * Verify a whole chain: each receipt's prev_hash must equal the previous
 * receipt's receipt_hash, and each signature must verify under the key resolved
 * for its signer. Fails closed on the first problem.
 *
 * @param resolveKey  maps a signer key_id to its public key PEM (undefined = unknown key)
 */
export function verifyChain(
  receipts: Receipt[],
  resolveKey: (keyId: string) => string | undefined,
): VerifyResult {
  let prev = GENESIS_PREV_HASH;
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    if (r.prev_hash !== prev) {
      return { ok: false, reason: `chain break at index ${i}: prev_hash does not link to the previous receipt` };
    }
    const pub = resolveKey(r.signer.key_id);
    if (!pub) {
      return { ok: false, reason: `index ${i}: unknown signer key_id "${r.signer.key_id}"` };
    }
    const v = verifyReceipt(r, pub);
    if (!v.ok) {
      return { ok: false, reason: `index ${i}: ${v.reason}` };
    }
    prev = r.receipt_hash;
  }
  return { ok: true };
}
