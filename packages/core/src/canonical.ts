/**
 * RFC-0002 canonical JSON serialization.
 *
 * Deterministic serialization for cryptographic operations: object keys sorted
 * alphabetically (recursive), arrays keep their order, no whitespace. The same
 * logical value always produces the same bytes, so hashes and signatures agree
 * across runtimes.
 *
 * This is an independent, MIT-licensed reimplementation of the algorithm used
 * by Vorion BASIS (`@vorionsys/security` `canonicalize`) and MUST produce
 * byte-identical output — the receipt chain here and any BASIS verifier have to
 * agree. If you change this, re-check it against the BASIS canonicalizer.
 */

function sortKeys(value: unknown): unknown {
  if (typeof value === "number" && !Number.isFinite(value)) {
    // JSON.stringify would silently turn NaN/Infinity into null — a value
    // change under a signature. Refuse instead (fail closed).
    throw new TypeError(`cannot canonicalize non-finite number ${value}`);
  }
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortKeys);
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    out[key] = sortKeys((value as Record<string, unknown>)[key]);
  }
  return out;
}

/** Deterministic JSON string with recursively sorted keys. */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

/** UTF-8 bytes of the canonical JSON — the input to every hash/signature here. */
export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
