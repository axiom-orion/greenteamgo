import { describe, expect, it } from "vitest";

import {
  InMemoryIdentityStore,
  hashApiKey,
  hashEquals,
  mintApiKey,
} from "../src/identity.js";

describe("api key hashing", () => {
  it("hashes deterministically and differently per key", () => {
    expect(hashApiKey("gtg_k_1_abc")).toBe(hashApiKey("gtg_k_1_abc"));
    expect(hashApiKey("gtg_k_1_abc")).not.toBe(hashApiKey("gtg_k_1_abd"));
    expect(hashApiKey("x")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("hashEquals is true for equal hashes, false otherwise", () => {
    const h = hashApiKey("secret");
    expect(hashEquals(h, hashApiKey("secret"))).toBe(true);
    expect(hashEquals(h, hashApiKey("other"))).toBe(false);
  });
});

describe("mintApiKey", () => {
  it("returns a raw key and a record that stores only the hash", () => {
    const { rawKey, record } = mintApiKey({ workspaceId: "ws1", scopes: ["green:create"] });
    expect(rawKey).toMatch(/^gtg_.+_.+/);
    expect(record.workspace_id).toBe("ws1");
    expect(record.scopes).toEqual(["green:create"]);
    expect(record.key_hash).toBe(hashApiKey(rawKey));
    // the record must NOT contain the raw secret
    expect(JSON.stringify(record)).not.toContain(rawKey);
  });

  it("mints unique keys", () => {
    const a = mintApiKey({ workspaceId: "ws1", scopes: [] });
    const b = mintApiKey({ workspaceId: "ws1", scopes: [] });
    expect(a.rawKey).not.toBe(b.rawKey);
    expect(a.record.key_id).not.toBe(b.record.key_id);
  });
});

describe("InMemoryIdentityStore", () => {
  it("resolves a registered raw key to its identity", () => {
    const store = new InMemoryIdentityStore();
    const raw = store.mint({ workspaceId: "ws1", scopes: ["green:create", "green:read"] });
    const id = store.resolve(raw);
    expect(id?.workspace_id).toBe("ws1");
    expect(id?.scopes).toEqual(["green:create", "green:read"]);
    expect(id?.scopes).not.toContain("green:decide");
  });

  it("returns undefined for an unknown or tampered key", () => {
    const store = new InMemoryIdentityStore();
    const raw = store.mint({ workspaceId: "ws1", scopes: ["green:create"] });
    expect(store.resolve("gtg_nope_nope")).toBeUndefined();
    expect(store.resolve(raw + "x")).toBeUndefined(); // one char off → different hash
    expect(store.resolve(raw)?.scopes).toEqual(["green:create"]);
  });
});
