# @vorionsys/greenteamgo-identity

Agent **identity** — API key minting, hashed storage, and scope resolution.

API keys are high-entropy secrets, so the store keeps only their **SHA-256 hash** and resolves a presented key by hashing it — plaintext keys are never persisted or compared byte-by-byte. A raw key is `gtg_<key_id>_<secret>`: `key_id` is a public handle (display, rotation, logs); the secret makes it valid.

```ts
import { mintApiKey, InMemoryIdentityStore } from "@vorionsys/greenteamgo-identity";

const store = new InMemoryIdentityStore();
const rawKey = store.mint({ workspaceId: "ws1", scopes: ["green:create", "green:read"] });
// show rawKey to the user ONCE; only its hash is stored

store.resolve(rawKey);
// { key_id: "k_…", workspace_id: "ws1", scopes: ["green:create", "green:read"] }
store.resolve("gtg_wrong");           // undefined
```

`mintApiKey()` returns `{ rawKey, record }` where `record` holds `key_hash` and **not** the secret — verified in tests. `hashApiKey()` and `hashEquals()` (constant-time) are exported for adapters that store keys in their own database.

Used by `@vorionsys/greenteamgo-api`: its store hashes keys on registration and resolves by hash, so no inbound raw key is ever retained.

## License

MIT © Vorion
