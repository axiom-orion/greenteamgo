# GreenCodex — run the demo

**Codex, governed.** Codex asks a human before doing anything risky; every
decision becomes a signed, hash-linked receipt.

```
Codex ──(request_approval, via greenteamgo MCP)──▶ inbox API
                                                      │
                          you approve/deny  ◀── web approval page ("the phone")
                                                      │
                                             signed receipt (Ed25519, chained)
```

## 1. Build

```
cd D:\voriongit\greenteamgo
npm install
npm run build --workspaces
```

## 2. Start the console (the inbox API + approval page)

```
npm -w @vorionsys/greenteamgo-console start
```
Open **http://localhost:4000/** — that's the approval inbox ("the phone").
It prints the agent key Codex uses.

## 3. Point Codex at greenteamgo

- Append `demo/codex-config.toml` to your `~/.codex/config.toml`.
- Put `demo/AGENTS.md` in the project folder you run Codex in (or `~/.codex/AGENTS.md`
  for all projects) — it tells Codex to call `request_approval` before risky actions.

## 4. Run Codex and ask for something risky

```
codex
```
Then, e.g.: *"Commit everything and force-push to main."*

Codex calls `request_approval` → the request appears at http://localhost:4000/
(with an optional GPT-written risk summary) → you **Approve** or **Deny**:
- **Approve** → Codex proceeds; a signed receipt is recorded.
- **Deny** (with a reason) → Codex stops and adapts. Fail-closed.

## 5. Verify the receipts

Every decision is in the workspace chain. Export and verify without trusting the server:
```
curl -s http://localhost:4000/v1/receipts -H "authorization: Bearer gtg_demo_agent_key" > receipts.json
curl -s http://localhost:4000/v1/keys     -H "authorization: Bearer gtg_demo_agent_key" > keys.json
npx greenteamgo-verify receipts.json keys.json
# OK: N receipt(s) verified — chain intact, signatures valid.
```

## What uses OpenAI here
- **Codex** is the coding agent (GPT under the hood) — the thing being governed.
- **GPT risk summary** (`OPENAI_API_KEY` in `.env`) writes the one-line "what this
  does and why it's risky" on each approval card. Fail-soft: if the key/credit is
  missing, the card falls back to the raw summary.
