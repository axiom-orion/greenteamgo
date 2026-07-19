# @vorionsys/greenteamgo-mcp

**A human approval gate for your AI agent.** When your agent wants to do something risky — push to main, run a destructive command, send money — it asks first. You get a push notification, review on your phone, and approve or deny. Every decision becomes a signed, hash-linked receipt.

**Unanswered requests fail closed.** No decision by the deadline means deny. Always.

Part of Newnansville Agent Teams, built on Vorion (BASIS / RFC-0002).

## Claude Code quickstart

```bash
claude mcp add greenteamgo -e GREENTEAMGO_API_KEY=<your-workspace-key> -- npx -y @vorionsys/greenteamgo-mcp
```

Then add this to your project's `CLAUDE.md`:

```markdown
## Approval gate
Before any destructive or high-impact operation — shell commands that modify state
outside the workspace, file writes to system or config paths, `git push`, package
publishing, payments, or sending messages — call the `request_approval` tool and
proceed ONLY if the result status is "approved". Treat "expired" and any error as
denied. If denied with a reason, adjust your approach using the reason instead of
retrying the same action.
```

That's it. Your agent now pages you before acting.

## Tools

### `request_approval`

```ts
request_approval({
  action_type: string,   // "shell_exec" | "file_write" | "git_push" | "payment" | custom
  summary: string,       // one line, shown in the push notification
  detail?: string,       // markdown, rendered in the app
  payload?: object|string, // args/diff; ≤256KB inline; NEVER include secrets
  risk?: "low"|"medium"|"high"|"critical",  // default "medium"
  timeout_s?: number,    // default 900 (block) / 86400 (async); expiry = deny
  mode?: "block"|"async" // default "block"
})
// block → { status: "approved"|"denied"|"expired", reason?, receipt }
// async → { status: "pending", request_id }
```

`denied` may carry a `reason` written by the human — feed it back into your plan. `expired` means nobody answered in time: **treat as denied.**

### `get_decision`

`get_decision({ request_id })` → `{ status, reason?, receipt? }` — poll an async request.

### `list_pending`

`list_pending()` → summaries of requests still waiting on a human.

## Configuration

| Env var | Required | Default | Notes |
|---|---|---|---|
| `GREENTEAMGO_API_KEY` | yes | — | workspace-scoped agent key |
| `GREENTEAMGO_API_URL` | no | `https://api.greenteamgo.app` | point at a self-hosted or stub API |
| `GREENTEAMGO_DEFAULT_RISK` | no | `medium` | |
| `GREENTEAMGO_DEFAULT_TIMEOUT` | no | `900` | seconds, block mode |

## Semantics that matter

- **Fail closed.** Expiry, network failure at the deadline, quota errors, any error at all → the answer is no. The agent instruction is always "proceed only on approved".
- **Payloads are hashed.** The SHA-256 of your payload is computed client-side and lands in the signed receipt; verify later that what was approved is what ran.
- **Approve costs attention, deny is cheap.** Approving happens in the app (biometric for high/critical). Deny works from the notification.
- **Receipts are portable.** Hash-linked, Ed25519-signed, RFC-0002 canonical serialization. Export the chain and verify it without trusting the server.

## Blocking behavior

Block mode polls the API with backoff (2s → 15s cap) from the local MCP process, so serverless duration limits never apply. The deadline is absolute: `timeout_s` after creation, the request is expired server-side regardless of push delivery, and the tool returns `expired` even if the API is unreachable.

## License

MIT © Vorion
