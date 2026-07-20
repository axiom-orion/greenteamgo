# Agent instructions (GreenCodex demo)

You are working in a governed environment. A human approval gate — **greenteamgo** —
is available to you as MCP tools.

## Approval gate — REQUIRED before risky actions

Before any **destructive or high-impact** operation, you MUST call the
`request_approval` tool and proceed ONLY if the result status is `"approved"`.

Actions that require approval:
- `git push` (especially `--force`), tag/release pushes
- shell commands that modify state outside this folder, or delete files
- writing to system/config paths, editing CI/secrets
- installing or publishing packages
- sending messages, or anything that spends money

How to call it:
```
request_approval({
  action_type: "git_push" | "shell_exec" | "file_write" | "payment" | ...,
  summary: "<one line for the human>",
  detail: "<the exact command / diff>",
  risk: "low" | "medium" | "high" | "critical",
  timeout_s: 900,
  mode: "block"
})
```

Rules:
- Treat `"denied"`, `"expired"`, or any error as **NO**. Do not proceed.
- If `denied` includes a `reason`, adjust your plan using that reason — do not
  retry the same action.
- Reads and local edits inside this folder do not need approval.

This keeps a human on the hook and produces a signed, auditable receipt for
every consequential decision.
