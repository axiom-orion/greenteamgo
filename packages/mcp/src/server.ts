import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  GreenTeamGoClient,
  PayloadTooLargeError,
  type RequestState,
  type Risk,
} from "./client.js";
import type { Config } from "./config.js";

export const VERSION = "0.1.0";

export function buildServer(cfg: Config, client?: GreenTeamGoClient): McpServer {
  const api = client ?? new GreenTeamGoClient({ apiUrl: cfg.apiUrl, apiKey: cfg.apiKey });
  const server = new McpServer({ name: "greenteamgo", version: VERSION });

  server.registerTool(
    "request_approval",
    {
      title: "Request human approval",
      description:
        "Ask a human to approve or deny an action BEFORE you perform it. Use this before destructive or risky operations: shell commands that change state, file writes outside the workspace, git push, payments, sending messages. In block mode (default) this waits for the human decision. A result of \"expired\" MUST be treated as denied — fail closed, never proceed. If denied with a reason, use the reason to adjust your approach.",
      inputSchema: {
        action_type: z
          .string()
          .min(1)
          .describe('Kind of action, e.g. "shell_exec", "file_write", "git_push", "payment", or custom'),
        summary: z
          .string()
          .min(1)
          .max(300)
          .describe("One-line human-readable summary shown in the push notification"),
        detail: z
          .string()
          .optional()
          .describe("Markdown detail rendered in the app (command, diff, context)"),
        payload: z
          .union([z.string(), z.record(z.unknown())])
          .optional()
          .describe("Args/diff as object or string. Max 256KB inline. NEVER include secrets."),
        hash_only: z
          .boolean()
          .optional()
          .describe(
            "Upload ONLY the payload's SHA-256, never the payload itself. Use for sensitive payloads; the human sees summary/detail plus the hash the receipt commits to.",
          ),
        risk: z
          .enum(["low", "medium", "high", "critical"])
          .optional()
          .describe("Risk class; default from server config (medium). high/critical require biometric approval."),
        timeout_s: z
          .number()
          .int()
          .positive()
          .max(604800)
          .optional()
          .describe("Seconds until the request expires. Expiry = deny. Defaults: 900 block / 86400 async."),
        mode: z
          .enum(["block", "async"])
          .optional()
          .describe('"block" waits for the decision (default); "async" returns a request_id to check with get_decision'),
      },
    },
    async (args) => {
      const mode = args.mode ?? "block";
      const timeoutS =
        args.timeout_s ?? (mode === "block" ? cfg.defaultBlockTimeoutS : cfg.defaultAsyncTimeoutS);
      const risk = (args.risk ?? cfg.defaultRisk) as Risk;
      try {
        const created = await api.createRequest({
          action_type: args.action_type,
          summary: args.summary,
          detail: args.detail,
          payload: args.payload,
          hash_only: args.hash_only,
          risk,
          timeout_s: timeoutS,
          mode,
        });
        // Pre-decided by server-side policy (auto-allow/deny rules) — report it
        // regardless of mode: an async caller told "pending" after an auto-DENY
        // would keep working toward an action that is already refused.
        if (created.status && created.status !== "pending") {
          return jsonResult(decisionView(created));
        }
        if (mode === "async") {
          return jsonResult({
            status: "pending",
            request_id: created.request_id,
            expires_at: created.expires_at,
          });
        }
        const deadline = Date.now() + timeoutS * 1000 + 5000;
        const state = await api.waitForDecision(created.request_id, deadline, {
          initialMs: cfg.pollInitialMs,
        });
        return jsonResult(decisionView(state));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "get_decision",
    {
      title: "Get decision",
      description:
        'Check the status of a previously created approval request. "expired" MUST be treated as denied (fail closed).',
      inputSchema: { request_id: z.string().min(1) },
    },
    async ({ request_id }) => {
      try {
        return jsonResult(decisionView(await api.getRequest(request_id)));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "list_pending",
    {
      title: "List pending approvals",
      description: "List approval requests still waiting for a human decision in this workspace.",
      inputSchema: {},
    },
    async () => {
      try {
        const items = await api.listPending();
        return jsonResult(
          items.map((r) => ({
            request_id: r.request_id,
            status: r.status,
            summary: r.summary,
            risk: r.risk,
            created_at: r.created_at,
            expires_at: r.expires_at,
          })),
        );
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  return server;
}

function decisionView(s: RequestState): Record<string, unknown> {
  const out: Record<string, unknown> = { request_id: s.request_id, status: s.status };
  if (s.reason) out.reason = s.reason;
  if (s.receipt) out.receipt = s.receipt;
  if (s.status === "expired") out.note = "treat as denied (fail closed)";
  return out;
}

function jsonResult(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

function errorResult(err: unknown) {
  const msg =
    err instanceof PayloadTooLargeError
      ? err.message
      : err instanceof Error
        ? err.message
        : String(err);
  return {
    isError: true as const,
    content: [
      {
        type: "text" as const,
        text: `greenteamgo error: ${msg}. Do not proceed with the gated action (fail closed).`,
      },
    ],
  };
}
