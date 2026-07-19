/**
 * Notify module — turn a pending request into an inbox item and deliver it to
 * the human. The delivery transport is pluggable: a WebhookNotifier (POST the
 * inbox item to a URL — works with any push/relay, and is what we test with)
 * ships now; an FCM notifier layers on the same InboxItem shape later.
 *
 * The `Notifier` here is structurally identical to the one the API expects, so
 * these notifiers drop straight into `RequestService`.
 */

export type Risk = "low" | "medium" | "high" | "critical";

/** The minimum a request must expose to be turned into an inbox item. */
export interface NotifiableRequest {
  request_id: string;
  workspace_id: string;
  action_type: string;
  summary: string;
  detail?: string;
  risk: Risk;
  created_at: string;
  expires_at: string;
}

/** What the phone/app renders and lets the human act on. */
export interface InboxItem {
  request_id: string;
  workspace_id: string;
  action_type: string;
  summary: string;
  detail?: string;
  risk: Risk;
  created_at: string;
  expires_at: string;
  /** deep link into the app's decision screen */
  deep_link: string;
  /** the two decisions the human can take (deny is cheap, approve costs attention) */
  actions: ["approve", "deny"];
}

export interface Notifier {
  notify(request: NotifiableRequest): void | Promise<void>;
}

export interface InboxItemOptions {
  /** base for the decision deep link, e.g. "greenteamgo://requests" or an https URL */
  deepLinkBase?: string;
}

export function buildInboxItem(req: NotifiableRequest, opts: InboxItemOptions = {}): InboxItem {
  const base = (opts.deepLinkBase ?? "greenteamgo://requests").replace(/\/$/, "");
  return {
    request_id: req.request_id,
    workspace_id: req.workspace_id,
    action_type: req.action_type,
    summary: req.summary,
    detail: req.detail,
    risk: req.risk,
    created_at: req.created_at,
    expires_at: req.expires_at,
    deep_link: `${base}/${encodeURIComponent(req.request_id)}`,
    actions: ["approve", "deny"],
  };
}

/** No-op notifier (default). */
export class NoopNotifier implements Notifier {
  notify(): void {
    /* intentionally nothing */
  }
}

export interface WebhookNotifierOptions extends InboxItemOptions {
  url: string;
  /** optional bearer token for the webhook endpoint */
  token?: string;
  fetchFn?: typeof fetch;
}

/**
 * Deliver inbox items by POSTing them to a URL. Transport-agnostic: point it at
 * a relay, an FCM-sending function, a chat webhook, or a test server.
 */
export class WebhookNotifier implements Notifier {
  private fetchFn: typeof fetch;

  constructor(private opts: WebhookNotifierOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  async notify(request: NotifiableRequest): Promise<void> {
    const item = buildInboxItem(request, this.opts);
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.opts.token) headers["authorization"] = `Bearer ${this.opts.token}`;
    const res = await this.fetchFn(this.opts.url, {
      method: "POST",
      headers,
      body: JSON.stringify(item),
    });
    if (!res.ok) {
      throw new Error(`webhook notify failed: ${res.status}`);
    }
  }
}
