# @vorionsys/greenteamgo-notify

The GreenTeamGo **notify** module — turns a pending approval request into an **inbox item** (what the phone renders) and delivers it through a pluggable transport.

- `buildInboxItem(request, opts)` — the one inbox-item shape: request context, risk, expiry, a decision deep link, and the two actions (`approve` / `deny` — deny is always cheap, approve costs attention).
- `WebhookNotifier` — POSTs inbox items to any URL (a relay, an FCM-sending function, a chat webhook, a test server). Optional bearer token.
- `NoopNotifier` — the default when no transport is configured.
- An FCM notifier ships later on the same `InboxItem` shape.

Structurally compatible with the `Notifier` interface `@vorionsys/greenteamgo-api`'s `RequestService` expects — drop either notifier straight in. Delivery failure is isolated from the request lifecycle: a webhook outage never fails the create or weakens fail-closed expiry (see the api package).

```ts
import { WebhookNotifier } from "@vorionsys/greenteamgo-notify";

const notifier = new WebhookNotifier({
  url: "https://relay.example.com/inbox",
  token: process.env.RELAY_TOKEN,
  deepLinkBase: "greenteamgo://requests",
});
// new RequestService({ store, notifier })
```

## License

MIT © Vorion
