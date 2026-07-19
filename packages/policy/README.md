# @vorionsys/greenteamgo-policy

Versioned **policy** rules that decide an event's fate before a human is ever paged:

- **allow** — auto-approve (receipt sealed, no human)
- **deny** — auto-block (receipt sealed, no human)
- **gate** — ask the human (GreenTeamGo default)
- **challenge** — make the caller prove itself (RedTeamGo default)

First matching rule wins; if none matches, the policy's `default_effect` applies. This is what keeps the human's attention (and the free-tier approval quota) for the requests that actually need judgment.

```ts
import { evaluate } from "@vorionsys/greenteamgo-policy";

const policy = {
  id: "pol_1", workspace_id: "ws1", version: 2, default_effect: "gate",
  rules: [
    { id: "r_read",  action_type: "file_read", effect: "allow", risk_class: "low" },
    { id: "r_pay",   action_type: "payment",   effect: "deny" },
    { id: "r_shell", action_type: "shell_*", min_risk: "high", effect: "gate" },
    { id: "r_bot",   actor_type: "observed",   effect: "challenge" }, // Red
  ],
};

evaluate(policy, { action_type: "file_read" });
// { effect: "allow", risk: "low", policy_id: "pol_1", policy_version: 2, matched_rule_id: "r_read" }

evaluate(policy, { action_type: "git_push", risk: "high" });
// { effect: "gate", risk: "high", policy_id: "pol_1", policy_version: 2 }  (default)
```

## Rule matching

| Field | Meaning |
|---|---|
| `action_type` | exact (`git_push`), wildcard (`*`), or prefix glob (`shell_*`) |
| `min_risk` | event risk must be ≥ this (`low < medium < high < critical`) |
| `actor_type` | `agent_key` (Green) or `observed` (Red) |
| `effect` | `allow \| deny \| gate \| challenge` |
| `risk_class` | assign/override the risk carried into the receipt |

Wired into `@vorionsys/greenteamgo-api`: `allow`/`deny` seal a receipt with `decider.method: "policy"` and page nobody; `gate`/`challenge` create a pending request and notify. Auto and human decisions share one receipt chain.

## License

MIT © Vorion
