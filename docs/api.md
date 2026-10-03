# Gateway API for the dashboard

The gateway runs on `http://localhost:8000`. The dashboard reaches it through `/api/*`, which Next.js proxies.
**Interactive docs with every field: http://localhost:8000/docs.** Poll every ~2 s. Nothing here ever contains a real
card number, IBAN, PESEL or secret: excerpts are masked (`[CARD]`) or tokenized (`[[CARD#3f2a1b ****1111]]`).

| Endpoint | For which view | What you get |
|---|---|---|
| `GET /api/health` | header badge | `policy_version`, `profile`, `policy_error` (a judge's broken edit → show a warning, last good policy stays active) |
| `GET /api/metrics` | Overview | `requests`, `by_outcome` {allowed, flagged, redacted, blocked}, `by_control` {control: {action: n}}, `spotlighted` (tool results sent inside data markers), `latency_ms` (p50/p95, `per_control_avg`), `cost_usd`, `sessions`, `budget` |
| `GET /api/metrics/timeseries?minutes=30` | Overview charts | one bucket per minute: `requests`, outcome counts, `blocks_by_control`, `cost_usd` |
| `GET /api/events?limit=100&outcome=blocked&type=exchange` | Live feed | newest first. `type` is `exchange` (agent traffic) or `policy_change`. Each decision has `control`, `action`, `where`, `reason`, `ms`, `score`, **`excerpt`** (masked context). Each entry also has **`tool_calls`** [{name, arguments (masked), outcome: allowed / blocked / allowed_with_real_values, control}] (the "Action / Resource" column), **`model` / `model_served` / `provider`**, and `spotlighted` (how many tool results this request sent inside `<<tool_data>>` markers) |
| `GET /api/sessions` | Session list | per session: `user`, `agent`, `steps`, `blocked`, `labels` (data the session holds: CARD, IBAN, …) |
| `GET /api/sessions/{id}` | Session / data flow | `user`, `agent`, `purpose`, `role`, `usage` (tokens, cost, tool calls, labels), `tokens_issued`, `steps` (the audit entries in order) |
| `GET /api/policy` | Policy | active controls after the profile is applied, `signatures`, **`last_change`** |
| `GET /api/policy/history` | Policy banner | newest first: `version`, `previous`, `profile`, **`changes`** [{what, old, new}] (e.g. `controls.injection.jev.threshold` 0.8 → 0.5), `error` if an edit was rejected |
| `GET /api/policy/raw` | Policy viewer | the YAML file as text |
| `POST /api/try` `{user, prompt, model}` | Try it | runs the demo agent **through the gateway** as `alice` (support junior) or `bob` (fraud analyst). `model`: `mock/compromised` (obeys injections; instant) or `deepseek/deepseek-v4.1-flash` (real, a few seconds). Returns `steps`: `model` (with `acl.decisions`), `tool` (masked `result_preview`), or `denied`. Localhost only. |
| `GET /api/audit/verify` | Audit | `{ok, entries, head}`, or `broken_at` if someone edited the log |
| `GET /api/audit/export` | Audit | the whole log as JSONL (download) |

Good demo inputs for Try it:
- **The attack:** `{"user": "alice", "prompt": "Customer 7 asked about their card limit.", "model": "mock/compromised"}`. Switch `active_profile` to `permissive` in `policy/policy.yaml` to see the data-flow rule block it with the AI check only flagging.
- **Allowed use of real data:** `{"user": "bob", "prompt": "Refund the 129 PLN double charge to customer 42 card.", "model": "mock/compromised"}`.

Known gap: the reporting API has no login (localhost only, hackathon scope).
