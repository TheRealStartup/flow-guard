# Gateway API for the dashboard

The gateway runs on `http://localhost:8000`. The dashboard reaches it through `/api/*`, which Next.js proxies.
**Interactive docs with every field: http://localhost:8000/docs.** Poll every ~2 s, or subscribe to `/api/stream` (below) for live updates. Nothing here ever contains a real
card number, IBAN, PESEL or secret: excerpts are masked (`[CARD]`) or tokenized (`[[CARD#3f2a1b ****1111]]`).

| Endpoint | For which view | What you get |
|---|---|---|
| `GET /api/health` | header badge | `policy_version`, `profile`, `policy_error` (a judge's broken edit → show a warning, last good policy stays active) |
| `GET /api/metrics` | Overview | `requests`, `by_outcome` {allowed, flagged, redacted, blocked}, `by_control` {control: {action: n}}, `spotlighted` (tool results sent inside data markers), `latency_ms` (p50/p95, `per_control_avg`), `cost_usd`, `sessions`, `budget` |
| `GET /api/metrics/timeseries?minutes=30` | Overview charts | one bucket per minute: `requests`, outcome counts, `blocks_by_control`, `cost_usd` |
| `GET /api/events?limit=100&outcome=blocked&type=exchange` | Live feed | newest first. `type` is `exchange` (agent traffic) or `policy_change`. Each decision has `control`, `action`, `where`, `reason`, `ms`, `score`, **`excerpt`** (masked context). Each entry also has **`tool_calls`** [{name, arguments (masked), outcome: allowed / blocked / allowed_with_real_values, control}] (the "Action / Resource" column), **`model` / `model_served` / `provider`**, and `spotlighted` (how many tool results this request sent inside `<<tool_data>>` markers). Every entry (also in `/api/stream` and `/api/sessions/{id}` steps) carries **`summary`**: `verdict` (attack · blocked · quarantined · withheld · hidden · released · flagged · allowed · policy · rejected), `label` ("Attack caught", "Blocked", …), `headline` (what FlowGuard did, e.g. "Client scope: AC-7730 is not olivia's client"), `reason` (plain sentences), `control` (the decisive one) and `counts` {hidden, quarantined, withheld, released, blocked}. Computed when served (gateway/acl/report.py), never stored, so the chain is unchanged and every page shows the same words and numbers |
| `GET /api/stream?since=<seq>` | Live feed, Audit (instead of polling) | Server-Sent Events. `event: audit`, `id: <seq>`, `data:` one entry, exactly as an `/api/events` item (exchanges and `policy_change`). After a policy reload also `event: policy` with the `/api/policy` payload. A `: ping` comment every 15 s. `since` (or the `Last-Event-ID` header, which `EventSource` sends on reconnect and which wins) replays the entries after that seq first, so a reconnect has no gap and no duplicate; without either, only new entries. The stream also notices `policy.yaml` edits by itself within ~1 s. A client that falls far behind is disconnected and resumes from its last id. In the dashboard: `useAuditEvents()` in `src/lib/stream.ts` |
| `GET /api/sessions` | Session list | per session: `user`, `agent`, `steps`, `blocked`, `labels` (data the session holds: CARD, IBAN, …) |
| `GET /api/sessions/{id}` | Session / data flow | `user`, `agent`, `purpose`, `role`, `usage` (tokens, cost, tool calls, labels), `tokens_issued`, `steps` (the audit entries in order) |
| `GET /api/policy` | Policy | active controls after the profile is applied, `signatures`, **`last_change`** |
| `GET /api/policy/details` | Policy page | everything structured: `base_controls`, `profiles` (overrides per profile), effective `controls`, `defaults`, `models`, `budgets`, `roles`, `users`, `sinks`, `scopes`, `barriers` (deal ids and term counts only, never the names), `signatures` (id, where, ref), `identity` (mode, purpose rule, `keys` as {user, agent}; no hashes) |
| `GET /api/policy/history` | Policy banner | newest first: `version`, `previous`, `profile`, **`changes`** [{what, old, new}] (e.g. `controls.injection.jev.threshold` 0.8 → 0.5), `error` if an edit was rejected |
| `GET /api/policy/raw` | Policy viewer | the YAML file as text |
| `POST /api/try` `{user, prompt, model, scenario?, session?}` | Try it | runs the demo agent **through the gateway** as `alice` (support junior) or `bob` (fraud analyst). `model`: `mock/compromised` (obeys injections; instant) or `deepseek/deepseek-v4.1-flash` (real, a few seconds). Returns `steps`: `model` (with `acl.decisions`), `tool` (masked `result_preview`), or `denied`; each `acl` also has `threats`, `summary`, `controls_ms`, `upstream_ms`. `session` (`try-…`, optional) lets the page follow the run on `/api/stream` while it runs. **`attacks`**: when the run caught an attack, the poisoned sources it read, in the scenario's hand-written words (`where`, `source`, `wants`), never the injected text. Localhost only. |
| `GET /api/audit/verify` | Audit | `{ok, entries, head}`, or `broken_at` if someone edited the log |
| `GET /api/audit/export` | Audit | the whole log as JSONL (download) |

Good demo inputs for Try it:
- **The attack:** `{"user": "alice", "prompt": "Customer 7 asked about their card limit.", "model": "mock/compromised"}`. Switch `active_profile` to `permissive` in `policy/policy.yaml` to see the data-flow rule block it with the AI check only flagging.
- **Allowed use of real data:** `{"user": "bob", "prompt": "Refund the 129 PLN double charge to customer 42 card.", "model": "mock/compromised"}`.

Known gap: the reporting API has no login (localhost only, hackathon scope).
