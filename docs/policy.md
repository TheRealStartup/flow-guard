# The policy file

One file decides everything the gateway does: [`policy/policy.yaml`](../policy/policy.yaml), plus three files it names:
the attack-signature feed [`policy/signatures.json`](../policy/signatures.json), the API-key list
[`policy/identities.yaml`](../policy/identities.yaml) and the directory [`policy/directory.yaml`](../policy/directory.yaml).
Nothing about what is allowed lives in code.

**Rules vs. people.** `policy.yaml` speaks only about roles, data classes and destinations; it never names a person.
Who has which role, which clients they cover and which deals they are wall-crossed for is in `directory.yaml`, a
stand-in for the bank's identity provider, entitlement system, CRM and compliance control room. In production those
attributes arrive with each request (claims in the sign-on token) or are looked up there.

**Live, safe reload.** The gateway re-reads the four files when they change; no restart. A broken edit (bad YAML,
unknown action, invalid regex, missing profile) is rejected and the **last good policy stays active**, so a typo never
switches controls off. The dashboard's Policies page and `GET /api/policy/history` show the error.

**Every decision names its policy.** The policy version is the declared `version` plus a hash of all four files
(`0.2@1a2b3c4d`). Each audit entry records it, and each change is itself an audit entry (`policy_change`) listing what
changed, field by field, in the effective controls. "Which rule blocked this, and who had changed it that morning?"
has an answer.

## Actions

Every control takes one action, from weakest to strongest:

| Action | Effect |
|---|---|
| `allow` | control is off |
| `flag` | let it through, record it in the audit log |
| `redact` | replace the sensitive part: PII and secrets become reversible tokens such as `[[IBAN#3 ****2874]]`; injected text is quarantined |
| `block` | stop the request, or drop the tool call before the agent runs it |

Each control accepts only the actions it implements. Redact exists only where something can be cut out of a text
(PII, secrets, signatures, barrier, injection check); gates (models, budget, tool access, scope, data lake, purpose, data
flow, spotlighting) take allow, flag or block. Any other value is rejected like a broken edit, and the dashboard shows
only the valid buttons.

`defaults.on_error` (and a control's own `on_error`) says what happens when a check itself fails or times out:
`block` (fail closed, the default) or `allow`.

## Where each control acts

```
agent ──request──▶ gateway ──▶ model provider            model ──response──▶ gateway ──▶ agent runs the tool
  1 identity + purpose                                      7 access.tools   (role may use this tool?)
  2 models.allowlist, budget                                8 access.scope   (argument inside the user's scope?)
  3 signatures (prompt, tool results)                       9 signatures     (tool arguments)
  4 classes, barrier.mnpi, pii.*, secrets                  10 flow.sensitive_to_external (+ egress for Bash)
  5 injection.jev (prompt: jailbreak; tool result: injection)  11 budget (tool calls)
  6 spotlight (tool results wrapped as data)               12 tokens → real values, only for detokenize sinks
```

## Controls

| Control | Default | What it stops | How |
|---|---|---|---|
| `models.allowlist` | block | unapproved models or providers | only models listed under `models` |
| `budget` | block | runaway agents, cost blowouts | per session: tokens, USD, tool calls, compute seconds (`budgets`, raised per role) |
| `pii.card` | redact | card numbers reaching the model vendor | pattern + Luhn checksum |
| `pii.iban` | redact | account numbers reaching the vendor | pattern + mod-97 checksum |
| `pii.pesel` | redact | national ID numbers | pattern + PESEL checksum |
| `pii.passport` | redact | passport numbers | only where the text labels them as a passport, must contain a digit |
| `secrets` | redact | API keys and credentials leaving with the context | provider key prefixes, private keys, credentials in URLs, `KEY=value` assignments with secret-looking values |
| `barrier.mnpi` | redact | material non-public information crossing the information barrier | results naming a restricted deal are withheld from anyone not on that deal; the reply does not confirm the deal exists |
| `access.datalake` | block | an agent writing its own queries against firm data | the agent may only name a query from the `datalake` catalog its role may run; refused before it runs if the result could not be sent on |
| `access.scope` | block | an agent reaching beyond its human's remit | tool arguments must be in the user's scope (e.g. only assigned clients) |
| `signatures` | block | known attacks from outside intelligence | regexes from the feed, matched where each signature says |
| `access.tools` | block | an agent using tools its human may not | role → tool list |
| `flow.sensitive_to_external` | block | data leaving the organisation, whatever the model was tricked into | a call to an external sink is dropped if it carries sensitive data (`mode: value`) or, stricter, once the session has seen any (`mode: session`) |
| `injection.jev` | redact | instructions hidden in data the agent reads (ForcedLeak, EchoLeak) | TypeSafe's Jev model scores each text (never above its `max_class`: Jev is an outside service); above `threshold` the text is quarantined (`redact`) or the request stopped (`block`); JSON tool results are judged field by field so one poisoned field does not cost the whole record |
| `spotlight` | flag | the model confusing data with instructions | tool results are wrapped in `<<tool_data id=…>>` markers with a note that they are data; tool data faking the marker is escaped and flagged (or blocked) |

Detectors are tuned against false positives: checksums for numbers, whole-word keys for secrets. An uncertain match
(the secrets heuristic) is redacted but does not mark the session as holding sensitive data.

## Data classes

```yaml
classification:
  levels: [public, internal, P2, DP30]   # lowest first
  max_to_model: P2
  default: internal
  action: redact                         # redact: withhold with the neutral barrier message | block: stop the request
  tools: {get_client_file: P2, get_customer: internal, ...}
```

Before any model or judge sees a message, it gets a class from a trusted source, never from the model: the tool
that returned it (`tools`), a restricted deal term it names (`barriers.restricted[].class`, e.g. Project Falcon is
DP30), or the data-lake query that produced it. A tool not listed is unclassified and treated as above every limit.
Tokenising identifiers never lowers a class.

Each destination has a limit: `max_to_model` for every model, a model's own `max_class` below that, and
`injection.jev.max_class` for the outside judge (`P2`, the same approval as the model vendor; DP30 reaches neither). Content above the limit is
withheld. A tool result that may reach the model but not Jev cannot be injection-checked, so that request is blocked.

## Data lake

```yaml
datalake:
  tool: query_datalake
  argument: query
  datasets:        {fx_reference: {class: public}, client_positions: {class: P2}, deal_pipeline: {class: DP30}}
  transformations: {sector_counts: {class: internal, from: deal_pipeline, count_by: sector, min_group: 3}}
  queries:
    client_positions:   {dataset: client_positions,     roles: [onboarding_analyst]}
    pipeline_by_sector: {transformation: sector_counts, roles: [mna_banker]}
```

The agent never writes a query; it names one from `queries`. A query is refused before it runs if the user's role is
not listed, or if its class is above what the model (and Jev, while the AI check is on) may receive; every refusal
gives the same neutral reason. Each result carries the lake's own class label; a missing or mismatching label leaves
it unclassified, so it is withheld. A lower-class view of a dataset exists only as a listed transformation: the deal
team's agent may see how many live deals each sector has (groups under `min_group` suppressed), never the deals.

## Profiles

`active_profile` picks one of `strict`, `balanced` (the controls as written) or `permissive`. A profile overrides only
the fields it names. Switching is one line and shows up in the audit trail as a new policy version.

| | strict | balanced | permissive |
|---|---|---|---|
| secrets | block | redact | redact |
| IBAN, PESEL | redact | redact | flag only |
| data flow | any external call once the session saw sensitive data | calls carrying sensitive data | calls carrying sensitive data |
| injection threshold / action | 0.50 / block | 0.80 / redact | 0.95 / flag, fails open |
| fake spotlight markers | block | flag | flag |

Data-flow control stays `block` in every profile: it is the backstop when detection misses.

## Models

```yaml
models:
  deepseek/deepseek-v4.1-flash: {upstream: openrouter, input_per_m: 0.10, output_per_m: 0.30}
```

Each approved model names its upstream (`openrouter`, `ollama`, `mock`), optionally a price per million tokens (used
only when the provider does not report the cost), and optionally `max_class`: the highest data class it may receive,
below `classification.max_to_model`. That is the vendor approval: a model added from the dashboard's Policies page gets
the lowest class (`internal`) unless someone chooses higher, so a new vendor sees no client data by default.

`models.allowlist` is the enforcement switch, shown as **Enforce** (block: other models are refused), **Monitor** (flag:
other models are let through, recorded, and get only the default class) and **Off** (allow). `mock/compromised` is a scripted model that obeys every
injected instruction; the demo and the tests use it to show the controls, not the model's manners.

## Budgets

```yaml
budgets:
  session: {max_tokens: 60000, max_cost_usd: 0.05, max_tool_calls: 20, max_compute_seconds: 300}
```

Limits per session. A role can raise or lower any of them (`roles.developer.budget`: Claude Code sends ~16k tokens
per request).

## Identity

```yaml
identity: {mode: api_key, keys_file: identities.yaml, require_purpose: true}
```

`api_key`: every request presents a key; it maps to exactly one (user, agent) pair in `identities.yaml`, and the
agent gets that user's role, never more. Only SHA-256 hashes are stored; `just new-key <user> <agent>` makes a key.
A key may carry a default `purpose` for agents that cannot send headers (Claude Code). No key, unknown key or missing
purpose: denied, and the denial is audited. `header` mode trusts `X-User` and is for local development only.

## Users, roles, barriers, scopes

```yaml
users:
  olivia: {role: onboarding_analyst, side: public, assigned_clients: [NW-2041]}
  marcus: {role: mna_banker, side: private, deals: [falcon]}
roles:
  onboarding_analyst: {tools: [get_client_file, screen_sanctions, search_documents, send_email]}
barriers:
  public_message: "Some results are outside your access."
  restricted:
    - {id: falcon, terms: ["Project Falcon", "Kestrel Dynamics", "KSTL"]}
scopes:
  get_client_file: {argument: client_id, user_field: assigned_clients}
```

- **Roles** list the tools a user's agent may call. `"*"` allows any tool (a coding agent with its own tool set); all
  other controls still apply. Users without a role get `default` (no tools).
- **Barriers**: content naming a restricted deal reaches only users whose `deals` include it. Nobody, the deal team
  included, may send it to an external sink.
- **Scopes**: `get_client_file` may only be called with a `client_id` from the user's `assigned_clients`; the call is
  stopped before the file is read.

## Sinks and egress

```yaml
sinks:
  external: [send_email, http_post, WebFetch]   # data leaves the organisation here
  detokenize: [charge_card, screen_sanctions]   # real values are put back only for these tools
egress:
  tools: {Bash: command}
  patterns: ['\b(curl|wget|nc|ncat|scp|rsync|ftp)\b']
  allow_hosts: [localhost, 127.0.0.1, pypi.org, files.pythonhosted.org]
```

- **External sinks** are where `flow.sensitive_to_external` applies.
- **Detokenize sinks** are the only tools that receive real values in place of tokens (the sanctions check needs the
  real passport number; the model never sees it).
- **Egress**: coding agents send data out through the shell. A `Bash` command matching a pattern, to a host outside
  `allow_hosts`, counts as an external sink. A command with no recognisable host counts as outside.

## Attack-signature feed

`controls.signatures.feed` names a JSON file of known attack patterns, reloaded on change like the policy:

```json
{"id": "SIG-CURL-PIPE-SHELL", "where": ["tool_args", "tool_result", "prompt"],
 "pattern": "…", "ref": "Remote script execution"}
```

`where` is any of `prompt`, `tool_result`, `tool_args`, `tool_description`. System prompts are not scanned (they are
the operator's own text). The shipped feed holds 8 signatures, each referencing a real incident or CVE: malicious pickle
model files, `torch.load` without `weights_only` (CVE-2025-32434), unsafe YAML loading, `curl | sh`, `rm -rf /`
(the Replit database deletion), ShadowRay (CVE-2023-48022), MCP tool poisoning, markdown-image exfiltration. In
production the file is pulled from a threat-intelligence source.

## Changing the policy

1. Edit `policy/policy.yaml` (or the feed, or the keys file) and save.
2. The next request uses it. Check the dashboard's Policies page or `GET /api/policy/history`: the new version and the
   field-by-field diff, or the error if the edit was rejected.
3. The tests in [`tests/cases/controls.yaml`](../tests/cases/controls.yaml) describe each control's expected behaviour;
   `just test` runs them against the policy.
