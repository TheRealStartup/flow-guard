# Decisions

## D1 · MVP enforcement point = an OpenAI-compatible model proxy · ⚠️ CONTESTED (Paul, 10-03 15:05), revisit
We go with it for now, to get one path working end to end. Paul is not convinced; revisit before building the second adapter.

**For**
- One place sees tool definitions, tool results (as messages) and tool calls (in the response).
- It redacts before the model, blocks or edits tool calls, counts tokens exactly, and enforces allowed models.
- Any agent can use it via `base_url`.

**Against / open**
- **Only model traffic.** The agent process still receives raw tool results (it sees the real card number), and anything the agent does without asking the model is invisible.
- **Easy to bypass.** The agent can simply change `base_url`. Real enforcement needs network egress control or a managed config.
- **Different API formats.**
  - Codex uses the OpenAI *Responses* API, Claude Code the Anthropic *Messages* API, so `/v1/chat/completions` covers neither yet.
  - Streaming must be buffered for each tool-call block.
- **What the tools actually do** (arguments → effects) is better seen at an MCP gateway or a harness hook.

**Revisit when:** we add the Claude Code / Codex demo; the Goldman mentor says where their traffic flows; or after the MVP stands (Sat ~20:00).
**Escape hatch:** the engine (`decide()`) knows nothing about the adapter. An MCP gateway or hook calls the same engine.

## D2 · No approvals in the MVP
A policy action `require_approval` blocks with a reason for now. Approval by a second person, bound to a hash of the arguments, is extension #1.

## D3 · Latency target: 300 ms p95 applies to the rule-based path only · PROPOSED, open
US-1.1 asks for overhead under 300 ms at p95. The Jev check can't meet that.

**Measured (venue wifi):**
- 14:45: 2.0–4.5 s per Jev call.
- 15:40 (curl breakdown): 0.59–0.77 s on a new connection.
  - DNS 0.26–0.41 s (slow venue DNS)
  - TCP + TLS about 0.3 s
  - server work about 0.3–0.4 s
- The 14:45 numbers were not reproduced; probably a load spike.
- With the reused connection (in the code since 15:00), expect 0.3–0.45 s per call.

**Proposal:**
- The 300 ms target applies to the rule-based path (single-digit ms).
- AI-check latency is reported separately (`/api/metrics` → `per_control_avg`).
- The AI check runs only on new untrusted content, cached.
- If we must meet 300 ms end to end, add a local classifier first (backlog).

**Decide with:** the team, after the mentor conversation.

## D4 · Two core demo scenarios · DECIDED (Paul, Sun ~01:10)
- **A: client onboarding (KYC / CDD).** An institutional client, a hedge fund, whose documents probe for deal information. Shows information barriers, an "assigned clients only" rule, and identity documents that never reach the model.
- **B: a developer using the real Claude Code** through the gateway. Shows client data at the vendor border (debugging a production payments log), attacks from the supply chain, and budgets.
- **Customer support (alice/bob)** is background only: tests and dashboard examples, not on stage.

## D5 · What "airtight" means · PRINCIPLE (Paul, Sun ~01:10)
First and foremost, each scenario must make sense as a business case, use the language of the business, and get its details right: documents, thresholds, roles, data flows. Fallbacks and mocks are secondary.

## D6 · Data classes are enforced at every model boundary, Jev included (issue #13)
Jev runs at api.typesafe.ai, so it is an external model destination, not an internal check. Masking cards, IBANs and
secrets does not remove confidential business facts, and a user cleared to read a deal is not thereby cleared to send it
to a model provider.

**Rule:** every message gets a class (`public < internal < P2 < DP30`, `classification` in policy.yaml) from a trusted
source: the tool that produced it, or a restricted term it names. Tokenising never lowers it. Content above
`max_to_model` (or a model's own `max_class`) is withheld with the neutral barrier message. Content the model may
receive but Jev may not (`injection.jev.max_class`, never above `max_to_model`) cannot be injection-checked, so the
request is blocked, whatever `on_error` says. Missing classes or limits fail closed; a misspelt class keeps the last
good policy. Every request re-classifies the whole history, so a lowered limit applies to earlier messages too.

**Defaults:** ~~Jev `internal`~~ Jev `P2` (amended, see below); `get_client_file` P2. The Falcon deal and `query_datalake` are DP30: no model
gets them, the deal team included.

**Known limit:** a tool result's class comes from the call id this gateway let through. For history the gateway never
saw (a client that starts mid-conversation), it falls back to the tool name the agent claims. The MCP gateway removes
that gap, because it sees the tool's own result.

**Amended (Paul, Sun ~02:25): Jev's limit = the model vendor's limit, P2.** With Jev at `internal`, the policy handed
the client file to one outside vendor (the model, via OpenRouter) but not to the other (Jev) that guards it, so every
onboarding run was blocked and core scenario A could not run. A destination's limit follows its vendor approval, not
its job; both are outside processors, so both get P2, and DP30 reaches neither. The mechanism is unchanged: lowering
Jev's limit below the data still stops the request (the tests now set that limit explicitly). Open: Jev is still a third
party. The production answer is an in-house model plus an on-premise injection check for P2 (open-weight classifier),
with outside vendors at `internal` (board card).

## D7 · Data lake: named queries, refused before they run, labels verified (first demo)
The agent never writes a query; it names one from `datalake.queries` in policy.yaml (`demo/datalake.py` holds the
synthetic datasets). The gateway refuses a call before it runs if the query is unknown, the user's role may not run
it, or its result could not be sent on (above the model's limit, or above Jev's while the AI check is on). Every
refusal has the same reason, so it reveals nothing about which datasets exist, their class or who may see them.
The lake labels each result; the gateway takes the class from the query it let through (not from the arguments the
agent echoes back) and withholds a result whose label is missing or differs. A lower-class view of a dataset exists
only as a declared transformation: `sector_counts` gives the deal team counts per sector, groups under 3 dropped,
never the deals. The public side gets no pipeline view at all, because a count of pending deals is MNPI to them.

## D8 · HR: no model judges employees; personnel files reach no model (`access.purpose`, HR card)
HR may use the agent for administration and policy questions, never to evaluate, rank, rate, review or decide on
employees (a decision about a person is made by a person). Personnel files hold salary, health and manager notes.

**Rule:** `access.purpose` in policy.yaml holds rules scoped to roles (today `hr-no-employee-judging` for `hr_admin`).
It is the first check on every request, before the model allowlist, the data classes, the signatures and Jev, so a
stopped request reaches neither the task model nor Jev, and it does not depend on `signatures` or `injection.jev` being
on. It stops a request when:
- the stated purpose (X-Purpose, or the key's default) contains a forbidden one: `performance_review`, `termination`,
  `ranking` (case, spaces, `-` and `_` ignored, so `Performance Review` and `termination-letter` count);
- any message of the conversation matches one of the rule's signatures (rank / rate / evaluate / performance review /
  fire / who to let go, near an employee reference such as `E-1001`, "my team", "these employees"; a Polish variant
  too; and people named in the prompt: "Should we fire Maria?", "Can we let Maria go?", "Fire Maria.", "Write a
  performance review for Maria.", "Evaluate Maria's performance.", "Rank Alice and Bob by performance", in any
  capitalisation), whatever the header claims. The whole history is searched on every request, so a request that once went
  through (rule off at the time) is stopped when it is replayed after a live reload. Tool results are searched only if
  their source class lets them reach the model; a record that is withheld anyway cannot carry a request to the model,
  and a note in it that mentions a review must not stop admin work.
The denial names the rule and the signature id, never the request text (excerpt `[WITHHELD: request text not
recorded]`), so the audit log, the API answer and Try it do not repeat it. Ordinary work is not affected: "rank these
cities", "rank the employee benefit options", "should we fire the analytics event…", "which event should we fire?", "sort the rates table", "what is
the parental leave policy?" pass, and other roles are not checked at all. The handbook (`demo/hr.py`) is a synthetic
sample company policy with fictional rules, not real leave or employment-law requirements. Try it shows a tool-result
preview only when the tool's class and the default class are both known levels and the tool is not above the default;
anything unclassified, misspelt or missing is withheld.

**Personnel files:** `get_employee` is DP30 (its class comes from `classification.tools`, set out of band, never from
the record), scoped to the user's `allowed_employees` (`access.scope`: the call never runs outside them), and listed in
`classification.block_calls_above_limit`: while the current model, or Jev while it is on, may not receive DP30, the call
is not made at all, so the record is not even fetched. A record the agent holds anyway (forged or replayed history) is
withheld by the class gate like any DP30 result. `get_hr_policy` (the published handbook) is internal. Both adapters
(`/v1/chat/completions` and `/v1/messages`) call the same engine, so all of this applies to both (tests/test_hr.py).

**Fail closed:** a malformed rule (no roles, forbidden not a list, a regex that does not compile or matches empty text,
action `redact`) is rejected on reload and the last good policy, with its rules, stays active (`policy_error` in
/api/metrics). A judge may still switch the control to `flag` or `allow` on purpose; that is a policy decision, logged
as a policy change.

**Known limits:** the signatures are deterministic regexes, not a semantic guarantee. They catch the plain ways of
asking (and invisible or full-width characters, JSON escapes), not paraphrases ("who would you keep if budgets were
cut?", "how did Maria do this year?", "show Maria the door", "Maria or Bob: who stays?"), synonyms beyond the listed
verbs, other languages than English and Polish, or look-alike letters from other scripts. A named person is recognised
only by the shape of the sentence (any word that is not a determiner or a listed technical noun), so a technical
"should we fire telemetry now?", "terminate staging." or "evaluate Postgres's performance" may be stopped for HR users. They may also stop a
borderline policy question that names a specific employee next to "termination". No model, ours or Jev, is used to
judge HR prompts or records: an external judge would itself be a model processing the records. The purpose header is
what the caller states; the rule stops a declared forbidden purpose, it cannot prove a declared benign one.

**Purpose in reports:** an HR X-Purpose is free text and can itself name a person, a salary or a health matter. A role
with `redact_purpose: true` (today `hr_admin`) keeps its raw purpose in memory only, for `access.purpose` on every
request; the audit log, events, export and `/api/sessions/{sid}` show `[WITHHELD: purpose not recorded]`, allowed or
blocked, whether `access.purpose` is on or off. A request refused before identity is established (no or wrong key, a key
claiming another user, a session hijack) never records the caller's purpose. Other roles keep their purpose in the log.
A non-boolean flag is rejected on reload (last good policy stays). Tests: tests/test_hr_reporting.py.

## D9 · The scripted model (`mock/compromised`) stays in the demo, labelled as hijacked · DECIDED for now (Paul, Sun ~04:00)
Real models often refuse obvious data theft on their own (DeepSeek: 3 of 3), which hides whether our controls work. The
scripted model obeys every instruction it reads. It is used for two beats only, both introduced as "a model we hijacked on
purpose": the backstop (injection check on Flag, the data-flow rule still stops the email) and the runaway loop (the
budget stops it). Everything else runs on DeepSeek. Paul dislikes mock models; may change (alternatives: recorded audit
entries, or DeepSeek with the check on Flag and accept that it may refuse).

## D10 · Integrity: the injection check looks only at what an outsider can write · DECIDED (Paul, Sun ~05:30)
**Problem.** The first real onboarding-desk run (Claude Code, Sun ~06:30) quarantined the bank's own screening verdicts
(Jev 0.77–0.80) and the hub's submission receipt (0.46). Nothing in them was written by an outsider: a screening verdict
in a fixed format reads like an instruction ("resolve each result", "escalate"). Jev was calibrated on public datasets
without agent tool results, and the threshold change (0.80 → 0.40) was merged without an end-to-end run.

**Cause.** A design gap, not a threshold problem. Data classes (D6) answer *who may read* data (confidentiality, Bell–
LaPadula). Nothing answered *whose words a result can carry* (integrity, Biba). Every tool result was treated as possibly
hostile, so the check ran where there was nothing to find.

**Decision.** A second axis per source, `integrity` in policy.yaml: `external` (an outsider can write it: a client's
document, an email, a web page, a public register) or `bank` (written only by the bank's own systems). Jev checks
prompts and external results; bank results are recorded as "not checked: written only by the bank's own system".
- Unlisted tools are external, and `integrity.default` may not be set to `bank` (rejected on reload).
- A result is `bank` only when this gateway let the call through to that tool in this session. History the gateway
  did not see, or a result the agent relabels, is external.
- Signatures, redaction, the class gate and spotlighting still run on bank results.
- Jev's data-class limit no longer applies to bank results, because Jev never receives them.
- Mixed systems are split by tool: the hub's case record is `bank`, its `get_document` (client submissions) is
  `external`; `get_client_file` stays external because it carries the client's documents.

**Limit.** A bank system that echoes an outsider's text (a submitted name in a screening result) carries a short piece of
it unchecked. The signatures still see it; a system that echoes long outside text must be listed as external. Tests:
tests/test_integrity.py.
