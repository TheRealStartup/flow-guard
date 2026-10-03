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

**Defaults:** Jev `internal`; `get_client_file` P2, so the onboarding flow stops at the client file unless
`injection.jev.max_class` is raised to P2 (a live-edit demo). The Falcon deal and `query_datalake` are DP30: no model
gets them, the deal team included.

**Known limit:** a tool result's class comes from the call id this gateway let through. For history the gateway never
saw (a client that starts mid-conversation), it falls back to the tool name the agent claims. The MCP gateway removes
that gap, because it sees the tool's own result.

## D7 · HR: no model judges employees; personnel files reach no model (`access.purpose`, HR card)
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
  too), whatever the header claims. The whole history is searched on every request, so a request that once went
  through (rule off at the time) is stopped when it is replayed after a live reload. Tool results are searched only if
  their source class lets them reach the model; a record that is withheld anyway cannot carry a request to the model,
  and a note in it that mentions a review must not stop admin work.
The denial names the rule and the signature id, never the request text (excerpt `[WITHHELD: request text not
recorded]`), so the audit log, the API answer and Try it do not repeat it. Ordinary work is not affected: "rank these
cities", "sort the rates table", "what is the parental leave policy?" pass, and other roles are not checked at all.

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
cut?"), other languages than English and Polish, or look-alike letters from other scripts. They may also stop a
borderline policy question that names a specific employee next to "termination". No model, ours or Jev, is used to
judge HR prompts or records: an external judge would itself be a model processing the records. The purpose header is
what the caller states; the rule stops a declared forbidden purpose, it cannot prove a declared benign one.
