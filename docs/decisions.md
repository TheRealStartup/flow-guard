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
