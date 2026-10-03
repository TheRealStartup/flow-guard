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
