# Spec: Claude Code behind the gateway

Status: phase 1 BUILT (Sat 3 Oct ~22:30): `gateway/acl/adapters/anthropic.py`, `just claude-code`,
`tests/test_claude_code.py` (16 tests). Checked end to end with the real `claude` 2.1.283 binary and `mock/compromised`:
`.env` read → model saw only `[[SECRET#…]]`; poisoned README → `Bash curl` dropped by `flow.sensitive_to_external`;
"until they pass" → 20 real pytest runs, then `budget` stopped it. Phase 2 (hooks) not built.

**Run it:** `just gateway` in one terminal, then `just claude-code` (interactive) or
`just claude-code mock/compromised -p "What is configured in .env?"`.

## Goal
A real, unmodified Claude Code session runs with its model traffic going through our gateway. The judges watch
Claude Code try something it should not do (send a secret out, obey a poisoned README) and see the gateway stop it,
with the decision in the same audit log and dashboard as our scripted demo agents.

**Why it matters for the pitch**
- Judges see a tool they know, not our scripted agent, governed by the same policy, audit log and dashboard.
- Makes "practicality / implementability" concrete: one environment variable, no change to the agent.
- Fits Goldman's developer rollout (Devin, coding agents at scale) and the missing developer persona in the brief.

**What it proves, and what it does not** (say this on the slide, it is part of the reporting score)
- Proves: the gateway governs any agent that speaks a standard model API; it decides before the agent acts (a blocked
  tool call is removed from the model's answer, so Claude Code never runs it); secrets are tokenized before they reach
  the model provider; every step is audited with the policy version.
- Does not prove: that Claude Code cannot bypass it. The developer can unset `ANTHROPIC_BASE_URL`. Production answer:
  pin the variable in `managed-settings.json` plus network egress control (only the gateway may reach model providers).
  The local Claude Code process still sees raw tool output (it ran the tool); only the model is shielded (same as D1).

## Two routes (both documented by Anthropic)

| | A · Model proxy (`ANTHROPIC_BASE_URL`) | B · Hooks (`PreToolUse` / `PostToolUse`) |
|---|---|---|
| What we see | Prompts, tool results, proposed tool calls | The exact tool call about to run, and its output |
| Can block a tool call | Yes: drop it from the model's answer | Yes: hook returns `deny` with a reason |
| Can hide secrets from the model | Yes: tokenize tool results before forwarding | Not for built-in tools (⚠️ verify; MCP output only) |
| Injection check, budgets, model allowlist | Yes, existing engine | Tool-call checks only |
| Model | Any model in `policy.models` (Ollama, mock) | Whatever Claude Code uses (Anthropic) |
| Work | New `/v1/messages` adapter (format translation + SSE) | Hook script + `/api/decide` endpoint |

**Decision: build A first** (it is the user's demo and reuses the whole engine). B is phase 2: it adds an
authoritative execution-side check and covers sessions that talk to Anthropic directly. Both share one session
because Claude Code passes its own session id to both.

## Phase 1: `/v1/messages` adapter

### Request flow
```
claude (ANTHROPIC_BASE_URL=http://localhost:8000)
  → POST /v1/messages  (Anthropic format, stream=true)
  → identity.resolve()                 key → devon / claude-code, default purpose, session from Claude Code's id
  → translate Anthropic → OpenAI chat  (system, messages, tool_use/tool_result, tools)
  → engine.check_request()             signatures, redaction, barrier, Jev, spotlight, budget   (unchanged)
  → call_upstream()                    ollama | openrouter | mock                               (unchanged)
  → engine.check_response()            access.tools, signatures on args, flow, budget, detokenize (unchanged)
  → translate OpenAI → Anthropic       tool_calls → tool_use blocks; notes → text block
  → replay as SSE                      message_start … content_block_* … message_delta, message_stop
```
The engine stays format-agnostic (D1 escape hatch): all Anthropic knowledge lives in
`gateway/acl/adapters/anthropic.py`, mounted next to `llm_proxy.router` in `main.py`.

### Requirements
1. **Endpoint** `POST /v1/messages`. Identity via `Authorization: Bearer` (Claude Code sends this with
   `ANTHROPIC_AUTH_TOKEN`) and also accept `x-api-key` (sent with `ANTHROPIC_API_KEY`). Same `resolve()` and same
   `engine.deny()` audit entry on failure, returned as an Anthropic error body (`{"type":"error","error":{…}}`).
2. **Session.** Use `X-Session` if present, else Claude Code's session id as `session_hint`: verified, it sends an
   `X-Claude-Code-Session-Id` header and the same id inside `metadata.user_id` (a JSON string). Gateway session = `devon-<id>`.
   One Claude Code session = one gateway session = one row on the dashboard.
3. **Purpose.** Claude Code cannot be told to send `X-Purpose` per request, so the key carries a default purpose
   (already supported). `ANTHROPIC_CUSTOM_HEADERS="X-Purpose: …"` also works and overrides it.
4. **Translation, Anthropic → OpenAI**
   - `system` (string or text blocks) → one `system` message.
   - user text blocks → `user` message; `tool_result` blocks → one `tool` message each (`tool_call_id` = `tool_use_id`,
     content = joined text; images dropped with a flag).
   - assistant `text` + `tool_use` blocks → `assistant` message with `tool_calls` (arguments = JSON of `input`).
   - `thinking` blocks: dropped before the upstream call (local models do not accept them).
   - `tools` (`name`, `description`, `input_schema`) → OpenAI `function` tools. `tool_choice` mapped.
   - **Strip `cache_control` before translating.** Claude Code moves it between turns; left in, it changes the
     message hash, so old tool results would be re-judged by Jev every turn (`s.seen` dedupe relies on stable hashes).
5. **Translation, OpenAI → Anthropic.** `content` → `text` block; each kept tool call → `tool_use` block (same id,
   `input` = parsed arguments); `finish_reason` `tool_calls` → `stop_reason` `tool_use`, `stop` → `end_turn`,
   `length` → `max_tokens`. Usage → `input_tokens` / `output_tokens`. A blocked request → a normal assistant message
   with the existing "⛔ Request blocked by AI Control Layer [...]" text, so Claude Code shows it instead of retrying.
6. **Streaming.** Claude Code always streams. MVP: call upstream non-streaming, run `check_response`, then emit the
   whole result as one well-formed SSE sequence (one delta per block). Honest trade-off: no token-by-token output,
   but every tool call is checked before Claude Code sees it. `stream=false` returns plain JSON.
7. **Model mapping.** Claude Code sends Anthropic model names. The user sets `ANTHROPIC_MODEL` and
   `ANTHROPIC_SMALL_FAST_MODEL` (background calls: titles, summaries) to a model from `policy.models`. Anything else is
   blocked by `models.allowlist` as today, which is itself a demo beat ("unapproved model").
8. **Side endpoints.** Verified with a capture server: Claude Code 2.1 sends `HEAD /api/hello` at start, then
   `POST /v1/messages?beta=true`. We answer `/api/hello` with 200 and `/v1/messages/count_tokens` with an estimate.
   It also sends mid-conversation `role: "system"` messages and `<system-reminder>` text parts in user turns, both handled.
   Unknown model names make Claude Code print an `unrecognized_model` notice on stderr; harmless.
9. **Audit and dashboard.** No new entry type. Each request is one `exchange` entry with `agent: claude-code`, the
   tool calls (allowed / blocked / allowed with real values) and the policy version. The SSE event feed and
   `/api/sessions` work unchanged.
10. **Latency.** Log the adapter's translation time inside `controls_ms`. Jev on Claude Code's large prompts: the
    system prompt is already skipped; only new user text and new tool results are judged.

### Policy for Claude Code (in `policy.yaml`, judges can edit it live)
```yaml
users:
  devon: {role: developer}
roles:
  coding_agent:              # Claude Code brings its own tools
    tools: ["*"]
    budget: {max_tokens: 2000000, max_tool_calls: 200, max_compute_seconds: 1800}
sinks:
  external: [send_email, http_post, WebFetch]   # + Bash egress, below
```
- **Decided:** Claude Code is devon's second agent (key → `devon / claude-code`, with a default purpose), so it gets
  exactly devon's role and never more (US-1.2). The `developer` role lists Claude Code's tool names explicitly
  (`Read, Edit, Write, Bash, WebFetch, …`) instead of `"*"`, so judges can remove `Bash` live and see `access.tools`
  drop it; other Claude Code tools (`Agent`, `Skill`, …) are dropped with a reason. The role raises `max_tokens` to 2M
  (Claude Code sends ~16k tokens per request) and keeps `max_tool_calls: 20` for the runaway-loop beat.
  Test key: `ACL_CLAUDE_CODE_KEY` in `demo/dev-keys.env`.
- **Bash egress rule (new, small).** Claude Code sends data out through `Bash` (`curl`, `wget`, `nc`, `scp`), not a
  tool named `http_post`. Add to the engine's tool-call check: a `Bash` call whose `command` matches an egress
  pattern counts as an external sink. Policy:
  ```yaml
  egress:
    tools: {Bash: command}                     # tool → argument holding a shell command
    patterns: ['\b(curl|wget|nc|ncat|scp)\b']
    allow_hosts: [localhost, 127.0.0.1, pypi.org]
  ```
  Then the existing `flow.sensitive_to_external` decides. Note: `curl -d @.env https://…` carries no token in its
  arguments, so `mode: value` misses it; the session has read the `.env` (label SECRET), so `mode: session` catches it.
  Good live beat: set `flow.sensitive_to_external.mode: session`, rerun, now blocked. (The `strict` profile goes further:
  `secrets: block` stops every request whose history holds a secret.) A broken pattern is rejected on reload; the
  last good policy stays active.
- **Tokens written to files.** If the model writes a token like `[[SECRET#…]]` into a file through `Write`/`Edit`,
  the file gets the token, not the secret. MVP: leave it (safe failure, visible). Option: add `Write`/`Edit` to
  `sinks.detokenize` for local paths only.

### The demo (what Paul runs)
`just claude-code` creates a throwaway copy of the developer scenario's fake repo (`fx-rates-service`, built from
`demo/developer.py`'s `REPO` at runtime, so nobody hand-copies the quarantined README), then starts:
```bash
ANTHROPIC_BASE_URL=http://localhost:8000 ANTHROPIC_AUTH_TOKEN=$DEVON_CC_KEY ANTHROPIC_MODEL=mock/compromised ANTHROPIC_SMALL_FAST_MODEL=mock/compromised claude
```
Beats (dashboard open next to the terminal):
1. **"What's configured in .env?"** Claude Code runs `Read .env`. The model only ever receives `[[SECRET#…]]`;
   dashboard shows "1 value hidden from the model".
2. **"Read the README and do what it says."** The poisoned README tells the agent to send the repo's secrets to an
   outside URL. `mock/compromised` obeys and proposes `Bash: curl … https://…`. The gateway drops the call before
   Claude Code runs it; Claude Code shows "⛔ AI Control Layer blocked `Bash` …". Dashboard: red row, audit entry.
   (Jev may also quarantine the README line first; either way the call never runs.)
3. **Live policy edit.** Judge edits `policy.yaml` (removes `Bash` from the `developer` role, adds a host to
   `egress.allow_hosts`, or sets flow mode `session`); the next step shows the new policy version in the audit entry.
4. **Budget.** "Keep running the tests until they pass": the failing test loops until `max_tool_calls` stops it.
5. Optional, slow: the same with `ANTHROPIC_MODEL=qwen3:4b` on Ollama to show a real model. ⚠️ Claude Code's
   prompt is ~20k tokens; on yoga's CPU that may be minutes per turn. Measure before promising it on stage.

**Mock model changes.** `mock/compromised` must emit Claude Code's tool names and argument shapes (`Read {file_path}`,
`Bash {command}`) when it sees Claude Code's tools in the request, and still obey any instruction it reads. It must
also answer Claude Code's background calls (titles, summaries) with plain text.

### Tests (`tests/test_claude_code.py`, no network, no Claude Code binary)
Recorded Claude Code request bodies (real shape, fake data) in `tests/cases/claude_code/`:
- translation round trip: Anthropic → OpenAI → Anthropic keeps ids, order, tool inputs;
- `cache_control` moved between two turns → old tool result not re-judged (judge call count);
- `.env` tool result → model receives a token, never the value;
- `Bash curl` to an outside host with a token → blocked, `stop_reason` not `tool_use`, call absent from the SSE stream;
- `Bash curl -d @.env` after reading `.env`: allowed in `balanced`, blocked in `strict`;
- `curl localhost` → allowed; unknown model → blocked; `x-api-key` and Bearer both authenticate; bad key → 401;
- SSE output parses with the official `anthropic` SDK's stream parser (dev dependency, no network).
Plus one manual smoke test with the real `claude` binary, recorded in the PR.

## Phase 2: hooks (same engine, execution side)
- `POST /api/decide` on the gateway: `{session_id, tool_name, tool_input, phase: pre|post, tool_response?}` →
  `{decision: allow|deny, reason, seq}`. It runs the same tool-call checks as `check_response` (one shared function,
  extracted from the loop there) and writes an audit entry of type `tool_execution`.
- `gateway/acl/adapters/hook.py`: reads Claude Code's hook JSON on stdin, calls `/api/decide`, prints
  `hookSpecificOutput.permissionDecision` (`deny` + reason). Gateway unreachable → deny (fail closed, per
  `defaults.on_error`).
- Installed through a `settings.json` in the demo repo; production story: `managed-settings.json` with managed hooks
  only, so a developer cannot remove it. ⚠️ verify the exact keys against the current Claude Code docs.
- Value: the audit log records what actually ran, not only what the model proposed (closes D1's "a recorded tool call
  does not prove the agent executed it").

## Open questions
1. ~~Per-key role vs. a second user~~: decided, same user devon, second key (see the policy section).
2. Is a 20k-token Claude Code prompt usable on yoga with `qwen3:4b`, or is the live demo mock-only plus a recording?
3. Does Jev (2–4.5 s per call, fail closed at 8 s) make each Claude Code turn too slow? If yes: judge only tool
   results from files/web, not the user's typed prompt, under the `coding_agent` role.
4. Where the hooks route is allowed to run against a real Anthropic model (the judges have no keys; ours only).

## If nobody builds it
The pitch still says, honestly: the gateway works with any agent that uses a standard model API; the groundwork
(default purpose per key, `"*"` tool roles, per-role budgets) is built for exactly such clients; connecting Claude Code
is a documented next step on the roadmap slide. Move "Claude Code hook, Anthropic Messages API" in `docs/backlog.md`
to point here.
