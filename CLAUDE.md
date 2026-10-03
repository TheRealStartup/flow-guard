# AI Control Layer — HackYeah 2026 (Goldman Sachs partner task)

Brief, judging and all ideas: `~/Sync/vault/private/Life/HackYeah 2026 — AI Control Layer.md`. Read it first.
Judging: guardrail robustness 30, architecture and performance 20, reporting 20, test suite 15–20, practicality 10–15.
Judges run our tests, type ad-hoc prompts, and **edit `policy/policy.yaml` while it runs**. No paid APIs:
everything must run locally (Ollama, CPU on yoga, no GPU, 30 GB RAM).

## MVP (decided direction, details open)
Bank support agent acting on behalf of a user. One Python policy engine, thin adapters:
- `gateway/acl/adapters/mcp.py`: FastMCP proxy + middleware in front of demo MCP servers. Swaps card
  numbers for reversible tokens (`[[CARD:…1111]]`) before the model sees them; puts the real value back
  only at sinks the policy allows.
- `gateway/acl/adapters/llm.py`: OpenAI-compatible `/v1/chat/completions` → Ollama. Prompt checks, budgets,
  dropping blocked tool calls. No streaming when tools are present (MVP).
- `gateway/acl/adapters/hook.py`: Claude Code PreToolUse/PostToolUse hook → engine `/decide`.
- Data-flow labels per session (tokens = labels); PCI → external sink needs a four-eyes approval bound
  to the hash of the exact arguments.
- Detector tiers: regex + Luhn → small classifier → Ollama judge, each with its latency logged.
- Hash-chained JSONL audit log (every entry has the policy version), `/metrics`, SSE events → dashboard.
- Tests: pytest, cases as YAML in `tests/cases/` (input, user, expected decision).

Session identity across adapters: `X-Session` / `X-User` headers. Decide nothing that breaks this.

## Layout
`gateway/` Python (uv) · `dashboard/` Next.js + shadcn · `policy/` policy.yaml + signature feed ·
`demo/` fake customer DB MCP server, outbox, demo agent · `tests/` · `docs/` architecture diagram.

## Run
`direnv allow` (or `nix develop`), `just install`, `just ollama` + `just models` once, `just dev`, `just test`.

## Status (Sat 3 Oct ~16:30)
Working: model proxy (`/v1/chat/completions`), policy live reload + profiles, card/IBAN/PESEL/secret
redaction as reversible tokens, Jev injection/jailbreak check (fail closed on error), role → tools,
data-flow block to external sinks, budgets (tokens/$/compute/tool calls), signature feed, hash-chained
audit log, `/api/metrics|events|audit/verify|audit/export`. `just test`: 44 tests, ~2 s, no network.
`mock/compromised` is a scripted model that obeys injections, for the demo and the tests.
Not yet: dashboard page, architecture diagram, approvals, MCP gateway, streaming.
Known: Jev measured 2–4.5 s per call on Sat (advertised 70–500 ms), timeout 8 s.
