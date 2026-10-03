# Backlog (from the team's user stories, reviewed Sat 15:30)

Full reasoning: the vault note "HackYeah 2026 — AI Control Layer", section "User stories review".

## MVP, tonight
- [ ] **US-1.2** Deny requests without a user identity (no `anonymous` fallback). Per-agent API key; `purpose` field.
- [ ] **US-1.3** Information barriers: restricted list (tickers, deal codenames) + public/private side per user.
      The denial must not confirm the deal exists ("Some results are outside your access").
- [ ] **US-1.1 / US-2.1** Per-field masking mode: full / partial (`****4521`) / reversible token. Mark every
      removed span `[WITHHELD: reason]`, never omit silently.
- [ ] **US-7.1** Wrap tool results as labelled untrusted data (spotlighting), in addition to the Jev check.
- [ ] **US-9.2** Dashboard (Reporting = 20% of the score).
- [ ] Demo world: inbox tool with a deal email (MNPI), a client-PII email, a poisoned email; a public-side
      analyst and a private-side banker.
- [x] US-9.1 tamper-evident audit · US-7.1 Jev quarantine · budgets · signatures · allowed models · live reload · tests

## Write stories for (brief requires them; no story yet)
Budgets / runaway loops · attack signatures / supply chain · allowed models · admin edits the policy live ·
fail closed · performance telemetry · test suite as a deliverable · **developer persona** (Claude Code / Codex:
secrets redacted, no slowdown).

## Open conflict
US-1.1 "overhead < 300 ms p95" vs Jev measured at 2–4.5 s per call. Proposal: p95 < 300 ms for the
rule-based path; the AI check only on new untrusted content, cached; or a fast local classifier in front.

## If time
US-7.4 approvals (D2) · US-2.2 privilege + US-2.5 HR via one Jev `choice` question in the same call ·
US-5.2 region routing (OpenRouter provider pinning) · US-8.3 request access (merge with feedback claims).

## Roadmap slide (not building)
Epic 4 fact-checking · US-1.4 attachments · US-1.5 roster sync · US-8.2 time-bound access ·
US-7.2 delegation narrows · US-7.3 request signing beyond per-agent keys · canary tokens · policy replay · SMT/Cedar.
