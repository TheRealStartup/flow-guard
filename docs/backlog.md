# Backlog (from the team's user stories, reviewed Sat 15:30)

## Team / admin, now
- [ ] **Agree on the demo world** (customer DB + inbox? public-side analyst + private-side banker?) before the dashboard is designed around it.
- [ ] **Mentor talk:** (1) deadline: the rules say the task runs "11:00 PM Oct 3" to "11:00 PM Oct 4", the event schedule ends coding Sun 11:00;
      plan for 11:00 AM until confirmed; (2) do judges run our tests with our keys? (3) which weights are correct (tests 15 or 20, practicality 15 or 10)?
- [ ] **HackTribe:** register the team, project title, members; check whether there is a draft submission (2025 had one at Sat 20:00).
      Final: description + PDF of at most 10 slides, English or Polish.

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

## Open conflict: the 300 ms in US-1.1
US-1.1 "overhead < 300 ms p95" vs Jev. Measured 15:40 (curl breakdown, venue wifi):
- Jev total 0.59–0.77 s on a new connection: DNS 0.26–0.41 s (slow venue DNS), TCP+TLS ~0.3 s, server work ~0.3–0.4 s.
- An invalid request (no model work) takes 0.34 s, and the Cloudflare baseline 0.24 s, so the venue network costs ~0.1–0.2 s per round trip.
- The 2–4.5 s seen at 14:45 was not reproduced; probably a load spike at TypeSafe or on the wifi.
- With the reused connection (in code since 15:00) expect ~0.3–0.45 s per Jev call; still above 300 ms p95.
Proposal: the target applies to the rule-based path (single-digit ms); report AI-check latency separately
(`/api/metrics` → `per_control_avg`); run it only on new untrusted content and cache it; a local classifier first if we must hit 300 ms.

## If time
US-7.4 approvals (D2) · US-2.2 privilege + US-2.5 HR via one Jev `choice` question in the same call ·
US-5.2 region routing (OpenRouter provider pinning) · US-8.3 request access (merge with feedback claims).

## Roadmap slide (not building)
Epic 4 fact-checking · US-1.4 attachments · US-1.5 roster sync · US-8.2 time-bound access ·
US-7.2 delegation narrows · US-7.3 request signing beyond per-agent keys · canary tokens · policy replay · SMT/Cedar.
