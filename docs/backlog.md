# Backlog: parked ideas

Ideas we like but are not building now. **Tasks, owners and status live on the board**:
https://github.com/orgs/TheRealStartup/projects/1. User stories and requirements live in the team's central
Google Doc. Open decisions: `docs/decisions.md`. When an idea here gets picked up, it becomes a board card and
leaves this file.

## If time (after the MVP stands)
- **Approvals with a second person** (US-7.4, D2): bound to a hash of the exact arguments, so the action can't change after approval.
- **Legal privilege and HR data** (US-2.2, US-2.5): one extra Jev `choice` question in the same call.
- **Region routing** (US-5.2): OpenRouter provider pinning per model in `policy.yaml`.
- **Request access** (US-8.3), merged with Paul's **feedback claims**: "this block was wrong" → counted for business impact; confirmed false alarms become test cases.
- **Emergency override** ("break glass"): a written reason, a second approver, a flagged audit entry.

## Demo scenarios (parked, Paul Sat ~18:50)
- **Inbox scenario:** an inbox tool with a deal email (MNPI), an email with client personal data, and a poisoned email. Covers US-1.1 (masking in email content) and US-1.3 (information barriers through email: a public-side analyst must not see a private-side deal, and the denial must not reveal that the deal exists).

## Detection and feeds
- **Fingerprints of known secrets (Exact Data Match).** HMAC fingerprints (with a key the gateway holds, never a plain hash) of our real secrets, pushed by the secret store on rotation. A hit means block + alert + rotate. Same mechanism for real customer card numbers and IBANs: a real customer's card versus any number that passes the Luhn check. Demo: a DB password no pattern catches.
- **Exfiltration destinations feed:** webhook.site, ngrok, paste sites, newly registered domains → the data-flow rule gets a "where to" dimension.
- **Hashes of known malicious models and packages** (supply chain).
- **Known jailbreak prompts**, matched by embedding similarity, as a fast check before Jev.
- **Signed feeds:** check the signature before loading `signatures.json` and the other feeds.
- **Canary tokens:** fake cards and credentials planted in the data; seen outbound = certain leak.
- **Pinned MCP tool descriptions:** block if a description changes after approval.
- **Risk score per session and user**, graduated responses (log → approval → slow down → stop), kill switch.

## Adapters (revisit D1)
MCP gateway (FastMCP), Claude Code hook, Anthropic Messages API, OpenAI Responses API, streaming.

## Reporting
OWASP mapping per control, CSV export, anchoring the audit hash publicly (daily timestamp), policy replay (run a new rule against past traffic before switching it on).

## Roadmap slide (not building this weekend)
Epic 4 fact-checking · US-1.4 attachments · US-1.5 roster sync · US-8.2 time-bound access ·
US-7.2 delegation only narrows · US-7.3 request signing beyond per-agent keys · SMT / Cedar policy analysis
("can card data reach an external destination without approval?").
