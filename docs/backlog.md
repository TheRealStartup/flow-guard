# Backlog (after the MVP stands)

Ideas we like but are not building yet. Details and reasoning: the team's notes (Paul's vault, "HackYeah 2026 — AI Control Layer").

## Detection and feeds
- **Fingerprints of known secrets (Exact Data Match).**
  - HMAC fingerprints of our real secrets, pushed by the secret store on rotation. A hit means block + alert + rotate.
  - Demo: a DB password no pattern catches.
  - Same mechanism for real customer card numbers and IBANs (a real customer's card versus any number that passes the Luhn check).
- **Exfiltration destinations feed:** webhook.site, ngrok, paste sites, newly registered domains → the data-flow rule gets a "where to" dimension.
- **Hashes of known malicious models and packages** (supply chain).
- **Known jailbreak prompts**, matched by embedding similarity, as a fast check before Jev.
- **Signed feeds:** check the signature before loading `signatures.json` and the other feeds.
- **Fast local classifier** (DeBERTa prompt injection, ~50 ms) in front of Jev.
- **Canary tokens:** fake cards and credentials planted in the data; seen outbound = certain leak.
- **Pinned MCP tool descriptions:** block if a description changes after approval.

## Workflow
- **Approvals with a second person**, bound to a hash of the exact arguments (D2).
- **Feedback claims** ("this block was wrong") → counted for business impact; confirmed false alarms become test cases.
- **Emergency override** ("break glass") with a reason and a second approver.
- **Policy replay:** run a new rule against past traffic before switching it on.
- **Risk score per session/user**, graduated responses, kill switch.

## Adapters (revisit D1)
- MCP gateway (FastMCP), Claude Code hook, Anthropic Messages API and OpenAI Responses API, streaming.

## Reporting
- Dashboard views beyond the MVP (see the mockups), OWASP mapping per control, CSV export, anchoring the audit hash publicly.

## Research
- SMT / Cedar policy analysis: "can card data reach an external destination without approval?"
