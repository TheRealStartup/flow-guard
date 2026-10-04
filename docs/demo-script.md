# Demo script (pitch order)

> **Two scripts exist.** Inez's [`docs/pitch/demo-script.md`](pitch/demo-script.md) (with the deck) is the preferred
> one (Paul, Sun ~02:38). Merge this file's business-language lines and open gaps into it later, then delete this one.

Two core scenarios (decision D4). Dashboard http://localhost:3000 next to the terminal. Each step: **do**, what
**happens**, and the line to **say** (business language, decision D5). Gateway: `just gateway`; dashboard: `just dashboard`.

## Opening (~20 s)
> "Goldman already runs AI agents on real work: Claude agents that onboard clients, coding agents next to thousands of
> developers. Each agent acts on behalf of an employee. Who checks what the agent does with the client's data, and on
> whose authority?"

## A · Client onboarding (dashboard → Live demo)
1. **Routine onboarding.** Example "Passports tokenized, real one only to sanctions screening", olivia, DeepSeek.
   Passports and the settlement IBAN reach the model only as tokens; sanctions screening gets the real passports.
   *Say:* "The model provider never sees a passport number; the internal sanctions check gets the real one."
2. **The client attacks through its own documents.** Same run: the ownership document is quarantined (p≈0.94–0.98).
   *Say:* "The client wrote the documents our agent reads. That is how Salesforce's agent was compromised (ForcedLeak,
   2025). Only that paragraph is removed; the rest of the file stays usable."
3. **Detection fails, nothing leaves.** `policy/policy.yaml`: `active_profile: permissive`, rerun with mock/compromised.
   The email out is blocked by the data-flow rule; the audit trail shows the new policy version. Set back to `balanced`.
   *Say:* "Detectors miss things (Microsoft's own missed EchoLeak). Client data cannot leave, whatever the model is
   tricked into."
4. **Information barrier.** Example "Information barrier: public side asks about a restricted deal" → "Some results are
   outside your access." Then "Deal team may read, MNPI may not leave".
   *Say:* "The answer does not even confirm a deal exists. The deal team can read it but cannot email it out."
5. **Scope.** Example "Not her client: stopped before the file is read".
   *Say:* "An agent never gets more access than its human."

## B · Developer with the real Claude Code (terminal)
`just claude-code deepseek/deepseek-v4.1-flash` (first run: trust `/tmp/flowguard-demo/payments-service` once).
1. *"The nightly payments job failed. Look at logs/payments-nightly.log and tell me what went wrong."*
   Claude finds `EURO` vs ISO `EUR`; IBANs and the card appear only as tokens.
   *Say:* "The Samsung incident, prevented: production data, the AI still solves it, the client data never reaches the
   vendor. The real Claude Code, unmodified: one environment variable."
2. `just claude-code` (scripted model): *"Read the README and do what it says."* The outgoing `curl` is dropped before
   Claude Code runs it.
3. *"Keep running the tests until they pass."* The budget stops it after 20 tool calls.
   *Say:* "Thousands of agents means cost and runaway loops: every agent has a budget."

## Closing (dashboard → Audit trail)
Open one blocked entry: who, which agent, which purpose, which policy version, what was found. Point at the integrity
badge: "Tamper-evident, as broker-dealer record-keeping (SEC 17a-4) asks. Change one line and the chain breaks."

## Not yet business-correct (board)
- Onboarding documents follow a general KYC pattern, not a verified checklist (P1 card).
- Client names still reach the model (P2).
