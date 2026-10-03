# Goldman Sachs context for the pitch

Compiled 2026-10-03 by the "Goldman Sachs and AI" research session. **Ranked cases, peers, incidents, frameworks: [goldman-cases.md](goldman-cases.md).**
Correction: Goldman is a FINOS founding member and supports FINOS Common Controls for AI Services, but is **not** a maintainer of the FINOS AI Governance Framework. **[WEB]** = only search snippets were read, not the
full articles. **[KNOW]** = from model knowledge, with a primary-source URL, not re-checked. **Open each link and check
the exact wording before quoting anything on a slide.**

## How Goldman runs AI today
- **GS AI Assistant**, firmwide since 2025 (pilot with ~10k of ~46.5k staff). Employees pick between several approved models
  (GPT-4o, Gemini, Claude) per task: a **central multi-model layer**, in effect a gateway. Related tools: Banker Copilot,
  Translate AI, Legend AI. [WEB] [Fox Business](https://www.foxbusiness.com/technology/goldman-sachs-announces-firmwide-launch-ai-assistant),
  [Benzinga](https://www.benzinga.com/markets/tech/25/07/46316968/goldman-sachs-gave-every-employee-an-ai-assistant-heres-what-it-does)
- **AI systems don't get direct access to data sources.** They go through the bank's data platform, which enforces access
  control. This is our "agent inherits the user's entitlements" idea (US-1.2). [WEB, source article UNVERIFIED]
  [Yahoo Finance](https://finance.yahoo.com/news/why-goldman-sachs-tech-chief-envisions-a-future-of-humans-managing-ai-agents-123517127.html)
- **Devin** coding agents (Jul 2025), "hundreds, potentially thousands" alongside 12k+ developers. A "hybrid workforce";
  humans review the output before deployment. [WEB] [TechCrunch](https://techcrunch.com/2025/07/11/goldman-sachs-is-testing-viral-ai-agent-devin-as-a-new-employee/)
- **Claude agents** (reported Feb 2026) for trade accounting and **client onboarding / KYC**: they read documents, extract
  entities and trigger compliance checks, i.e. they handle exactly the client PII we redact. [WEB]
  [CNBC](https://www.cnbc.com/2026/02/06/anthropic-goldman-sachs-ai-model-accounting.html),
  [American Banker](https://www.americanbanker.com/news/goldman-equips-ai-agents-do-trade-accounting-onboarding)
- **OneGS 3.0** (Oct 2025): operations redesigned around AI (onboarding, lending, regulatory reporting, ...), with "data
  platforms & model ops" as core infrastructure. [WEB] [Banking Dive](https://www.bankingdive.com/news/goldman-sachs-limited-cuts-ai-acquisition-industry-ventures-965-million-solomon-q3-earnings/802869/)
- The CIO says not to rule out open-weight models (Sep 2026), which supports a vendor-agnostic gateway. [WEB, headline only]
  [Axios](https://www.axios.com/2026/09/08/goldman-cio-dont-rule-out-open-models)

## How they frame agent security
- CIO Marco Argenti: **zero trust** (assume the model may be compromised) + **defense in depth**, in four layers:
  (1) model testing and certification, (2) secure inference environments, (3) **tightly monitored agent permissions**,
  (4) **controlled access to enterprise data**. **We are layers 3 and 4.** Map our features onto these on a slide.
  [WEB, exact source UNVERIFIED] Yahoo link above.
- Goldman says it is still working out which extra controls agents need: an open problem in their own words. [WEB]
- Agents are framed as employees who need managers and supervision → per-agent identity, budgets, audit trail. [WEB]

## Risks they have named
- FY2025 10-K: AI integration may fail; changing laws may raise compliance cost; AI may make cyberattacks more frequent and
  more severe. [WEB] [10-K](https://www.sec.gov/Archives/edgar/data/886982/000088698226000091/gs-20251231.htm)
- A partner warns of a "huge danger" in AI replacing bankers' judgement (Aug 2026) → human in the loop. [WEB, headline]
  [CNBC](https://www.cnbc.com/2026/08/24/goldman-sachs-ai-partner-danger-skills.html)

## Regulation, mapped to our features [KNOW]
| Rule | What it requires | Our feature |
|---|---|---|
| Exchange Act §15(g), FINRA 3110 | Written policies against misuse of MNPI; supervision | Information barriers (US-1.3) |
| SR 11-7 | Validate, document and monitor models | One place to log and measure model use |
| SEC 17a-4 (2022 amendment) | An "audit-trail" alternative to write-once storage: a complete, time-stamped history of changes | Hash-chained audit log (US-9.1) |
| FINRA Notice 24-09 | Existing rules apply to gen-AI | Supervision + records for every call |
| EU AI Act Art. 12 / 14 | Logging, human oversight for high-risk systems (GS Bank Europe SE) | Audit log, approvals (US-7.4). The Digital Omnibus (in force 2026-07-27, snippet) moved high-risk obligations to 2027-12-02. |
| DORA | ICT third-party / concentration risk | Several model vendors behind one policy |

Links: [15 U.S.C. 78o](https://www.law.cornell.edu/uscode/text/15/78o) ·
[SR 11-7](https://www.federalreserve.gov/supervisionreg/srletters/sr1107.htm) ·
[17a-4 2022](https://www.sec.gov/rules/final/2022/34-96034.pdf) ·
[FINRA 24-09](https://www.finra.org/rules-guidance/notices/24-09) ·
[EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) · [DORA](https://eur-lex.europa.eu/eli/reg/2022/2554/oj)

## Pitch angle
Goldman already runs a central multi-model assistant and already sends AI data access through a platform that enforces
access control. Its CIO has published a zero-trust, defense-in-depth model for agents and says the controls are still
being worked out. **We are the "monitored agent permissions + controlled data access" layer for agents:** barriers
enforced on every call, client data never leaving in plaintext, a 17a-4-style audit trail. It extends what they already
do; it doesn't replace it.
