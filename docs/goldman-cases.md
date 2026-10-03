# Where an AI Control Layer matters most at Goldman Sachs

Research done 2026-10-03 (three parallel searches: Goldman itself, peers and incidents, frameworks). Tags: **V** = page read,
**S** = search snippet only, **inferred** = our reasoning, no direct source. Check the exact wording before putting a quote on a slide.
Background facts: [goldman-context.md](goldman-context.md).

## The one-line pitch
Goldman's CIO Marco Argenti describes four layers of AI security: model testing, secure inference, **"tightly monitored agent
permissions"** and **controlled access to enterprise data** (Axios 2026-09-08, via a secondary write-up **V**). **We are layers 3 and 4 as a
product.** Goldman already "scrubs" personal data before it reaches a model and has "other controls [that] govern entitlements"
(American Banker ~2025-02-20 **V**). We extend that to agents, which act on behalf of an employee and call tools.

## Ranked cases

### 1. Client onboarding / KYC agents (strongest, and the recommended main demo)
- **Real at Goldman:**
  - Anthropic engineers were embedded for 6 months to build Claude agents for client vetting/onboarding and trade accounting (CNBC 2026-02-06 **S**).
  - The agents extract entities and work out ownership, paired with rules engines and human review (American Banker 2026-02 **V**).
  - Client onboarding is one of the first five processes in the OneGS 3.0 memo (Oct 2025, secondary **V**).
- **What goes wrong without controls:**
  - Passports, beneficial-owner details and account numbers flow to third-party models.
  - A document *submitted by the client* carries hidden instructions.
  - The agent then emails or uploads the file somewhere it shouldn't.
- **Closest real incident: ForcedLeak, Salesforce Agentforce (CVSS 9.4, 2025-09 S).**
  - An injection in a public web-to-lead form (client-submitted content!) made the agent exfiltrate CRM data.
  - The exfiltration went to an allowlisted domain that had expired and was re-registered for $5.
- **Microsoft's injection detector missed EchoLeak (CVE-2025-32711, V).** Detection alone is not enough, so we also block the data flow.
- **Our features:**
  - reversible tokens (the real passport number reaches only the internal sanctions-screening tool);
  - injection check on documents;
  - data-flow block to external sinks;
  - per-user entitlements;
  - hash-chained audit log.
- **Goldman's own risk wording:** 10-K FY2025 (**V**): AI may "result in the release of private, confidential or proprietary information".
- **Frameworks:**
  - FINOS AIR-RC-001 / MI-2 (data filtering);
  - FINOS AIR-SEC-010 (prompt injection);
  - OWASP LLM01 / LLM02;
  - FINRA 2026 "Data Sensitivity".

### 2. Bankers' assistants and information barriers (MNPI)
- **Real at Goldman:**
  - Banker Copilot exists (**S**).
  - Argenti: "I'm completing a task on behalf of a Goldman employee" (PYMNTS 2025-01-21 **V**).
  - The Fed fined Goldman $36.3M in 2016 over leaked confidential supervisory information (**S**): a real barrier failure.
- **What goes wrong:** an agent working for a private-side banker carries deal data into public-side or research output.
- **Similar incidents:** Slack AI (2024, **V**) leaked private-channel data through retrieval. No public agent-MNPI incident is known (**inferred** risk).
- **Our features:** information barriers (restricted list + side per user) and a denial that doesn't confirm the deal exists.
- **Frameworks:** Exchange Act §15(g); FINOS MI-16 "Preserving Source Data Access Controls"; FINRA 2026 "Scope and Authority".

### 3. Coding agents at scale (Devin and others)
- **Real at Goldman:**
  - Devin pilot: "hundreds, potentially thousands" of instances next to ~12k developers (TechCrunch 2025-07-11 **S**).
  - A job posting describes the GS AI Platform as a "secure, multi-model backbone for autonomous agents" with MCP and A2A (**S**).
- **What goes wrong:** malicious pickled models (~100 found on Hugging Face, 2024, **V**), `curl | bash`, poisoned MCP tools (GitHub MCP 2025 **S**), secrets leaking from `.env`, an agent deleting production data (Replit 2025 **V**).
- **Our features:**
  - attack signatures (the brief's "historical attacks" requirement);
  - secret redaction;
  - budgets: thousands of agents means denial-of-wallet risk (FINOS MI-9, ATLAS T0034 Cost Harvesting);
  - ShadowRay showed AI compute is itself an attack target.

### 4. Trade accounting / back-office agents that *act*
- **Real at Goldman:**
  - The same Claude programme (**S**).
  - Outputs are checked against the ledger, and source attribution serves as an audit trail (American Banker **V**).
- **What goes wrong:** a wrong action repeated at high volume, with no record of which agent did what on whose behalf.
- **Argenti:** "The most dangerous thing would be if you let the agent act without human supervision" (American Banker **V**).
- **Our features:** entitlements, audit log, budgets. **Gap: approvals for high-impact actions.** This is our parked extension D2, and FINRA, OWASP ASI09 and Argenti all expect it.

### 5. Many models behind one policy (the gateway itself)
- **Real at Goldman:**
  - "plug-and-play with those models" (Fortune 2025-03-19 **V**);
  - the GS AI Assistant routes to OpenAI, Google and Meta models (**V**);
  - the CIO says not to rule out open-weight models (Axios 2026-09 **S**);
  - the 10-K speaks of third-party models "over which we may have limited visibility" (**V**).
- **Our features:** allowed models, provider pinning (OpenRouter `provider.only`), budgets, the same controls whatever the model. DORA third-party concentration risk.

## What peers do (normal practice 2025–26)
- **One governed internal front door** for all models:
  - JPMorgan LLM Suite (**V**);
  - BNY Eliza "under one governed roof" (**S**);
  - Goldman GS AI Platform (**V**).
- **Deutsche Bank DB Lumina publishes the closest control stack to ours** (**V**, Google Cloud blog): guardrails, stored prompt logs, central entitlements ("dbEntitlements"), "controlled access to confidential data with audit trails", human review.
- **BNY "digital employees"** with logins and human managers (**S**). This matches our per-agent keys mapped to (user, agent).
- **JPMorgan CISO Pat Opet's open letter (2025-04-26, V):** integrations have "dismantled essential boundaries"; it names AI agents.
- **SEC/CFTC off-channel fines:** about $2B across Wall Street, **Goldman $125M** (2022, **S**). Unrecorded business communication is a nine-figure problem, and agent actions will be judged the same way. This is the argument for the audit log.

## Frameworks to cite (most impressive first)
1. **FINOS AI Governance Framework v2 (2025-10-20, V).** Written by banks (Morgan Stanley, Citi, NatWest, RBC...).
   - Goldman supports FINOS *Common Controls for AI Services* (2025-06-24, **V**) but is **not** a maintainer of the framework. Don't overclaim.
   - Our mapping:
     - MI-1/MI-2 → redaction;
     - MI-12/MI-16 → entitlements, barriers;
     - MI-17 AI firewall → the gateway;
     - MI-18 agent least privilege → keys + roles;
     - MI-9 denial-of-wallet → budgets;
     - MI-21 agent decision audit → audit log.
2. **FINRA 2026 Oversight Report, GenAI section (2025-12-09, V).**
   - Agent risks it names: autonomy, scope and authority, auditability, data sensitivity.
   - It also expects stored prompt/output logs and tracked model versions.
3. **OWASP GenAI LLM Top 10 2026 (2026-08-04, V for the date; item order via CSA).**
   - LLM03 Excessive Agency moved up.
   - Also the OWASP Agentic Top 10 (2025-12, ASI01–10, **S**).
   - The OWASP *Agent Control Standard* v0.1 ("guardian agent" enforcement points) describes our architecture; we could claim alignment.
- Also: MITRE ATLAS AML.T0051 (prompt injection), T0086 (exfiltration via agent tool calls), T0034 (cost harvesting); mitigation M0030 "Restrict Agent Tool Invocation on Untrusted Data" = our data-flow rule.
- **EU AI Act:** the Digital Omnibus (in force 2026-07-27, **S**) moved the high-risk obligations from 2026-08-02 to **2027-12-02**.

## Gaps the frameworks expect (candidate work, highest value first)
1. **Human approval for high-impact actions** (FINRA, ASI09, Argenti's quote). Our D2 extension; now strongly justified.
2. **Model version in every audit entry** (FINRA). Cheap; add it.
3. **Pinned MCP / tool descriptions** (FINOS MI-20, ASI04). Already a parked idea.
4. **Delegation that only narrows between agents, with token exchange** (ASI03, OpenID agentic identity paper 2025-10). Our per-agent keys are a first step.
5. **Output-side checks** (LLM10:2026, Hidden Context Exposure LLM08:2026).

## Recommendation for the demo
- **Main story = case 1 (onboarding).** Strongest Goldman evidence, ForcedLeak as the real-world twin, and it reuses the engine we have.
- **Case 3 (coding agent)** shows the brief's "historical attacks".
- **Case 2 (barriers)** is the Goldman-specific policy example.
- **Case 4** justifies building approvals next.
