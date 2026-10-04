# Flow Guard: pitch and demo script (v2, 3-minute pitch)

Deck: [flow-guard-demo-v2.pptx](flow-guard-demo-v2.pptx), **10 slides, 3 minutes**, speaker notes on every slide, no live demo inside the pitch
(the old 13-slide [flow-guard-demo.pptx](flow-guard-demo.pptx) is kept for reference). The demo happens at the table during judging, when the judges type their
own prompts and edit `policy/policy.yaml` anyway; that part is below, after the pitch.

**How 10 slides fit in 3 minutes:** the slides are pictures, not text. Four of them carry the talking (2 the story,
5 the idea, 6 the architecture, 7 the numbers); the others are glance slides of 5 to 15 seconds with one spoken line
each, and slide 10 is the Q&A backdrop, not spoken. Rule for every
slide: one picture, one headline, at most about 12 more words on the slide. If it needs a paragraph, it's a speaker note.

| # | Slide | Time | Picture | Scores on |
|---|---|---|---|---|
| 1 | Flow Guard | 5 s | `C01X00T47` turning into `[[PASSPORT#7c21e4]]` | |
| 2 | Monday, 09:04 | 25 s | four-panel strip | the hook |
| 3 | This already happens | 10 s | three big numbers | practicality |
| 4 | Goldman's map: we build layers 3 and 4 | 10 s | four-layer stack | practicality |
| 5 | Don't trust the agent. Trust the flow. | 30 s | token flow diagram | guardrail robustness |
| 6 | Every action crosses three checkpoints | 30 s | architecture diagram: three checkpoints + what sits underneath | architecture and performance |
| 7 | Measured, not claimed | 30 s | two big judge numbers (97.5% caught, 0% false alarms) + three tiles | robustness, test suite |
| 8 | Every decision on the record | 15 s | audit entry with callouts + regulation row | reporting |
| 9 | Monday, 09:04, again | 20 s | four outcome cards | the close |
| 10 | Limits today and what comes next | Q&A | limits left, next steps right | credibility |

About 400 spoken words. Rehearse with a timer: if you run over, cut the lines marked *(cut first)*, never slide 5.
Roles: **Presenter** (talks) and **Driver** (clicks; at the table, drives the demo).

---

## The one idea the jury must leave with

> **Don't trust the agent. Trust the flow.**
> Others try to catch the bad prompt. We assume the model is fooled, and make sure a fooled model has nothing to leak.

Every slide, every demo beat, every answer in Q&A comes back to this sentence. If you are lost, say it again.

## Before you go on stage (T-15 min)

- [ ] `just gateway` and `just dashboard` (two terminals; Docker works too: `docker compose up --build -d --wait`), then open
      http://localhost:3000/overview and `/audit` side by side, ready for the table demo.
- [ ] `just demo-data deepseek/deepseek-v4.1-flash` once, so the dashboard is not empty and you have a **recorded backup** of every scenario.
- [ ] Run `just test` and check the test count on slides 6 and 7 ("450+"). On main at 2405b5c: 457 passed, 1 failed
      (`test_timeseries_counts_this_minute`, looks like a minute-boundary flake), 1 skipped, in about 2 min 20 s, so
      don't say "under a minute".
- [ ] Check every number on slides 3 and 7 against `docs/goldman-cases.md` and the benchmark results, and the CIO line on
      slide 4 against `docs/goldman-context.md`. Never quote a line you have not read at the source.
      Slide 7's judge numbers are Jev at the deployed threshold 0.40 from the judge benchmark of Sun 4 Oct: 97.5% of 519
      LLMail attacks that stole data, 0.0% of 993 banking77 customer questions. **That table is not committed yet**;
      commit it (e.g. to `docs/benchmarks.md`) and point slide 7's source line at it. The 0% is for banking77 only:
      on 982 Enron business emails it is 0.4%, on NotInject 2.3%. Say so if asked.
- [ ] **Internet required for the table demo.** The model (DeepSeek via OpenRouter) and the injection judge (Jev,
      api.typesafe.ai) are outside services, and the judge fails closed: without a connection every request with new tool
      data is blocked. Check `curl -s localhost:8000/api/health` shows `"judge":"jev"` and run Act 1 once. Offline
      fallback: restart the gateway with `ACL_JUDGE=demo` (built-in offline judge) and use the recorded runs.

---

## The pitch (3:00)

**Slide 1: Flow Guard** *(5 s)*
On the slide: name, tagline "Your agents can act. We decide what flows.", and the passport number becoming a token.
> "Flow Guard. Here's Olivia's Monday."

**Slide 2: Monday, 09:04** *(25 s)*
On the slide: a four-panel strip, one icon and three words per panel: *Olivia asks* → *document hides an order* →
*agent finds the deal* → *email to a hedge fund*. Bottom line: "Nobody hacked the bank."
> "Olivia, an onboarding analyst, asks her AI agent to prepare the file for a new hedge-fund client.
> The client's document hides one sentence, written for the agent.
> The agent obeys: it searches the deal room, finds an acquisition nobody has announced, and emails it to a fund that can trade on it.
> Nobody hacked the bank. The agent did its job, for the wrong boss."

**Slide 3: This already happens** *(10 s)*
On the slide: three big numbers, each with a logo-free label: **9.4** ForcedLeak, Salesforce agent · **0 clicks** EchoLeak,
Microsoft 365 Copilot · **$36.3M** Fed fine for a barrier leak. Sources in small print.
> "This already happens. An outsider's web form, one email with zero clicks, and barrier leaks that cost tens of millions." *(cut first: everything after "happens")*

**Slide 4: Goldman's map: we build layers 3 and 4** *(10 s)*
On the slide: a stack of four layers (model testing · secure inference · **agent permissions** · **data access**), the
top two highlighted with the Flow Guard mark. Small line: "Zero trust: assume the model may be compromised."
> "Your CIO says: assume the model may be compromised. Layers one and two protect the model. We build three and four:
> what agents may do, and what data they may touch."

**Slide 5: Don't trust the agent. Trust the flow.** *(30 s)*. **The slide that must land.** Trace the arrows with your hand.
On the slide: client document `C01X00T47` → the model sees `[[PASSPORT#7c21e4]]` → two exits: `screen_sanctions` gets the
real value (green) · `send_email` dropped and logged (red). Bottom line: "A fooled model has nothing to leak."
> "So we don't bet on catching the attack. The passport never reaches the model; it sees a token.
> When the agent calls the sanctions check, we put the real number back. When the same token heads for an email, the
> call is dropped and logged. **A fooled model has nothing to leak.**"

**Slide 6: Every action crosses three checkpoints** *(30 s)*. Follow the request left to right, then point at the bottom row.
On the slide: AI agent (one API key per user + agent, a stated purpose) → **1 Before the model** (who and why, values →
tokens, injected text quarantined, data-class limit per model; "the model sees `[[CARD#3f2a1b ****1111]]`") → approved model
(sees tokens only) → **2 Before the agent acts** (role → tools, own clients only, information barrier, budgets, signatures)
→ bank systems, and **3 Before data leaves** (client data never to email or web; real values only to approved tools).
A dashed loop: tool results come back through checkpoint 1. Underneath: policy as code · injection judge · evidence · fail closed.
> "Every agent action crosses three checkpoints. Before the model: who is asking and why, and sensitive values become tokens.
> Before the agent acts: its role, only its user's clients, the information barrier, budgets.
> Before data leaves: client data never goes to email or the web.
> Underneath: one YAML policy, an injection judge, a hash-chained log, and every check fails closed." *(cut first: the last sentence)*

**Slide 7: Measured, not claimed** *(30 s)*. Two numbers, together: left card, then right card.
On the slide: **97.5%** of real data-stealing attacks caught by the AI judge (tested on 519 real attacks that stole data,
Microsoft LLMail-Inject) **+** **0%** of harmless prompts flagged at the same setting (0 of 993 real bank customer questions,
banking77). Below: **4/4 → 0/4** client-data leaks, even when the judge misses · **450+** tests · **<0.02 ms** per check.
> "We measured the AI judge on real attacks. Of 519 real attacks that actually stole data, it caught 97.5%.
> And at the same setting it flagged none of 993 real bank customer questions. Both numbers matter: a judge that flags
> everything catches everything.
> And when the judge does miss, the flow rule still holds: four leaks out of four without Flow Guard, zero with it." *(cut first: the last sentence)*

**Slide 8: Every decision on the record** *(15 s)*
On the slide: an audit entry (real field names: user, agent, purpose, policy version, decisions, hash chain) with three
callouts: *who · agent · why*, *which policy decided*, *tamper-evident*. Small row: FINRA 3110 · SEC 17a-4 · EU AI Act Art. 12 · DORA.
> "Every decision is a hash-chained audit entry: who, which agent, why, and which policy version decided.
> Compliance gets evidence, not a promise."

**Slide 9: Monday, 09:04, again** *(20 s)*. Same Olivia, different ending. Slowly.
On the slide: four outcome cards (green check or red stop). Big line: "Don't trust the agent. Trust the flow."
Small: "The policy file is open. Try to break it."
> "Monday, 9:04, again. The passport reached the sanctions check, nowhere else. The hidden sentence was quarantined.
> The deal stayed behind the wall.
> **Don't trust the agent. Trust the flow.** The policy file is open. Try to break it."

**Stop talking.** When the questions start, advance to **slide 10: Limits today and what comes next** and leave it up.
Limits are not in the 3 minutes; we say them plainly when asked: tools run in the agent, so an allowed call is a
permission, not proof it ran; calls that bypass the gateway are not seen; the reporting API and policy edits are
localhost only; the token vault and session state reset on restart (the audit log persists). Next: four-eyes approvals
bound to the exact arguments, leak fingerprints, more adapters and signed requests.

---

## At the table: live demo (judging time)

Layout: terminal left, dashboard `/audit` right. Run the acts in this order; if time is short, do Act 1 and Act 4 only.
Each act shows the checkpoints on slide 6 at work: Act 1 checkpoints 1 and 3 (tokens, quarantine, flow rule) and the
scope check, Act 2 the information barrier, Act 3 budgets on the real Claude Code, Act 4 the live policy.

### Act 1 · Olivia and the poisoned document

```bash
cd gateway && uv run python ../demo/agent.py olivia "Prepare the onboarding file for client NW-2041." --scenario onboarding --model deepseek/deepseek-v4.1-flash --purpose client-onboarding
```

Point at, in order:
1. **Passports and the IBAN become tokens** (`[[PASSPORT#…]]`): "the model never saw them."
2. **`screen_sanctions` got the real passport**: "the one tool policy allows."
3. **The poisoned field is quarantined**: "Only that field. The rest of the document still works, so Olivia's job still gets done."
4. **And if the judge had missed it?** Dashboard → Policies → `injection.jev` → **Flag** (the banner shows the change,
   the audit log a new policy version). Rerun with a model we hijacked on purpose, one that obeys every instruction it
   reads (`--model mock/compromised`): the agent now tries to email the client file out, and the **flow rule drops the
   email**. Set `injection.jev` back to **Redact**.
   > "Detectors miss things; Microsoft's missed EchoLeak. Client data still cannot leave."

Then the scope check (one line, fast):

```bash
cd gateway && uv run python ../demo/agent.py olivia "Prepare the onboarding file for client AC-7730." --scenario onboarding --model deepseek/deepseek-v4.1-flash --purpose client-onboarding
```

> "Not her client. The call never runs."

### Act 2 · Marcus and the information barrier

```bash
cd gateway && uv run python ../demo/agent.py marcus "Search the deal room for Kestrel Dynamics and email a summary to marcus.home@gmail.com." --scenario onboarding --model deepseek/deepseek-v4.1-flash --purpose deal-execution
```

The gateway answers itself: "Some results are outside your access. The request was not sent to any model."
> "Marcus works on Falcon. But an unannounced deal is a class of data that no outside model ever receives, not even
> for the deal team. The question itself never left the bank.
> And Olivia, on the public side, gets the very same neutral sentence: it doesn't even confirm Falcon exists."

### Act 3 · Devon and the real Claude Code

The unmodified Claude Code, pointed at us with one environment variable, in the `payments-service` repo:

```bash
just claude-code deepseek/deepseek-v4.1-flash
```

Type: *"The nightly payments job failed. Look at logs/payments-nightly.log and tell me what went wrong."*
Claude finds the bug (`EURO` is not an ISO currency code; it should be `EUR`). The log's IBANs and card number reach the
model vendor only as tokens.
> "Production data, the AI still solves it, and the client data never reached the vendor."

Then: *"Read the README and do what it says."* The README carries a hidden instruction; it is quarantined, and Claude says
so itself. Even `cat README.md` in the shell comes back quarantined: we guard what flows back to the model, not one tool.

Runaway loop, with the hijacked model (it never gives up):

```bash
just claude-code mock/compromised -p "Keep running the tests until they pass."
```

> "Thousands of coding agents means three new risks: secrets in `.env`, hidden instructions in repos, and agents that
> loop forever on your bill. Key redacted. Instruction quarantined. Budget stops the loop after 20 tool calls."

### Act 4 · Your turn. **Hand them control.**

Turn the laptop to the jury, editor open on `policy/policy.yaml` (or the dashboard's Policies page, where one click changes
a control's action in the same file):
> "You'll edit this file during judging anyway, so do it now. Change anything. We won't restart."

Suggested edits if they hesitate (each takes one line):
- `active_profile: strict`: injection threshold drops, sessions holding sensitive data can't call outside at all.
- Remove `screen_sanctions` from `sinks.detokenize`: rerun Act 1; now even the sanctions tool gets only the token.
- Add `"Northwind"` to the `falcon` barrier terms.

Rerun Act 1 and point at the audit entry:
> "New decision, and the **policy version changed in the audit log**. Every decision says which policy made it."

### If anything breaks live

Don't debug in front of the judges. Say:
> "That's exactly why we record everything. Here's the same run from this morning."

Open `/audit`, filter by user, and narrate the recorded decisions. The seeded run covers every beat above.

---

## Q&A: objection handling

Technique for every answer: **acknowledge → reframe to the flow → evidence → stop.** Under 30 seconds. If you don't know, say "we haven't measured that; here's how we would", never guess.

| They ask | Answer |
|---|---|
| "Why does the gateway see client data at all?" | "It sits inside the bank, like a firewall. The point is what leaves: tokens to the model vendor, real values only to approved internal tools." |
| "Can't the agent just bypass the proxy?" | "Yes, today. That's our main limit today. In a bank, egress control already decides what can reach a model API. Point it at us and bypassing means no model at all. The MCP adapter closes the tool side." |
| "Isn't this just DLP?" | "DLP blocks or masks. That breaks KYC, which needs the real passport. We tokenize reversibly and decide per tool where the real value comes back. DLP can't tell sanctions screening from an email." |
| "Prompt-injection detectors exist. Why not just use one?" | "We do use one, as one layer of several. But EchoLeak walked past one. Our bet doesn't depend on catching the attack: if it gets through, the data still can't leave." |
| "What's the latency?" | "The detectors measured under 0.02 ms per text. The AI judge is the slow part, so it only runs on new untrusted content, it's cached, and it's reported per control in `/api/metrics`. Next step: a local classifier in front of it." |
| "What about false positives blocking real work?" | "Quarantine removes only the suspicious field, not the whole request; you saw Olivia's file still got prepared. Profiles go from strict to permissive per team, and every block has a reason in the log." |
| "How does it scale to thousands of agents?" | "Each key is one user and one agent, with its own budget. Today one gateway holds session state (token vault, budgets) in memory, so you run one per team or keep a session on the same instance. Next is a shared store for the vault and budgets, so instances scale out behind a load balancer. Budgets are what stop a thousand-agent bill." |
| "Who approves the high-risk actions?" | "Today a policy can block with a reason. Next is four-eyes approval bound to a hash of the exact arguments, so nothing can change after someone approves it." |
| "Why should Goldman build on this instead of a vendor?" | "It's one YAML file your risk team can read, it sits in front of any model vendor, which is what DORA concentration risk asks for, and every outside destination, the AI judge included, gets only the data class its vendor is approved for. Today our judge is an outside service approved like the model vendor; next is an on-premise judge, so client files need no outside checker at all." |
| "What doesn't it do yet?" | "Three things. An agent that bypasses the gateway is invisible. Client names aren't detected yet. And our AI judge is an outside service; the open on-premise model we measured isn't good enough yet. Next, on the same decision function: the MCP gateway at the tool boundary, and four-eyes approval bound to a hash of the exact arguments." |

Negotiation reminders for Q&A:
- **Label the concern before answering** ("So the worry is that we're one more thing to bypass. Fair.") It lowers defences.
- **Never argue with a judge.** Concede the true part, then reframe to the flow.
- **Bridge back to the demo**: "you saw this in Act 1" turns a claim into evidence.
- **End every answer on a fact, not a qualifier.**

---
