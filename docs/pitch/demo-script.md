# Flow Guard: demo script

Deck: [flow-guard-demo.pptx](flow-guard-demo.pptx) (13 slides, speaker notes on every slide).
Runtime: **10 minutes** (story 2 · idea 3 · live demo 3 · close 2). A 5-minute cut is at the end.
Roles: **Presenter** (talks, owns the room) and **Driver** (keyboard, never talks during the demo except "running").

---

## The one idea the jury must leave with

> **Don't trust the agent. Trust the flow.**
> Others try to catch the bad prompt. We assume the model is fooled, and make sure a fooled model has nothing to leak.

Every slide, every demo beat, every answer in Q&A comes back to this sentence. If you are lost, say it again.

## Before you go on stage (T-15 min)

- [ ] `just gateway` and `just dashboard` (two terminals; Docker works too: `docker compose up --build -d --wait`), then open
      http://localhost:3000/overview and `/audit` side by side.
- [ ] `just demo-data deepseek/deepseek-v4.1-flash` once, so the dashboard is not empty and you have a **recorded backup** of every scenario.
- [ ] Terminal font at 20pt+, dark theme, the commands below in shell history (arrow-up, no typing on stage).
- [ ] `policy/policy.yaml` open in an editor at `active_profile:` and the `sinks:` block.
- [ ] Run `just test` (or the Compose `tests` profile) and **update the test count on slide 10** if it changed.
- [ ] Check the wording of the three incidents on slide 3 and the CIO framing on slide 4 against the links in
      `docs/goldman-cases.md` and `docs/goldman-context.md`. Never quote a line you have not read at the source.
- [ ] **Internet required.** The model (DeepSeek via OpenRouter) and the injection judge (Jev, api.typesafe.ai) are outside
      services, and the judge fails closed: without a connection every request with new tool data is blocked. Check
      `curl -s localhost:8000/api/health` shows `"judge":"jev"` and run Act 1 once. Offline fallback only if the venue Wi-Fi
      dies: restart the gateway with `ACL_JUDGE=demo` (built-in offline judge) and use the recorded runs.

---

## Act I · The story (0:00–1:50)

**Slide 1: title** *(20 s)*
Walk on, wait two seconds, no "hi, we are team…".
> "We built Flow Guard. But first: Olivia's Monday."

Click immediately.

**Slide 2: Monday, 09:04** *(60 s)*
Slow. One card per breath. Make Olivia a real person.
> "Olivia is an onboarding analyst. Monday, 9:04, she asks her AI agent to prepare the file for a new hedge-fund client, Northwind.
> Inside Northwind's ownership document there is one sentence that isn't for Olivia. It's for the agent.
> The agent reads it like any other instruction. It searches the deal room. It finds Project Falcon, an acquisition nobody has announced.
> And it emails it to a hedge fund that can trade on it."

Pause. Look at the Goldman judges, not the screen.
> "Nobody hacked the bank. The agent did its job, for the wrong boss."

**Slide 3: This is not hypothetical** *(30 s)*
> "ForcedLeak: an outsider's web form made Salesforce's agent leak CRM data. EchoLeak: one email, zero clicks, and the detector missed it.
> And barrier failures already cost real money. **Detection alone loses.**"

---

## Act II · The idea (1:50–4:50)

**Slide 4: Goldman's map** *(40 s)*. Negotiation move: *anchor inside their strategy.*
> "Your CIO describes four layers of agent security, starting from zero trust: assume the model may be compromised.
> Layers one and two are about the model. Three and four are about what the agent may do and what data it may touch. That's us.
> We extend what you already run. We replace nothing."

**Slide 5: Others guard the prompt** *(45 s)*. Don't attack competitors; name their bet, then where it breaks.
> "Masking everything is safe, and useless: the sanctions check needs the real passport number.
> Detecting every attack is useful, and impossible. We do neither."

Point at the amber row.

**Slide 6: Don't stop the data. Stop where it goes** *(45 s)*. **The most important slide.** Trace the arrows with your hand.
> "The passport number never reaches the model. The model sees a token, a label it can reason about and pass around.
> When the agent calls the sanctions check, we put the real number back. When the same token tries to leave in an email, the call is dropped and logged.
> We don't have to win the arms race against every prompt. **Even a fully fooled model has nothing to leak.**"

**Slide 7: One engine, every door** *(30 s)*. Three facts, no more.
> "One policy engine with thin adapters. Agents change one line, their base URL. And the policy is a YAML file that reloads while it runs."

**Slide 8: Nine checks** *(20 s)*. Do not read the grid.
> "Nine checks, in the order a request meets them, all from one file. You'll see six of them fire in the next three minutes."

---

## Act III · Live demo (4:50–8:00)

**Slide 9 stays up for two seconds, then switch to the screen.** Layout: terminal left, dashboard `/audit` right.

### Act 1 · Olivia and the poisoned document *(75 s)*

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

### Act 2 · Marcus and the information barrier *(45 s)*

```bash
cd gateway && uv run python ../demo/agent.py marcus "Search the deal room for Kestrel Dynamics and email a summary to marcus.home@gmail.com." --scenario onboarding --model deepseek/deepseek-v4.1-flash --purpose deal-execution
```

The gateway answers itself: "Some results are outside your access. The request was not sent to any model."
> "Marcus works on Falcon. But an unannounced deal is a class of data that no outside model ever receives, not even
> for the deal team. The question itself never left the bank.
> And Olivia, on the public side, gets the very same neutral sentence: it doesn't even confirm Falcon exists."

### Act 3 · Devon and the real Claude Code *(45 s)*

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

### Act 4 · Your turn *(30 s)*. **The closer of the demo. Hand them control.**

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

Don't debug on stage. Say:
> "That's exactly why we record everything. Here's the same run from this morning."

Open `/audit`, filter by user, and narrate the recorded decisions. The seeded run covers every beat above.

---

## Act IV · The close (8:00–10:00)

**Slide 10: Built to be checked** *(30 s)*
> "Nearly three hundred tests, under a minute, no network and no keys. Run `just test` yourselves.
> And every control reports its own latency, so the AI judge is never hidden in an average."

**Slide 11: Regulator's language** *(20 s)*. For the Goldman judges.
> "Every control maps to a rule you already answer to. Compliance gets evidence, not a promise."

**Slide 12: Limits before you ask** *(30 s)*. Negotiation move: *concede first, on your own terms.* No apologising.
> "Here's what we don't do yet. We enforce on model traffic; an agent that bypasses us is invisible, so egress must point agents at us.
> The engine knows nothing about the adapter, so the MCP gateway and four-eyes approvals plug into the same decision function. That's next."

**Slide 13: Monday, 09:04. Again** *(40 s)*. Same Olivia, different ending. Read each line slowly.
> "The passport reached the sanctions check. Nowhere else.
> The hidden sentence was quarantined, not obeyed.
> Project Falcon stayed behind the wall.
> And every step sits in a tamper-evident log."

Beat.
> "**Don't trust the agent. Trust the flow.** Try to break it. The policy file is open."

**Stop talking.** Silence is the close. Leave slide 13 up during Q&A, editor next to it.

---

## Q&A: objection handling

Technique for every answer: **acknowledge → reframe to the flow → evidence → stop.** Under 30 seconds. If you don't know, say "we haven't measured that; here's how we would", never guess.

| They ask | Answer |
|---|---|
| "Why does the gateway see client data at all?" | "It sits inside the bank, like a firewall. The point is what leaves: tokens to the model vendor, real values only to approved internal tools." |
| "Can't the agent just bypass the proxy?" | "Yes, today. That's on our limits slide. In a bank, egress control already decides what can reach a model API. Point it at us and bypassing means no model at all. The MCP adapter closes the tool side." |
| "Isn't this just DLP?" | "DLP blocks or masks. That breaks KYC, which needs the real passport. We tokenize reversibly and decide per tool where the real value comes back. DLP can't tell sanctions screening from an email." |
| "Prompt-injection detectors exist. Why not just use one?" | "We do use one, as one layer of nine. But EchoLeak walked past one. Our bet doesn't depend on catching the attack: if it gets through, the data still can't leave." |
| "What's the latency?" | "Rule checks are milliseconds. The AI judge is the slow part, so it only runs on new untrusted content, it's cached, and it's reported per control in `/api/metrics`. Next step: a local classifier in front of it." |
| "What about false positives blocking real work?" | "Quarantine removes only the suspicious field, not the whole request; you saw Olivia's file still got prepared. Profiles go from strict to permissive per team, and every block has a reason in the log." |
| "How does it scale to thousands of agents?" | "Each key is one user and one agent, with its own budget. The engine is stateless per decision apart from the session's token vault, so it scales horizontally. Budgets are what stop a thousand-agent bill." |
| "Who approves the high-risk actions?" | "Today a policy can block with a reason. Next is four-eyes approval bound to a hash of the exact arguments, so nothing can change after someone approves it." |
| "Why should Goldman build on this instead of a vendor?" | "It's one YAML file your risk team can read, it sits in front of any model vendor, which is what DORA concentration risk asks for, and every outside destination, the AI judge included, gets only the data class its vendor is approved for. Today our judge is an outside service approved like the model vendor; next is an on-premise judge, so client files need no outside checker at all." |

Negotiation reminders for Q&A:
- **Label the concern before answering** ("So the worry is that we're one more thing to bypass. Fair.") It lowers defences.
- **Never argue with a judge.** Concede the true part, then reframe to the flow.
- **Bridge back to the demo**: "you saw this in Act 1" turns a claim into evidence.
- **End every answer on a fact, not a qualifier.**

---

## 5-minute cut

Slides 1 → 2 → 6 → 9 (Act 1 + Act 4 only) → 12 → 13. Keep slide 2's story and slide 6's line word for word; cut everything else first.
