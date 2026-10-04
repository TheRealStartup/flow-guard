# UX review of the control center (Sun 4 Oct ~06:00)

A review agent went through all four dashboard pages element by element, from the point of view of a Goldman Sachs
judge (risk, compliance and engineering people, some not technical, a few minutes per page, often during a 3-minute
demo). This file is the work list. **Fixed** items are marked; everything else is open.

## Already fixed (commits 4b9340c, b3d43e9, 7f09c05)
- Audit list: the "What happened" column was 10 px wide at 1440 px. User and agent are merged into one column, the
  detail panel is narrower below 2xl, and the list time drops milliseconds.
- "Show session" clears the other filters; the Overview links to `/audit?outcome=attack`; "1 matching event".
- Audit tiles show "—" while loading instead of zeros. The first tile is now "Agent requests", noting the policy events.
- Live demo: personas by job (bob is a fraud analyst, marcus an M&A banker), hana (HR) and two HR examples added,
  no "[object Object]" in the controls table.
- Time-range buttons and signature dates no longer wrap; signature table header gap; the Next.js dev badge is hidden.
- Policies: aligned budget table with readable role names; the scripted model labelled "test only"; Ollama/qwen gone.

## Open, ranked by impact on a judge
1. **Fixed (feature/ux-rework):** the gateway serves a `summary` per entry (verdict, headline, plain reason); rows,
   detail and the Overview list show it. ~~**Rows name the next tool call, not what FlowGuard did** (/audit, /overview). "Get client file · Blocked" says
   nothing about the scope rule. Add a reason line: "Client scope: AC-7730 is not olivia's client", "Hidden
   instruction quarantined in the get_client_file result". Make the detail headline that sentence, not "Bash +1". (M)~~
2. **Fixed:** one verdict per event from the gateway, same badge everywhere. ~~**One event, several labels.** The row says "Attack defused"; the detail badge for the same event says "Redacted"
   or "Blocked"; the tiles say "Attacks stopped" (Overview) and "Attacks defused" (Audit). One outcome set everywhere,
   identical badge in row and detail (terminology table below). (S)~~
3. **Fixed:** tiles count requests by verdict (Attacks caught, Blocked, Data protected = hidden + withheld) with (i)
   definitions; the chart stacks the same groups. ~~**Overview numbers disagree.** In one 24 h view: 26 prompt injections (Attacks tile), 28 (What the controls
   caught), 31 messages quarantined (Data protected). Quarantines count in two tiles. One number per concept with an
   (i) definition: attacks = requests where an attack was caught; data protected = values hidden + values withheld.
   "12 requests blocked" covers scope, budget and identity, which are not attacks: give it its own line. (S/M)~~
4. **Fixed:** "What the attacker tried" callout from hand-written, behaviour-tested descriptions (ATTACKS in the
   scenario modules, tests/test_demo_attacks.py), never the injected text. ~~**Live demo shows that an attack was stopped, not what it wanted.** The worst-case run ends with "Done." and one
   table row. Add a short "What the attacker tried" callout above the findings: a safe, truncated excerpt of the
   quarantined text (never the raw payload into the audit log) and "Without FlowGuard: the agent would have …". (M)~~
5. **Fixed:** steps stream in from the audit stream (Try it takes a session id), the page scrolls to the result,
   five per-run tiles, one duration split into model / checks / AI check. ~~**Live demo: 24 s of silence, result below the fold.** Stream the steps as they happen (tokenized ✓ →
   get_client_file ✓ → injection check 0.91 → quarantined) and scroll to the result. Tiles that count only this run:
   Hidden / Quarantined / Withheld / Stopped / Released (today "Actions stopped 0" while an injection was quarantined).
   One duration ("24252 ms" in the header vs "37 checks in 12354 ms"). (M)~~
6. **Audit: policy reloads bury agent activity.** Default to agent activity, or collapse unchanged reloads into one row
   ("Policy reloaded ×6, no changes"). Policy changes need an author (dashboard / file edit). Humanise the diff
   ("Date-of-birth protection: added, Redact"), not `null → {"action":"redact"}`. (S/M)
7. **Policies reads like a config dump.** Plain name first, id second; a one-line "what it stops" per control (texts in
   docs/policy.md); three short sections a risk manager needs: who may use which tool (roles → tools, users → role),
   where real values go (detokenize sinks) and where data may leave (external sinks), and the data classes
   (public < internal < P2 client data < DP30 deal secrets; explain "≤ P2"). OWASP codes with a tooltip. "Fired · 24 h"
   counts link to `/audit`. Model add form: labels (model id, provider, highest data class). (M)
8. **Overview honesty.** Hide "+168 vs previous" when the previous period had no data; leave the scripted model out of
   latency and cost (the 24 h "model 0.2 ms median" is the test model; DeepSeek is ~1.6 s). (S)
9. **Five-second status line** above the Overview tiles: "All controls active · audit chain intact · nothing needs
   review". (S)
10. **Event detail for compliance** ("who did what, on whose authority, under which policy, why stopped"): show the
    user's request, their entitlements (role, assigned clients, side), the cost of the request, the policy version as a
    link to its diff; decisive check first, passing checks collapsed ("3 other checks passed"); "98% likely injection
    (limit 80%)" instead of "p=0.98 >= 0.8"; pretty-print tool arguments and hide spotlight markers (raw view stays). (M)

## Smaller items per page
- **Global:** header chips "JUDGE · JEV" / "BALANCED" → "Injection check: Jev (AI)" / "Profile: Balanced" with tooltips;
  sidebar "Read-only audit access" is untrue (Policies writes, Demo sends); gateway card "Gateway online · Balanced".
- **Overview:** sparkline without a label; "unknown" user → "Rejected API key"; role under each user name; "P2" as a
  class badge apart from data types; "What the controls caught" splits attacks from hidden data, releases not in amber
  (amber = flagged); "+5 more controls" not expandable; chart x-axis mostly empty at 24 h (fit to the data); session ids
  like "try-olivia-9eaf79" → "olivia · demo run 03:46"; "Users and agents" headers run together at 1440 px.
- **Audit:** Action filter shows raw tool ids; filters not in the URL (only `?session`, `?q`, `?outcome`); no filter by
  control or policy version; search does not match display names ("Client scope"); "(mode=value)" in callouts; Python
  list repr "['falcon']" in reasons; "Provider Relace" (an OpenRouter host) means nothing to judges; the masking note
  belongs next to the title; a one-line "tamper-evident: changing any earlier entry breaks this chain" by the hash.
- **Live demo:** subtitle "Define what…" (editing happens elsewhere) → the pitch line; flow diagram lacks the return
  arrow (tool results back through FlowGuard, where tokenizing and quarantine happen); highlight boxes that fired;
  agent actions grouped ("screen_sanctions ×7"); Where = "assistant" → "Model's answer"; long AI answer collapsed to 6
  lines; controls table collapsed by default ("17 controls active, see Policies"); "Controls enforced 17" vs the deck's
  "nine checks" (say "17 controls in 9 groups").
- **Policies:** reload banner without author; "Off / Monitor / Enforce" for models vs Allow/Flag/Block elsewhere
  (decide: keep it as a deliberate exception with a tooltip, or align); signature status line too technical
  ("Feed checked 03:48 UTC · 8 signatures valid") and "Pull feed now" gives no result message.

## One term per concept
| Concept | Seen today | Use |
|---|---|---|
| request or tool call stopped | Blocked, Stopped before it ran, Blocked before it left, Actions stopped | **Blocked** (subline says where) |
| injection or exfiltration caught | Attacks stopped, Attacks defused, "Redacted" badge | **Attack caught** |
| value replaced by a reversible token | tokenized, hidden, redacted, masked, Data protected | **Hidden** (tooltip: tokenized) |
| injected text removed | quarantined, Content removed | **Quarantined** |
| restricted content kept back | withheld, redact | **Withheld** |
| real value put back | Released, pii.detokenize | **Released to an approved tool** |
| the AI checker | Prompt-injection check, AI judge, JUDGE · JEV, injection.jev | **AI injection check (Jev)** |
| control names | ids on Policies and in Demo's Rule column | **display name first, id second**; search accepts both |
| counts | Requests / Total events / Activity log / chain entries | **Agent requests** vs **Audit entries (incl. policy)** |

## Keep
The demo summary sentence ("3 values hidden from the model · 1 message quarantined · 1 restricted item withheld · 2
real values released · nothing left the organisation"); the role hints under the request; "Blocked before it left" and
"Removed before the model saw it" callouts; the decision trace with per-control milliseconds; the chain-integrity strip
and per-event hash block; "Masked by the gateway…"; session budget bars; the one-click action toggles with the diff
banner; "What the model saw instead" with real tokens; the example titles on /demo; "All times in UTC"; "Block beats
redact beats flag … fail closed"; colours red = blocked/attack, blue = hidden, amber = flagged.
