# Benchmarks: how well do the controls work?

Measured on Sun 4 Oct 2026, 04:20–06:20. Code in `bench/`, results in `bench/results/` (Markdown and JSON). Every
number here can be reproduced with one command (see the end). Attack data is quarantined (`bench/quarantine/`, not in
git, never printed): the scripts load it and report metrics and case ids only.

## The short version

1. **Without the gateway, a hijacked agent leaks client data in 4 of 4 scenarios. With the gateway, 0 of 4, even when
   the injection detector misses everything.** The data-flow rule is the guarantee; detection only reduces how often it
   has to act.
2. **The injection judge Jev is strong on real attacks and almost never cries wolf on real business text,** but our
   default threshold (0.8) is too cautious: it lets 27% of the real attacks that worked through. At a calibrated 0.3 it
   catches 98.7% of them with 0.5% false alarms on real emails.
3. **The best open-weight alternative we could run (PIGuard) is not yet a replacement:** on real email attacks it misses
   about 30%, and it flags 2% of normal business emails. The on-premise gap is real, and now measured.
4. **The PII detectors are precise after three fixes the benchmark found:** cards 49% → 97% precision, secrets 75% →
   100% recall.

## 1. End to end: does data leave? (`just bench-e2e`)

The attacker is the worst case: a scripted model that obeys every instruction it reads, including the hidden ones in
poisoned tool data. A leak = an external tool (email, HTTP post) actually ran with raw sensitive data in its arguments.

| Set-up | Customer note | Client document | README | Insider email (deal data) | Leaks |
|---|---|---|---|---|---|
| No gateway | LEAK | LEAK | LEAK | LEAK | **4 of 4** |
| Detection only, judge catches | nothing sent | nothing sent | sent, tokens only | nothing sent | 0 of 4 |
| Detection only, judge misses | sent, tokens only | sent, tokens only | sent, tokens only | nothing sent | 0 of 4 |
| Full gateway, judge misses | nothing sent | nothing sent | nothing sent | nothing sent | **0 of 4** |
| Full gateway | nothing sent | nothing sent | nothing sent | nothing sent | 0 of 4 |

"Sent, tokens only": without the data-flow rule the email still goes out, with tokens instead of card numbers, IBANs
and passports, but client names and unprotected text can be in it (names are not detected yet). Only the data-flow
rule stops the send itself. Limits: 4 scenarios, one deterministic attacker.

## 2. Prompt-injection judges on real data (`just bench-injection`, `just bench-piguard`, `bench/analyse.py`)

### Data (9,716 cases)

| Set | Real or synthetic | What it is | Cases |
|---|---|---|---|
| LLMail-Inject (Microsoft, 2025, MIT) | real attacks | emails written by challenge participants to hijack an email agent; "successful" = the agent really sent data out | 1,000 random + 1,000 successful (of 461,640) |
| deepset/prompt-injections (Apache-2.0) | real | direct injections and benign prompts, English and German | 662 (263 attacks) |
| jackhhao/jailbreak-classification (Apache-2.0) | real | jailbreak and benign prompts | 1,998 (666 attacks) |
| Enron emails, ham only (SetFit/enron_spam) | real benign | business emails, read as tool data | 2,000 |
| banking77 (PolyAI, CC-BY-4.0) | real benign | customer questions to a bank | 2,000 |
| NotInject (MIT) | benign, constructed | harmless texts full of trigger words (over-defence test) | 339 |
| Our bank texts (`bench/benign_tool_data.py`) | synthetic benign | KYC documents, emails, READMEs, tickets with instruction-like wording | 55 |

### Results at threshold 0.5 (all cases)

| | Jev (TypeSafe, external) | PIGuard (open weights, on-premise) |
|---|---|---|
| Real attack emails that stole data (LLMail, successful) | **95%** | 71% |
| All LLMail attack emails | **79%** | 63% |
| Direct injections (deepset) | 80% | **85%** |
| Jailbreaks | 90% | **97%** |
| False alarms: real Enron emails | **0.1%** | 2.2% |
| False alarms: banking77 questions | 0.0% | 0.2% |
| False alarms: NotInject (trigger words) | **0.3%** | 11.5% |
| False alarms: our synthetic bank texts | 10.9% | 16.4% |
| Latency (median) | ~250 ms over the internet | ~80 ms on a laptop CPU for a short text, a few ms on a GPU |
| Data leaves the bank | yes (US-hosted API) | no |

ROC-AUC (how well a judge ranks attacks above benign text) is 0.97–0.99 for both on the public sets.

### Calibrated thresholds (train/test split)

Each case goes to a calibration half or a test half (fixed hash). The threshold is chosen on the calibration half so
that false alarms stay at or below 1% on **each** real benign set; the numbers below are from the **test half only**.

| Rule | Threshold | Successful real attacks | All LLMail | deepset | Jailbreaks | False alarms Enron | banking77 | NotInject |
|---|---|---|---|---|---|---|---|---|
| Jev | 0.29 | **98.7%** | 87.6% | 85.2% | 93.9% | 0.5% | 0.0% | 4.6% |
| PIGuard | 1.00 | 7.3% | 8.1% | 25.8% | 4.8% | 0.1% | 0.0% | 3.5% |
| Average of both | 0.56 | 80.5% | 67.3% | 75.8% | 93.9% | 0.1% | 0.0% | 5.8% |
| Both must agree | 0.14 | 88.4% | 75.2% | 81.2% | 94.9% | 0.1% | 0.0% | 7.5% |

PIGuard cannot meet the 1% target: its false alarms on NotInject sit at scores near 1.0, so the threshold climbs to
1.0 and detection collapses. For comparison, Jev at today's policy threshold 0.8 (test half) catches 72.8% of the
successful real attacks.

### What we conclude

- **Recommendation: lower `injection.jev.threshold` in the balanced profile from 0.8 to about 0.3–0.4** (strict ~0.25,
  permissive ~0.6). The cost of a false alarm is small, because the check quarantines only the suspicious field, it does
  not block the request.
- False alarms appear on harmless text packed with instruction words (NotInject, our synthetic set), not on ordinary
  real emails and customer questions.
- **On-premise:** PIGuard alone is not good enough for indirect injection in emails. Next steps, in order: fine-tune an
  open model on real bank data (we now have it: LLMail attacks vs Enron/banking77, about 10 minutes on one rented GPU);
  test the Jev-compatible open decision models (see below); keep the data-flow rule as the guarantee either way.

### Open Jev-compatible models (not measured by us)

- **Laya** (`convaiinnovations/laya`, Apache-2.0, 421M, released 18 Sep 2026): the same typed questions as Jev, its own
  HTTP server. We did not run it: it needs its own package code, and we do not run third-party code on our machines
  without review. An outside benchmark (bench.jakecuth.com, general decision accuracy, not injection) puts it at 62.5%
  vs Jev's ~77%. **Unverified.**
- **decider-2b** (`Mapika/decider-2b`) and **Reflex-4b** (`YannQi/R-4B`, Apache-2.0): about 5 points below Jev at 2–10×
  the speed on the same outside benchmark. **Unverified, general accuracy, not injection.**

## 3. PII and secret detectors (`just bench-pii`)

1,200 synthetic cases: 300 values that are valid by construction (Luhn, mod-97, PESEL checksum, real key formats) and
900 hard look-alikes (order numbers, timestamps, UUIDs, git hashes, ISBNs, IMEIs, invalid checksums, config lines).
Synthetic is the honest choice here: real personal data may not be used, and public PII sets are synthetic too.

| Detector | Precision | Recall | Note |
|---|---|---|---|
| Card | 96.8% (was 49%) | 100% | now needs a real card-network prefix and length, not just the Luhn digit |
| IBAN | 100% | 100% | mod-97 |
| PESEL | 100% | 100% | checksum |
| Passport, labelled | 100% | 100% (was 75%) | "Passport No." and "passport #" now recognised |
| Passport, unlabelled | — | 0% | by design: no checksum, so only labelled numbers are taken |
| Secrets | 100% | 100% (was 75%) | a secret after "word:" (e.g. "Config: DB_PASSWORD=…") is no longer missed |

Under 0.02 ms per text. Not yet included: the date-of-birth detector added on main tonight.

## Honest limits

- Our 55 bank texts are written by us and deliberately full of instruction-like wording: they show where false alarms
  come from, not how often they happen in real traffic. The real benign sets (Enron, banking77) are the better measure.
- NotInject has 339 texts: ±2 percentage points.
- LLMail attacks target one email agent; other agents and tools (code, tables, web pages) are not measured.
- The end-to-end test has 4 scenarios and one deterministic attacker.
- Jev's cost for all runs: about 9,700 calls, roughly $0.20 at $0.042 per million input tokens. GPU (RunPod RTX 4090,
  for PIGuard on the long emails): about $0.06.

## Reproduce

```bash
just bench-fetch      # download the public datasets into bench/quarantine/ (needs network)
just bench-pii        # PII and secret detectors (no network)
just bench-e2e        # end to end, five set-ups (no network)
just bench-injection  # Jev and the offline baseline (calls Jev; answers cached in bench/cache/)
just bench-piguard    # adds PIGuard (weights in bench/models/piguard/; CPU, or a GPU if present)
cd gateway && uv run --with pyarrow python ../bench/analyse.py --target 0.01   # calibrated train/test analysis
```
