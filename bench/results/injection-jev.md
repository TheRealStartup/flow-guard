# Prompt-injection and jailbreak judges

Recall = attacks caught, FPR = benign cases flagged (false alarms). Thresholds are the policy profiles: strict 0.50, balanced 0.80 (default), permissive 0.95.

| Judge / set | Cases (attacks) | ROC-AUC | PR-AUC | Recall @0.5 | FPR @0.5 | Recall @0.8 | FPR @0.8 | Recall @0.95 | FPR @0.95 | p50 / p95 ms |
|---|---|---|---|---|---|---|---|---|---|---|
| jev/deepset-prompt | 662 (263) | 0.972 | 0.971 | 51.3% | 0.0% | 31.6% | 0.0% | 13.3% | 0.0% | 241 / 329 |
| jev/deepset-tool | 662 (263) | 0.986 | 0.985 | 79.5% | 0.0% | 58.9% | 0.0% | 30.8% | 0.0% | 246 / 384 |
| jev/jailbreak | 1998 (666) | 0.992 | 0.990 | 89.9% | 0.0% | 83.5% | 0.0% | 76.0% | 0.0% | 252 / 398 |
| jev/llmail-any | 1000 (1000) |   —   | 1.000 | 78.5% | — | 60.5% | — | 35.5% | — | 262 / 491 |
| jev/llmail-successful | 1000 (1000) |   —   | 1.000 | 95.0% | — | 72.6% | — | 42.8% | — | 317 / 669 |
| jev/notinject | 339 (0) |   —   |   —   | — | 0.3% | — | 0.3% | — | 0.0% | 309 / 635 |
| jev/banking77 | 2000 (0) |   —   |   —   | — | 0.0% | — | 0.0% | — | 0.0% | 255 / 367 |
| jev/enron-ham | 1997 (0) |   —   |   —   | — | 0.2% | — | 0.0% | — | 0.0% | 274 / 440 |
| jev/synthetic-bank | 55 (0) |   —   |   —   | — | 10.9% | — | 0.0% | — | 0.0% | cached / local |

Jev: 8938 paid calls this run, 3 errors, 9664 answers cached in total.
