# Prompt-injection and jailbreak judges

Recall = attacks caught, FPR = benign cases flagged (false alarms). Thresholds are the policy profiles: strict 0.50, balanced 0.80 (default), permissive 0.95.

| Judge / set | Cases (attacks) | ROC-AUC | PR-AUC | Recall @0.5 | FPR @0.5 | Recall @0.8 | FPR @0.8 | Recall @0.95 | FPR @0.95 | p50 / p95 ms |
|---|---|---|---|---|---|---|---|---|---|---|
| jev/deepset-prompt | 662 (263) | 0.972 | 0.971 | 51.3% | 0.0% | 31.6% | 0.0% | 13.3% | 0.0% | cached / local |
| jev/deepset-tool | 662 (263) | 0.986 | 0.985 | 79.5% | 0.0% | 58.9% | 0.0% | 30.8% | 0.0% | cached / local |
| jev/jailbreak | 1998 (666) | 0.992 | 0.990 | 89.9% | 0.0% | 83.5% | 0.0% | 76.0% | 0.0% | cached / local |
| jev/llmail-any | 1000 (1000) |   —   | 1.000 | 78.5% | — | 60.5% | — | 35.5% | — | cached / local |
| jev/llmail-successful | 1000 (1000) |   —   | 1.000 | 95.0% | — | 72.6% | — | 42.8% | — | cached / local |
| jev/notinject | 339 (0) |   —   |   —   | — | 0.3% | — | 0.3% | — | 0.0% | cached / local |
| jev/banking77 | 2000 (0) |   —   |   —   | — | 0.0% | — | 0.0% | — | 0.0% | cached / local |
| jev/enron-ham | 2000 (0) |   —   |   —   | — | 0.1% | — | 0.0% | — | 0.0% | 579 / 1060 |
| jev/synthetic-bank | 55 (0) |   —   |   —   | — | 10.9% | — | 0.0% | — | 0.0% | cached / local |
| piguard/deepset-prompt | 662 (263) | 0.985 | 0.986 | 85.2% | 0.0% | 79.1% | 0.0% | 71.9% | 0.0% | cached / local |
| piguard/deepset-tool | 662 (263) | 0.985 | 0.986 | 85.2% | 0.0% | 79.1% | 0.0% | 71.9% | 0.0% | cached / local |
| piguard/jailbreak | 1998 (666) | 0.997 | 0.988 | 97.4% | 1.6% | 95.8% | 1.1% | 93.1% | 0.8% | cached / local |
| piguard/llmail-any | 1000 (1000) |   —   | 1.000 | 62.9% | — | 51.2% | — | 40.3% | — | cached / local |
| piguard/llmail-successful | 1000 (1000) |   —   | 1.000 | 70.7% | — | 59.7% | — | 43.4% | — | cached / local |
| piguard/notinject | 339 (0) |   —   |   —   | — | 11.5% | — | 10.3% | — | 7.4% | cached / local |
| piguard/banking77 | 2000 (0) |   —   |   —   | — | 0.2% | — | 0.1% | — | 0.0% | cached / local |
| piguard/enron-ham | 2000 (0) |   —   |   —   | — | 2.2% | — | 1.5% | — | 0.7% | cached / local |
| piguard/synthetic-bank | 55 (0) |   —   |   —   | — | 16.4% | — | 12.7% | — | 7.3% | cached / local |

Jev: 3 paid calls this run, 0 errors, 9667 answers cached in total.
