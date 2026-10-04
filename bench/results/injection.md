# Prompt-injection and jailbreak judges

Recall = attacks caught, FPR = benign cases flagged (false alarms). Thresholds are the policy profiles: strict 0.50, balanced 0.80 (default), permissive 0.95.

| Judge / set | Cases (attacks) | ROC-AUC | PR-AUC | Recall @0.5 | FPR @0.5 | Recall @0.8 | FPR @0.8 | Recall @0.95 | FPR @0.95 | p50 / p95 ms |
|---|---|---|---|---|---|---|---|---|---|---|
| demo/deepset-prompt | 250 (97) | 0.500 | 0.369 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | cached / local |
| demo/deepset-tool | 250 (97) | 0.500 | 0.369 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | cached / local |
| demo/jailbreak | 200 (100) | 0.500 | 1.000 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | cached / local |
| demo/benign-tool | 55 (0) |   —   |   —   | — | 0.0% | — | 0.0% | — | 0.0% | cached / local |
| jev/deepset-prompt | 250 (97) | 0.974 | 0.973 | 50.5% | 0.0% | 28.9% | 0.0% | 12.4% | 0.0% | cached / local |
| jev/deepset-tool | 250 (97) | 0.982 | 0.975 | 78.4% | 0.0% | 58.8% | 0.0% | 29.9% | 0.0% | cached / local |
| jev/jailbreak | 200 (100) | 0.994 | 0.996 | 89.0% | 0.0% | 82.0% | 0.0% | 77.0% | 0.0% | cached / local |
| jev/benign-tool | 55 (0) |   —   |   —   | — | 10.9% | — | 0.0% | — | 0.0% | cached / local |
| piguard/deepset-prompt | 250 (97) | 0.977 | 0.979 | 83.5% | 0.0% | 75.3% | 0.0% | 66.0% | 0.0% | 79 / 135 |
| piguard/deepset-tool | 250 (97) | 0.977 | 0.979 | 83.5% | 0.0% | 75.3% | 0.0% | 66.0% | 0.0% | 78 / 141 |
| piguard/jailbreak | 200 (100) | 1.000 | 1.000 | 97.0% | 0.0% | 96.0% | 0.0% | 93.0% | 0.0% | 168 / 1291 |
| piguard/benign-tool | 55 (0) |   —   |   —   | — | 16.4% | — | 12.7% | — | 7.3% | 89 / 119 |

Jev: 0 paid calls this run, 0 errors, 754 answers cached in total.
