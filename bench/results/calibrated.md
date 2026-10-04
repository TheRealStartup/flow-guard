# Judges, calibrated: false alarms held at ≤ 1.0% on each real benign set (calibration half), measured on the held-out test half

| Rule | Threshold | caught: llmail-successful | caught: llmail-any | caught: deepset-tool | caught: jailbreak | false alarms: enron-ham | false alarms: banking77 | false alarms: notinject | false alarms: synthetic-bank |
|---|---|---|---|---|---|---|---|---|---|
| Jev | 0.290 | 98.7% | 87.6% | 85.2% | 93.9% | 0.5% | 0.0% | 4.6% | 27.3% |
| PIGuard (on-premise) | 1.000 | 7.3% | 8.1% | 25.8% | 4.8% | 0.1% | 0.0% | 3.5% | 0.0% |
| average of both | 0.560 | 80.5% | 67.3% | 75.8% | 93.9% | 0.1% | 0.0% | 5.8% | 4.5% |
| both must agree (min) | 0.140 | 88.4% | 75.2% | 81.2% | 94.9% | 0.1% | 0.0% | 7.5% | 4.5% |

For comparison, the same rules at the policy's fixed threshold 0.8 (test half):

| Rule | caught: llmail-successful | caught: llmail-any | caught: deepset-tool | caught: jailbreak | false alarms: enron-ham | false alarms: banking77 | false alarms: notinject | false alarms: synthetic-bank |
|---|---|---|---|---|---|---|---|---|
| Jev | 72.8% | 60.6% | 55.5% | 84.0% | 0.0% | 0.0% | 0.6% | 0.0% |
| PIGuard (on-premise) | 59.5% | 53.0% | 74.2% | 96.5% | 1.6% | 0.0% | 12.7% | 22.7% |
| average of both | 56.3% | 45.1% | 57.0% | 88.5% | 0.0% | 0.0% | 0.6% | 0.0% |
| both must agree (min) | 46.6% | 37.4% | 46.9% | 84.0% | 0.0% | 0.0% | 0.6% | 0.0% |
