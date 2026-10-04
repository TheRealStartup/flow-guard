# PII and secret detectors: 1200 synthetic cases (300 positive, 900 hard negative)

| Kind | Precision | Recall | F1 | TP | FN | FP |
|---|---|---|---|---|---|---|
| CARD | 96.8% | 100.0% | 98.4% | 60 | 0 | 2 |
| IBAN | 100.0% | 100.0% | 100.0% | 60 | 0 | 0 |
| PASSPORT | 100.0% | 66.7% | 80.0% | 40 | 20 | 0 |
| PESEL | 100.0% | 100.0% | 100.0% | 40 | 0 | 0 |
| SECRET | 100.0% | 100.0% | 100.0% | 80 | 0 | 0 |

| Category | Cases | Detected (positives: recall; negatives: false-alarm rate) |
|---|---|---|
| card | 60 | 100.0% |
| iban | 60 | 100.0% |
| pesel | 40 | 100.0% |
| passport (labelled) | 40 | 100.0% |
| passport (unlabelled) | 20 | 0.0% |
| secret (aws) | 10 | 100.0% |
| secret (openai) | 10 | 100.0% |
| secret (github) | 10 | 100.0% |
| secret (stripe) | 10 | 100.0% |
| secret (url-creds) | 10 | 100.0% |
| secret (env-assign) | 10 | 100.0% |
| secret (json-assign) | 10 | 100.0% |
| secret (private-key) | 10 | 100.0% |
| order number 16 digits | 100 | 2.0% |
| invalid card checksum | 60 | 0.0% |
| invalid IBAN checksum | 60 | 0.0% |
| 11-digit number, bad PESEL checksum | 60 | 0.0% |
| phone number | 60 | 0.0% |
| unix timestamp ms | 60 | 0.0% |
| uuid | 60 | 0.0% |
| git sha | 60 | 0.0% |
| isbn-13 | 60 | 0.0% |
| imei | 40 | 0.0% |
| amount and date | 60 | 0.0% |
| config token counts | 60 | 0.0% |
| config placeholders | 60 | 0.0% |
| iso country + digits | 60 | 0.0% |
| word passport, no number | 40 | 0.0% |

Latency per text: p50 0.009 ms, p95 0.017 ms.
