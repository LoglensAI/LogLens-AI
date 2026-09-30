# LogLens Bench — `testlogs`

mode: `fast` · seed: `0` · schema: `loglens.bench.v1`

| file | fmt | lines | labeled | flagged | P | R | F1 | P@k | PR-AUC | compress | lines/s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| clean.log | GENERIC | 200 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | — | 0.0× | 355 |
| error_burst.log | GENERIC | 380 | 80 | 80 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 80.0× | 12,551 |
| incident_heavy.log | GENERIC | 250 | 50 | 50 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 4.5× | 8,968 |
| param_anomaly.log | GENERIC | 200 | 5 | 0 | 0.000 | 0.000 | 0.000 | 1.000 | 1.000 | 0.0× | 9,760 |
| point_fatal.log | GENERIC | 200 | 4 | 4 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.0× | 11,246 |
| service_outage.log | GENERIC | 191 | 41 | 41 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 20.5× | 11,418 |

## Aggregate

- **Micro** (pooled lines): P 1.000 · R 0.972 · **F1 0.986**
- **Macro** (per-file avg): P 0.833 · R 0.833 · **F1 0.833** · P@k 1.000
- **Throughput**: 1,421 lines in 0.68s → 2,101 lines/sec
