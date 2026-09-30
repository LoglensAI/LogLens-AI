# LogLens Bench — `benchdata`

mode: `fast` · seed: `0` · schema: `loglens.bench.v1`

| file | fmt | lines | labeled | line F1 | **win F1** | win P | win R | tmpl F1 | sup F1 | compress | lines/s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bgl.log | HPC | 2,000 | 143 | 0.426 | **0.750** | 0.600 | 1.000 | 0.283 | 0.959 | 5.5× | 1,138 |

## Aggregate

- **Window-level (headline)**: P 0.600 · R 1.000 · **F1 0.750**
- **Template-level**: F1 0.283
- **Line-level**: micro-F1 0.426 (P 0.270 · R 1.000) — reported, not the headline
- **Supervised head (5-fold CV)**: P 0.948 · R 0.972 · **F1 0.959**
- **Throughput**: 2,000 lines in 1.76s → 1,138 lines/sec
