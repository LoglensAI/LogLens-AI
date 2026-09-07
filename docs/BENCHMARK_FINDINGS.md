# Benchmark run — findings & recommendations

Ran the benchmark on a clean checkout against the public **LogHub BGL 2k**
sample (`scripts/fetch_benchmark.sh`, 1,999 lines, 143 labeled anomalies =
7.15%). Everything below is reproducible with the commands shown.

## What I measured (BGL 2k sample)

| Method                                   | Precision | Recall | F1    | Command |
| ---------------------------------------- | --------- | ------ | ----- | ------- |
| Unsupervised (default threshold)         | 0.334     | 1.000  | 0.501 | `loglens benchmark benchmarks/BGL_2k.log --format bgl` |
| Unsupervised (grid-best)                 | —         | —      | 0.530 | `… --grid` |
| Unsupervised (F1-optimal sweep)          | 0.477     | 0.741  | 0.581 | `python benchmark_labeled.py --file benchmarks/BGL_2k.log --sweep` |
| **Supervised head (RandomForest)**       | 0.902     | 0.965  | **0.932** | `… --supervised` |

## The gap you need to know about

`BENCHMARK.md` headlines **F1 0.957** (deep) / **0.948** (fast). Both are real
— but they're measured on the **full 500,000-line** BGL file with a tuned
threshold (0.8339). On the **2k sample that `fetch_benchmark.sh` actually
downloads**, the *unsupervised* detector scores ~**0.50–0.58**, not 0.95.

This isn't dishonesty in the algorithm — it's a scale effect. The detector's
strongest signals (rate-burst, flood, recurring-severe, volume-scaled rarity)
are calibrated for large files. On 2k lines they can't fire properly, so it
over-flags (note recall is a perfect 1.000 but precision collapses to 0.33).

The **supervised head holds up at 0.93 even on 2k**, because it learns from
features rather than volume statistics.

**Why this matters for pitching:** the README says "reproduce in two commands."
Anyone who runs exactly those two commands sees ~0.5 and a badge that says
0.957. That gap reads as inflation to a technical investor or design partner —
even though your 500K number is legitimate. Fix the reproduction path and the
number becomes an asset instead of a liability.

## Recommended fixes (in priority order)

1. **Make the reproducible number match the headline.** Pick one:
   - Ship/fetch a **larger, still-downloadable** BGL slice (e.g. 100k) so the
     "two-command" run lands near the headline; **or**
   - Label every number with its exact dataset size + mode + threshold, and
     make the small-sample number the one the quickstart prints.
2. **Lead with the supervised head (0.93) as the reproducible headline.** It's
   honest, holds on small data, and needs no torch/model download. Report it
   with a proper **train/test split or cross-validation** and state that
   explicitly (reviewers will assume leakage otherwise).
3. **Make the 500K / deep 0.957 independently reproducible.** A script that
   pulls the full BGL from a stable mirror, pins the embedding model, prints
   the threshold, and re-runs end-to-end. "Reproducible at scale" is a much
   stronger claim than a table someone has to trust.
4. **Add a second dataset to the default run** (Thunderbird is already in
   `BENCHMARK.md`). Cross-dataset generality with no retuning is your most
   defensible technical claim — surface it, don't bury it.
5. **Wire `--min-f1` into CI** as a regression gate so the number can't silently
   drop. You already support the flag.

## Minor inconsistencies spotted — now resolved

- ~~`cli.py` prints version **0.2.0**; `pyproject.toml` is **0.3.1**.~~
  **Fixed:** version now lives in a single source (`src/loglens/_version.py`),
  read by hatch, the API, and the CLI — a CI check guards against drift.
- ~~`pyproject.toml` "Bug Tracker" / "Source Code" URLs 404.~~
  **Fixed:** they now point to `github.com/ParasRajput810/LogLens-AI`.
- ~~The `--supervised` head was mislabeled "logistic reg" in the CLI.~~
  **Fixed:** it correctly reads "RandomForest" (the model actually used).

## Environment note

`--deep` mode and the full 500K dataset weren't runnable in this sandbox
(no model download / large-file mirror access), so those headline numbers
weren't re-verified here — only the 2k unsupervised + supervised numbers above,
which I ran directly.
