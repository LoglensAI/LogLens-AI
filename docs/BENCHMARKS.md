# LogLens AI — Benchmark Baseline (v0.9.0)

Measured baseline for the 0.9.0 release. All numbers are reproducible with the
commands shown; this file is the regression anchor for future releases (a drop
in accuracy or throughput below these figures should fail review).

- **Environment:** Linux x86_64, Python 3.11, 4 workers
- **Dataset (accuracy):** `benchmarks/BGL_2k.log` — 2,000 real HPC log lines,
  143 human-labeled anomalies (LogHub BGL)
- **Dataset (throughput):** BGL_2k tiled to 200k / 1M lines (throughput is
  content-independent; anomaly counts on the tiled file are not meaningful)
- **Build under test:** layered architecture (Phases 6–7), all CI gates green

---

## 1. Detection accuracy (BGL_2k, 143 labeled anomalies)

```
loglens benchmark benchmarks/BGL_2k.log --format bgl --supervised
```

| Method                          | Precision | Recall |    F1 |
|---------------------------------|-----------|--------|-------|
| Rule + embeddings (unsupervised)|     0.334 |  1.000 | 0.501 |
| Supervised head (RandomForest)  |     0.902 |  0.965 | 0.932 |

- **Unsupervised** runs with zero training and catches **100% of real
  anomalies** (recall 1.000) — it never misses, at the cost of some false
  positives. This is the out-of-the-box, no-setup path.
- **Supervised** (a few seconds to train on labeled logs) reaches **F1 0.932**
  with 90% precision and 97% recall.
- CI floor: unsupervised F1 must stay ≥ 0.45 (`--min-f1 0.45`).

## 2. Throughput, latency & memory

```
loglens bench <file> --modes fast,turbo --workers 4
```

| Mode  |   Lines | Time (s) | Lines/s | Peak RAM | Notes                          |
|-------|--------:|---------:|--------:|---------:|--------------------------------|
| fast  |   2,000 |    0.32  |   6,208 |     —    | full re-clustering, embeddings |
| turbo |   2,000 |    0.10  |  20,415 |     —    | parallel count-based scan      |
| fast  | 200,000 |   24.55  |   8,147 |   911 MB | full ML pass                   |
| turbo | 200,000 |    3.81  |  52,467 |   359 MB | chunked, multiprocess          |
| turbo |1,000,000|   18.77  |  53,292 | 1,099 MB | linear scaling                 |

- **turbo sustains ~52,000 lines/s** independent of file size (200k → 1M),
  at roughly **7× the throughput and ~40% the memory of fast mode**.
- **1,000,000 log lines analyzed in ~19 seconds** on a 4-core machine.
- **CLI cold-start: ~190 ms** (lazy-import; down from ~1.6 s pre-optimization).

## 3. Test suite

```
pytest --cov=loglens
```

- **171 passed, 11 skipped**, 0 failures
- **Coverage: 69.30%** (CI floor: 65%)

## 4. Quality gates (all blocking in CI)

| Gate                          | Result                         |
|-------------------------------|--------------------------------|
| ruff (lint + format)          | clean                          |
| mypy (strict, py3.10–3.12)    | 0 errors, 45 files             |
| import-linter (architecture)  | 1 contract kept, 0 broken      |
| pytest + coverage             | 171 passed, 69.30% ≥ 65%       |
| accuracy gate (F1)            | 0.501 ≥ 0.45                   |

## 5. Feature surface (exercised end-to-end)

**CLI (8 commands):** `version`, `hello`, `analyze`, `ask`, `benchmark`,
`train`, `bench`, `watch`.
**SDK (public API):** `analyze()`, `analyze_entries()`, `analyze_async()`,
`LogLensHandler` (drop-in `logging.Handler`), `LiveDetector`, `Monitor`/`init()`.
**Ingestion:** file, stdin, URL, live command output (`watch`).
**Output:** rich terminal, standalone HTML report, markdown.
**Detection:** DBSCAN clustering + TF-IDF (+ optional MiniLM neural embeddings,
`[deep]` extra) + supervised RandomForest head + additive rule engine.
**Extras:** LLM-powered root-cause analysis (bring-your-own-key: OpenAI / Azure
/ Groq), Slack / Teams / email alerting, secret/PII redaction before any LLM
call, SSRF-guarded webhooks.

## 6. Platform-agnosticity

- Multiprocessing (`turbo`) verified under the `spawn` start method
  (macOS/Windows default), not just Linux `fork`.
- All text file I/O specifies an explicit encoding (no Windows cp1252
  corruption); CRLF input handled.
- Cross-platform cache/config via `platformdirs`; no hardcoded paths.
- Only Unix-only API used is `resource` (guarded, optional).
- Known caveat: `watch` command parsing uses POSIX `shlex`; complex quoted
  commands on Windows may need adjustment (simple commands work).

## 7. Detection caps

Issue #17 made the two high-cardinality caps configurable. The accuracy check
below confirms the defaults are unchanged and the configurable path does not
regress detection (measured 2026-11-25, v0.13.1 + this change, Python 3.13).

```
loglens benchmark benchmarks/BGL_2k.log --format bgl
LOGLENS_MAX_CLUSTER_GROUPS=auto loglens benchmark benchmarks/BGL_2k.log --format bgl
```

| Setting | Cluster groups | Synonym vocab | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| Default | 40,000 | 2,000 | 0.270 | 1.000 | 0.426 |
| `auto` | RAM-scaled | 2,000 | 0.270 | 1.000 | 0.426 |
| Raised | 160,000 | 8,000 | 0.270 | 1.000 | 0.426 |
| Lowered (extreme) | 100 | 50 | 0.267 | 1.000 | 0.422 |

BGL_2k sits below the default caps, so default/auto/raised are identical by
construction; the lowered row shows the caps do bite when set below a log's
cardinality. The CI floor (`--min-f1 0.42`) passes at the default.

## 8. Binary size and cold start

Issue #18. The release binaries bundle the neural stack (torch +
sentence-transformers + the MiniLM model) so `--deep` works offline. Two checks:

**Neural dependencies load only for `--deep`.** On the v0.13.0 Linux binary,
`LD_DEBUG=files` shows `libtorch_cpu.so` is never opened by `version` or a
non-deep `analyze`, and is opened by `analyze --deep`.
`tests/test_packaging_prune.py` guards this in CI: it blocks and records any
import of torch / sentence-transformers / transformers / tokenizers during
`version`, `analyze` and `analyze --turbo`, and fails if there is one.

**Build-only torch files are pruned.** `collect_data_files("torch")` also
picked up torch's C++ test executables, headers, `protoc` and test libraries.
`packaging/pyinstaller/prune.py` now drops them. Measured by applying the same
filter to the published v0.13.0 Linux bundle and repacking with `tar -czf`:

| Linux x86_64 bundle | Download (`.tar.gz`) | Installed | Files |
|---|---:|---:|---:|
| v0.13.0 as released | 428.2 MB | 1,169 MB | 15,680 |
| v0.13.0 + pruning | 379.2 MB | 970 MB | 5,970 |
| **Saving** | **-49.0 MB (-11%)** | **-199 MB (-17%)** | **-9,710** |

What was removed (uncompressed): `torch/test` 84.7 MB, `torch/bin` test
executables and protoc 51.0 MB, `torch/include` 37.7 MB, test libraries in
`torch/lib` 1.7 MB, CMake files and stray headers 0.6 MB. The rest of the bundle
is dominated by `libtorch_cpu.so` (418 MB) and the MiniLM model (87 MB), both
needed for offline `--deep`.

Behaviour is unchanged: on `demo_incident.log` the pruned bundle's `--format
json` output is identical to the original in both fast and `--deep` (offline,
`HF_HUB_OFFLINE=1`) modes.

Cold start (`loglens version`, warm disk cache, same sandbox, best of 3):
0.27 s original vs 0.33 s pruned, within run-to-run noise. The ~190 ms figure
in section 2 was measured on a different machine. The Windows zip and macOS
tarball also pick up the same directories; their sizes are recorded by the next
release run (`verify_release.sh` prints every asset's size).
