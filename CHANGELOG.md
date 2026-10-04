# Changelog

All notable changes to LogLens AI are documented here.
This project adheres to [Semantic Versioning](https://semver.org).

## [0.13.0] - 2026-10-04

Consolidates the performance, horizontal-scale, and log-management work. Every
speed-up ships with a byte-identical equivalence test - **detection accuracy is
unchanged** (synthetic suite micro-F1 **1.000**, BGL unsupervised F1 **0.426**).

### Features
- **Self-tuning load distribution** for `analyze`: large local files are split
  into byte-range slices across cores automatically, with CPU headroom left for
  other work; opt-in `--parallel` runs the full detector per slice.
- **Auto-distribute large files into anomaly families** for a compact,
  scannable result instead of per-line noise.
- **Interactive log-management explorer** over saved results: anomaly vs
  anomaly-family views, time-range queries, severity-count filters, and family
  search - all served from a results file so queries never touch detection.
- Distributed parsing across detection modes; analyze timer / ETA / progress.

### Install & distribution
- **One-line installers that need no package manager:** `scripts/install.sh`
  (macOS + Linux `curl … | sh`, Apple Silicon **and** Intel) and
  `scripts/install.ps1` (Windows `irm … | iex`) download the self-contained
  binary straight from GitHub Releases. Both are attached to every release.
- **Windows MSI** (`loglens-windows-x86_64.msi`, WiX) for a machine-wide,
  double-click install that adds LogLens to `PATH` and auto-upgrades.
- Intel macOS (`loglens-macos-x86_64`) is now built and published again, and the
  Homebrew formula serves both Mac architectures.
- Release workflow now actually updates the Homebrew tap and Scoop bucket (was a
  TODO stub) and attaches the installer scripts + MSI to the release.
- New `INSTALL.md` with per-OS guides; README install table reworked.

### GitHub Action
- Analyze a single file, a **glob**, or a **list** of files in one run.
- New inputs: `comment-on-pr` (sticky PR comment), `sarif` (upload to the
  Security tab), `upload-report` (JSON artifact), `min-score`, `limit`.
- New outputs: `anomaly-count`, `incident`, `report-json`.

### Performance
- Shared template grouping across detectors and score memoization - faster
  detection, byte-identical output.
- Lean clustering from per-template vectors instead of expanding to
  `(n_lines, dim)` - fixes the out-of-memory halt on multi-million-line files.

### Build & CI
- **Single source of truth for the version** (`src/loglens/_version.py`) bumped
  to 0.13.0 and aligned across API / CLI / `hatch version` (enforced by the
  `consistency` job) and every packaging manifest (winget / scoop / homebrew /
  Inno Setup); provenance via `loglens version --json`.
- New standing synthetic-suite micro-F1 ≥ 0.99 gate (G1, P1.7).

### Bug Fixes
- Ship the `testlogs/hdfs_sessions.log` and `testlogs/rate_burst.log` fixtures
  that `testlogs/` being git-ignored had dropped - a clean checkout now runs the
  parallel-scan and multi-source suites green.
- The CI "accuracy gate" step was a silent no-op running a smoke script that
  asserted on the removed `hello` command; made it a real check and renamed the
  step. The actual accuracy floors (BGL, G1) are unchanged.
- Remove the stale `report.json` benchmark dump accidentally committed at the
  repo root, and git-ignore it.

_Note: 0.12.0 and 0.12.1 were incremental releases without their own changelog
entries; 0.13.0 is the first release carrying the full scale + log-management
surface._

## [0.11.0] - 2026-09-23

### Bug Fixes
- Fixed issue #3 (1db23af)

### Chores
- Bump version to 0.10.0 (fc6abb6)

### Other
- Add GitHub Action (analyze-action) + BrokenPipe fix (b204229)
- Autofix trailing whitespace and newline (4315b95)
- Unified scoring: correct scoring.py + normalized formatting (47262c5)
- Unified scoring: correct scoring.py + normalized formatting (1346428)
- Fix trailing-whitespace/newline lint from file transfer (78c5880)
- Unify scoring across live/classic/turbo; de-saturated hard-flag; explainable output + progress (539c4f0)
- Updated ReadMe.md (db7844f)

## [0.9.0] - 2026-09-22

### Bug Fixes
- Platform-agnostic - UTF-8/CRLF handling, Windows resource guard, spawn fallback (b02a1f3)

### Chores
- Updated the readme. (4852f22)

### Documentation
- Tracking badges + reproducible benchmark links (15e0b1b)

### Other
- Added new logo image (8672fc8)
- Phase 7: enforce layer boundaries in CI (import-linter); move entry points to interface (2d75603)
- Phase 6: reorganize modules into layer packages (domain/detection/application/infrastructure/interface) (0fea529)
- Fix CI mypy: skip numpy 2.x PEP695 stubs; type LiveProgress.task_id (2ad3ab0)
- Phase 5: clear mypy to zero, enforce ruff/mypy + coverage gates in CI (b51e80f)
- Phase 4: LLM redaction, webhook SSRF guard, secret + thread-safety hardening (47e5afb)
- Phase 3: fix live api inversion, extract reporting service, alerter port (08f31ba)
- Added cloud.py (fa5c50a)
- Phase 2: SRP decomposition split detector.detect, extract cloud-JSON, typed LogEntry, dedup CLI (39881d3)
- Normalize trailing newlines + import order (e846906)
- Phase 1: single severity source of truth, one masker, drop dead code, tidy scripts (e4822fa)
- Removed the data folder (9244d4b)
- Phase 0: fix silent render bug, remove dead deps, add observability + tooling (6a496f1)
- Add file-type guard + LLM provider abstraction (Closes #2) (dc50f9d)
- Merge pull request #1 from Dibya12345/main

chore: Updated the readme. (90773c0)
- Added Ci gate check (933dda9)

## [0.8.1] - 2026-09-14

### Bug Fixes
- Correct scikit-learn version specifier (was invalid TOML) (9db0199)
- Pin sklearn, silence unpickle warning; split manual PyPI publish (4b95183)

### CI/Build
- Split PyPI publish into a manual, tag-selectable workflow (6663d9c)

## [0.8.0] - 2026-09-14

### Features
- Bundle default model with auto-load; compress models; cache features (d3431e7)
- Bundle default model with auto-load; compress models; cache features (502d5c4)
- Bundle default model with auto-load; compress models; cache features (4411d45)

### Other
- Merge branch 'main' of github.com:ParasRajput810/LogLens-AI (47f1ce6)

## [0.4.2] - 2026-09-13

### Other
- Merge branch 'main' of github.com:ParasRajput810/LogLens-AI (afdf74c)

### Performance
- Chunk embeddings; add bundled bgl model (6e829c3)

## [0.4.0] - 2026-09-12

### Features
- Add supervised train/analyze --model; fix stdin ingestion (f9fb1bc)

## [0.3.4] - 2026-09-07

### Chores
- Sync version to 0.3.3 to match latest tag (8b0725b)

### Documentation
- Add changelog and fix backfill range logic (295f19a)

### Other
- Updated documentation (82c4fe4)
- Added automated release pipeline and changelogs (40a80bb)
- Added the CI pipeline and benchmarking in the CI pipeline (56e83f7)
- Added docker configuration (292b354)

## [0.3.3] - 2026-07-12

### Other
- Updated ReadMe.md (b6d961b)

## [0.3.2] - 2026-07-12

### Other
- Updated dockerfile (3b871e5)
- Updated docker.md (74c1fae)

## [0.3.1] - 2026-07-12

### Bug Fixes
- Fixed assertion in test_cli.py (eb36064)

### CI/Build
- Bump to 0.3.0, drop unused hdbscan/umap deps, add [deep] extra (909c45b)

### Features
- Add turbo mode for parallel log scanning (4351d69)
- Add benchmark command for accuracy certification (407a790)
- Add Stage 4 validation harness (P/R/F1, grid-search, supervised head) + tests (3ea687d)
- Add Otsu unsupervised auto-threshold + tests (5414ace)
- Embeddings engine, synonym learner, deep mode, parser fix, accuracy & benchmark tests (d314ec0)
- Async worker pool with live progress bar (e744424)
- Log parser with auto-detection and normalization (ad25bec)
- Async ingestion pipeline (file, stdin, http) (73b45c2)

### Other
- Added docker configuration and docker workflows (5ebe5aa)
- Version bump to 0.3.1 (ff9840f)
- Updated readm.md (e0526c0)
- Added monitoring and monitoring channels (45c4f3d)
- Documentation.md (a10279e)
- Added sdk integration and watch mode (447f5e2)
- Bumped version 0.2.0 to poetry and updated readme.md (e2a1319)
- Unify pipeline with template grouping, recalibrated scoring, and high-performance benchmarking (fb86762)
- LLM tests passing, RCA + HTML report + turbo verified (7511a4e)
- Updated readm.md and bechmark.md (ca41f37)
- Detector model tuning (cb843ed)
- Performed bechmarking (c360930)
- Graded semantic outlier scoring, deep-mode weight boost, --explain flag (b9b017c)
- Improve anomaly accuracy; add eval harness + HTML report (e32ba1c)
- Updated Readme.md (67be79e)
- Added supervised head in benchmarking and READme.md (2947c49)
- Added benchmarking in CI pipeline (6933b9a)
- Refined the anomaly detctor model (72990e1)
- Update git ci pipeline (5424e66)
- Fixed git ci tests (dcef08b)
- Project scaffold and CLI skeleton (bcd0f6a)

### Testing
- Add detector/clustering unit tests (10 cases) (3a3f69e)
- Add cloud JSON mapping tests, fix embeddings shape (430) and synonym assertion (07754ef)


