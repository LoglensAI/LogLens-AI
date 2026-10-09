# Changelog

All notable changes to LogLens AI are documented here.
This project adheres to [Semantic Versioning](https://semver.org).

## [0.13.1] - 2026-10-09

### Other
- Release prep v0.13.1: engine/daemon/error fixes + WiX v5 pin + PyPI tag fix (1399bd2)
- Ruff check --fix + ruff format (f7f388a)
- Ruff --fix (trailing newlines, blank-line whitespace) (2513ead)
- Added autoscaling on supervised head (28d2d7a)
- Fixed the deamon mode (b7e310e)

## [0.13.0] - 2026-10-04

### Bug Fixes
- Fixed minor bugs add extended github ci gate features (6cbf098)
- Restore trailing newlines (transfer artifact) + lower BGL CI gate to realistic 0.38 (90e5e0b)

### Chores
- Remove stale report.json (now git-ignored) (0a00eb3)

### Features
- Self-tuning load distribution with CPU headroom (3b14dec)
- Incident grouping (D13) + origin/blame classifier (9db91ad)
- Finish loglens.v1 additions scores{N,B,P,R,C,S}, incident_id, flags (D12) (e60f272)
- Auto-diagnose trace-kind + blocking impact, non-tech cards (D11d) (927c943)
- Routineness R badge (D11) + recency display +  command (d0e5ded)

### Other
- Close P1.7 (synthetic micro-F1 gate) + sync backlogs to reality (8d13843)
- Interactive log-management explorer over saved results (a7cc911)
- Auto-distribute large files into anomaly families (02b4741)
- Opt-in --parallel — full detector on byte-range slices across cores (ae42568)
- Fixed broken sttest case (07de8fc)
- Added timer for requestes (da1b643)
- Added distributed parsing in other models (22b0751)
- Parallel multi-source analysis across cores (Phase 2) (7f34272)
- Guarded+cached masker, level cache, __slots__ (Phase 1a) (3f2dc97)
- Ephemeral bench-routineness --download (no disk footprint) (ba2ea75)
- Self-learning baseline: analyze remembers each source's normal and improves every run (zero training); daemon test uses --no-learn for cold equivalence (71bbae5)
- Add window-level + template-level metrics (--window) and supervised-head benchmarking (--supervised); BGL window F1 0.75, supervised 0.97 (3f8457d)
- Updated CI gate (457ef58)
- Precision pass: tighten rate + parameter detectors BGL F1 0.266 → 0.395, recall 1.0, synthetic 1.0 (05b2df2)
- LogHub adapter (bench-fetch) for BGL/HDFS real-data benchmarking; first BGL result F1 0.266 (95dfc53)
- Parameteranomaly detector (robust median/MAD per template slot) — catches value outliers, param_anomaly F1 0.0 → 1.0 (0a071fe)
- Session-sequence detector (Markov) flags broken event order, fixes HDFS gap (F1 0.05 → 1.0) (004dc3c)
- Added test folder in gitingor (8c974cf)
- Determinism — add --seed, make turbo ordered + total sort order so tied families never reshuffle (4ca9717)
- Format auto-detect + parser packs (generic/logfmt/k8s CRI) with file-level sniff to recover service (972877a)
- Rich loglens.v1 JSON — template_id, line_numbers[], first/last_seen, sample_lines, placeholders (568a873)
- Add loglens version --json with commit+build provenance; bake build info in CI (2966610)
- Updated documentation (a99e09a)
- Release 0.12.1; auto-derive build version from _version.py (aadccad)
- Release 0.12.1; auto-derive build version from _version.py (58eae9d)
- Release 0.12.1: correct version + full command descriptions (2b785e6)
- Bump to 0.12.0; ensure all command descriptions present (122e2e6)
- Point Cloudsmith publishing at loglensai/loglensai-363o (527f758)
- Allow Cloudsmith publish on manual dispatch (test without a release) (10143a1)
- Host apt/yum repo on Cloudsmith (handles large debs); drop reprepro/gh-pages (f6f5886)

### Testing
- Ship rate_burst + hdfs_sessions fixtures (testlogs/ is gitignored) (960bb00)

## [0.12.0] - 2026-09-25

### Other
- Drop Intel Mac from build matrix; Intel users install via pip (b63433b)
- Drop Intel Mac from build matrix; Intel users install via pip (4fccd2a)
- Upload binaries as artifacts on manual runs; gate release/apt/tap jobs to release events (e6e6e50)
- Fix installer build: absolute bundled-model path + CPU-only model download (5ce9d05)
- Fix release-binaries workflow: gate tap step on env, not secrets (264d215)
- Add daemon mode + cross-platform installers; bundle neural, fix help & warnings (6555599)

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
- Platform-agnostic — UTF-8/CRLF handling, Windows resource guard, spawn fallback (b02a1f3)

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


