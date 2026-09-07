# Changelog

All notable changes to LogLens AI are documented here.
This project adheres to [Semantic Versioning](https://semver.org).

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


