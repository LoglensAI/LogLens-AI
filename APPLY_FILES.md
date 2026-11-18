# Apply today's 7 fixes (full files — no patches)

Reset any stuck patch state first:
    git am --abort        # if a git am is in progress
    git status            # clean main

Extract this zip at your repo root and copy the files in (includes .github):
    unzip -o loglens_today.zip
    cp -rf loglens_today/. .
    rm -rf loglens_today loglens_today.zip

Review + verify (mirrors CI):
    git add -A && git status        # expect 5 new + 6 modified files
    ruff check src/ tests/
    ruff format --check src/ tests/
    mypy src/loglens
    pytest -q

Commit (one commit is fine, or split by theme):
    git commit -m "fixes: gh templates, release-attach-on-dispatch, install.ps1 lint, RELEASING.md, env-caps, model-mismatch warning"
    git push

## Files (5 new, 6 modified)
NEW:
  .github/ISSUE_TEMPLATE/bug_report.yml
  .github/ISSUE_TEMPLATE/feature_request.yml
  .github/ISSUE_TEMPLATE/config.yml
  .github/pull_request_template.md
  RELEASING.md
MODIFIED:
  .github/workflows/release-binaries.yml   (attach binaries on manual dispatch)
  .github/workflows/ci.yml                 (install.ps1 PSScriptAnalyzer lint job)
  src/loglens/detection/synonyms.py        (LOGLENS_MAX_SYNONYM_VOCAB)
  src/loglens/detection/detector.py        (LOGLENS_MAX_CLUSTER_GROUPS)
  src/loglens/interface/cli.py             (model-mismatch warning)
  tests/test_cli.py                        (model-mismatch test)

All verified locally: ruff clean, mypy clean, test_cli.py 36 passed, YAML parses.

Note: if `git diff` shows whole files changed, your checkout is CRLF. Fix once with:
    git config core.autocrlf input
then re-copy — diffs will then show only the real changes.
