# LogLens AI - GitHub Action

Run LogLens on your CI logs to surface and explain anomalies, and optionally
**fail the build** when a real incident shows up. Everything runs on the runner -
your logs never leave it.

It produces:
- a **job summary** (incident table in the Actions run),
- inline **annotations** on the run,
- an optional **sticky PR comment** with the summary,
- an optional **SARIF** upload to the Security tab,
- an optional **JSON report artifact**,
- **step outputs** (`anomaly-count`, `incident`, `report-json`), and
- a **non-zero exit** (via `fail-on`) that fails the job.

It analyzes a single file, a **glob**, or a newline/comma **list** of files.

## Usage

```yaml
name: build
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # your build/test - capture its output
      - name: Build
        run: |
          set +e
          your-build-command 2>&1 | tee build.log
          exit ${PIPESTATUS[0]}

      # analyze the log; fail the job on any ERROR-or-worse anomaly
      - name: LogLens
        if: always()          # run even if the build step failed
        uses: LoglensAI/LogLens-AI@v0.13.0
        with:
          source: build.log
          fail-on: error       # critical | error | warning | fatal | any
          mode: fast           # fast | turbo | deep
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `source` | *(required)* | Log file(s): a path, a glob (`logs/*.log`), or a newline/comma list. |
| `fail-on` | `""` | Fail the job if an anomaly is this severity or worse (`critical` / `error` / `warning` / `fatal` / `any`). Empty = report only. |
| `mode` | `fast` | Detection mode: `fast`, `turbo`, or `deep`. |
| `min-score` | `0` | Only report anomalies scoring at least this (0–1). |
| `limit` | `25` | Max anomalies listed per file in the summary/comment. |
| `comment-on-pr` | `false` | Post/update a sticky summary comment on the PR. Needs `pull-requests: write`. |
| `sarif` | `false` | Emit SARIF and upload to the Security tab. Needs `security-events: write`. |
| `upload-report` | `false` | Upload the aggregated JSON report as a build artifact. |
| `report-name` | `loglens-report` | Artifact name for the JSON report. |
| `version` | latest | Pin a `loglensai` version, e.g. `0.13.0`. |
| `python-version` | `3.12` | Python version to run on. |

## Outputs

| Output | Description |
|--------|-------------|
| `anomaly-count` | Total anomalies across all analyzed files. |
| `incident` | `true` if any file tripped the incident flag. |
| `report-json` | Path to the aggregated JSON report (when `upload-report` is on). |

## Full example (PR comment + SARIF + gating)

```yaml
jobs:
  logs:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write     # for comment-on-pr
      security-events: write   # for sarif
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: |
          set +e
          your-build-command 2>&1 | tee build.log
          exit ${PIPESTATUS[0]}
      - name: LogLens
        if: always()
        id: loglens
        uses: LoglensAI/LogLens-AI@v0.13.0
        with:
          source: "build.log\n logs/*.log"
          fail-on: error
          comment-on-pr: true
          sarif: true
          upload-report: true
      - run: echo "Found ${{ steps.loglens.outputs.anomaly-count }} anomalies"
        if: always()
```

## Notes

- Use `if: always()` so LogLens still analyzes the log when the build step fails -
  that's exactly when you want the root cause surfaced.
- `fail-on` empty (the default) makes the Action **advisory** - it posts the
  summary and annotations but never fails the job. Turn on gating when you trust it.
- The Action wraps the same `loglens analyze --format json` CLI, so behavior matches
  what you get locally.