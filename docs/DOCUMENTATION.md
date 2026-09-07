# 📖 LogLens AI -Command Reference

Complete guide to every LogLens command, flag, and workflow.

> **Note on syntax:** `analyze` and `ask` take the log source via the `--source` option (a file path or URL). `benchmark` and `bench` take the file as a positional argument.

---

## Table of contents

1. [Installation](#installation)
2. [Global usage](#global-usage)
3. [`version`](#version)
4. [`hello`](#hello)
5. [`analyze`](#analyze) -the main command
6. [`watch`](#watch) -live log watching (docker, kubernetes, servers)
7. [Using LogLens inside Python](#using-loglens-inside-python-the-sdk) -the SDK
8. [Always-on monitoring & alerts](#always-on-monitoring--alerts-loglensinit) -Slack / Teams / Email, Sentry-style
9. [`ask`](#ask) -natural-language Q&A
10. [`benchmark`](#benchmark) -labeled accuracy evaluation
11. [`bench`](#bench) -speed / memory profiling
12. [AI (LLM) configuration](#ai-llm-configuration)
13. [Common workflows](#common-workflows)
14. [Exit codes](#exit-codes)

---

## Installation

```bash
pip install loglensai

# for deep (neural) mode
pip install "loglensai[deep]"
```

Verify:

```bash
loglens version
```

---

## Global usage

```bash
loglens [COMMAND] [OPTIONS]
loglens --help
loglens [COMMAND] --help
```

Available commands: `version`, `hello`, `analyze`, `watch`, `ask`, `benchmark`, `bench`.

---

## `version`

Print the installed LogLens version.

```bash
loglens version
```

---

## `hello`

Health-check command that confirms LogLens is installed and runnable.

```bash
loglens hello
```

---

## `analyze`

The primary command. Ingests a log source, detects anomalies, groups them into families, and optionally runs AI root-cause analysis and generates an HTML report.

```bash
loglens analyze --source <PATH|URL|-> [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--source` | string | *(required)* | Log source: file path or URL. |
| `--dry-run` | flag | off | Stop after ingestion; show stats only (no detection). |
| `--verbose` | flag | off | Show a sample parsed entry (field breakdown). |
| `--workers` | int | 4 | Number of parallel workers. |
| `--deep` | flag | off | Use neural (transformer) embeddings -most accurate, slower. Requires the `deep` extra (`pip install "loglensai[deep]"`). |
| `--turbo` | flag | off | Fast multiprocess scan for huge files (byte-range + template dedup, skips embeddings). |
| `--limit` | int | 20 | Max anomaly **families** to display. |
| `--sort-by` | string | `severity` | Sort anomalies by `severity`, `time`, or `service`. |
| `--explain` | int | 0 | Show top-N scored entries (flagged or not) with score + reasons -for debugging near-misses. |
| `--rca` | flag | off | Run AI root-cause analysis on detected anomalies (requires an LLM key). |
| `--provider` | string | env | LLM provider: `openai`, `azure`, or `groq`. |
| `--llm-model` | string | env | LLM model name / Azure deployment name. |
| `--api-key` | string | env | LLM API key (prefer the environment variable). |
| `--rca-out` | string | -| Save the RCA narrative to a markdown file (e.g. `rca.md`). |
| `--html` | string | -| Save a standalone offline HTML report (e.g. `report.html`). Includes RCA if `--rca` is set. |

### Modes

- **fast** (default): from-scratch TF-IDF statistical detector.
- **turbo** (`--turbo`): same accuracy, optimized throughput. Best for large files.
- **deep** (`--deep`): transformer semantic embeddings, best precision.

> `--turbo` and `--deep` are mutually meaningful -pick one. If neither is set, fast mode runs.

### Examples

```bash
# Basic -fast mode, format auto-detected
loglens analyze --source app.log

# Huge file, maximum speed
loglens analyze --source /var/log/prod.log --turbo --workers 8

# Best precision (neural)
loglens analyze --source app.log --deep

# Show only the top 5 families, sorted by service
loglens analyze --source app.log --limit 5 --sort-by service

# Debug why something almost got flagged
loglens analyze --source app.log --explain 15

# Just count/ingest, no detection
loglens analyze --source app.log --dry-run

# Full incident workflow: scan + AI root-cause + HTML dashboard
loglens analyze --source app.log --turbo --rca --html incident_report.html

# Save both the RCA markdown and the HTML report
loglens analyze --source app.log --rca --rca-out rca.md --html report.html
```

### Output

- **Anomaly families** panel: each unique incident with an `×N` occurrence count and a max score.
- **Category breakdown tree**: counts per severity level.
- **INCIDENT flag**: shown when ≥30% of entries are severe.
- **HTML report** (`--html`): dark-themed dashboard with severity breakdown, per-service breakdown, and score distribution -fully offline (no internet required).

---

## `watch`

**What it does, in one line:** it sits next to your running app and taps you on the shoulder the moment something goes wrong - instead of you scrolling through thousands of log lines later.

Think of it like a security camera for your logs. Normally, when an app runs (a website, a database, anything inside Docker), it constantly writes little status messages called *logs*. 99% of them are boring: "request ok", "user logged in". Hidden between them are the important ones: "connection refused", "out of memory", "disk failure". `watch` reads the stream live, ignores the boring lines, and prints **only the problems** - the moment they happen.

### How to use it

Give it the same command you would normally use to see your logs, in quotes:

```bash
# watch a Docker container
loglens watch "docker logs -f my-api"

# watch an app running on Kubernetes
loglens watch "kubectl logs -f deploy/api -n prod"

# watch a service on a Linux server
loglens watch "journalctl -u nginx -f"
```

Then just leave it running. Press **Ctrl-C** whenever you want to stop.

### What you'll see

While it runs, nothing appears as long as everything is healthy. When a problem shows up, you get a line like this, instantly:

```
2024-03-10T14:30:00Z [ERROR] api-gateway 0.84 connection reset by peer during checkout
          severity ERROR; recurring ERROR pattern (14x); failure keyword in severe entry
```

That reads as: *when* it happened, *how bad* it is (`ERROR`), *which part* of your system (`api-gateway`), a *score* from 0 to 1 (closer to 1 = more serious), *what* happened, and underneath - in plain words - *why* LogLens thinks it matters.

Really serious lines (CRITICAL, FATAL, EMERGENCY) are shown **immediately**, without any waiting. When you press Ctrl-C, you get a closing summary card:

```
╭──────────── WATCH SUMMARY ────────────╮
│ lines analyzed: 12,419                │
│ anomalies:      15  (ERROR: 14, FATAL: 1)
│ incident mode:  no                    │
╰───────────────────────────────────────╯
```

### When would I use this?

- You just deployed a new version and want to know *right away* if it starts failing.
- Something feels slow or broken and you want to stare at one clean feed of problems instead of a firehose of noise.
- You want to keep an eye on a server overnight - leave `watch` running and check the summary in the morning.

### Useful options

| Option | What it means |
|--------|---------------|
| `--window 500` | How many recent lines LogLens keeps in mind while judging (default 500). |
| `--quiet` | Print only the problems, no status messages. |
| `--threshold 0.85` | Be pickier: only show things scoring above 0.85. |
| `--mode deep` | Slower but smarter judging (uses the neural model). |
| `--rca` | When you stop watching, the AI reads everything that was caught and writes a short **root-cause story**: what most likely broke, and in what order. |
| `--rca-out rca.md` | Also save that AI explanation as a file you can share. |
| `--html-report out.html` | When you stop, save a **one-page visual dashboard** (open it in any browser - charts, the anomaly list, and the AI story if `--rca` was on). |

The AI options use the same setup as the rest of LogLens - set `LOGLENS_LLM_PROVIDER`, `LOGLENS_LLM_MODEL` and `LOGLENS_LLM_API_KEY` once (see [AI (LLM) configuration](#ai-llm-configuration)). A typical "leave it running during a deploy" command looks like:

```bash
loglens watch "docker logs -f my-api" --rca --html-report deploy_watch.html
```

You watch problems stream in live; when you press Ctrl-C you get the summary, the AI's explanation of what went wrong, and a dashboard file you can send to a teammate.

---

## Using LogLens inside Python (the SDK)

**What it does, in one line:** everything the `loglens` command can do, but callable from your own Python code - so your app can check logs by itself, or even raise an alarm about *its own* problems while it runs.

You don't need to know how the detection works. There are three tools, from simplest to most advanced:

### 1) `analyze()` - "here are some logs, tell me what's wrong"

You hand it logs (a file, a list of lines, or even a command), and it hands back the problems, worst first.

```python
from loglens import analyze

result = analyze("app.log")                     # a log file
result = analyze(lines=my_list_of_lines)        # lines you already have
result = analyze(cmd="docker logs my-api")      # output of a command

for a in result.anomalies:
    print(a.level, a.score, a.message, a.reasons)

print(result.summary())
# {'entries': 5000, 'anomalies': 13, 'incident': False,
#  'by_level': {'FATAL': 1, 'ERROR': 12}, 'format': 'STANDARD'}
```

Each anomaly tells you: how bad (`level`), how confident (`score`, 0–1), what happened (`message`), where (`service`), and why it was flagged (`reasons`, in plain words).

**Use it when:** you want a script that checks last night's logs, a small dashboard, a daily report - anything where you have logs and want answers programmatically. Inside async apps (like FastAPI) use `await analyze_async(...)` - same thing, doesn't block your app.

### 2) `LogLensHandler` - your app raises its own alarm

This is the one-liner that plugs LogLens into any Python application. Python apps already write logs through the standard `logging` module - this handler quietly reads that stream from the inside, and calls **your function** the moment a log line looks like trouble.

```python
import logging
from loglens import LogLensHandler

def alert_me(anomaly):
    print("🚨", anomaly)          # or send Slack / email / anything

logging.getLogger().addHandler(LogLensHandler(on_anomaly=alert_me))
```

That's the entire setup. From then on, if your app logs something like `database connection refused`, your `alert_me` function fires within seconds - while the app keeps running normally. If your alert function itself crashes, nothing happens to your app; LogLens swallows the error safely.

**Use it when:** you run a FastAPI/Django/any-Python service and want to hear about problems *from the app itself*, without setting up any external monitoring system.

### 3) `LiveDetector` - for custom streaming setups (advanced)

If your logs come from somewhere unusual (a message queue, a socket, anything), feed lines in one by one and get anomalies out:

```python
from loglens import LiveDetector

det = LiveDetector(window=500)
for line in my_source():
    for hit in det.feed(line):     # returns new anomalies, or nothing
        print(hit)
print(det.summary())               # totals when you're done
```

It remembers the last `window` lines, re-judges them periodically, reports each problem **exactly once**, shows CRITICAL/FATAL lines instantly, and never crashes your loop even if one batch of lines is weird. (This is exactly what powers `loglens watch` under the hood.)

**Quick chooser:**

| You want... | Use |
|-------------|-----|
| "Check these logs and give me the problems" | `analyze()` |
| "My Python app should alert me when it's in trouble" | `LogLensHandler` |
| "I have my own stream of lines to feed in" | `LiveDetector` |
| "Watch docker/kubernetes logs from the terminal" | `loglens watch` (no Python needed) |

### 4) The AI layer - explanations and shareable reports, from code

Everything the CLI's AI can do is also one method call away in Python. After any `analyze()` (and on a `LiveDetector` too), you can:

```python
result = analyze("app.log")

rca = result.rca()                 # AI writes a short root-cause story
print(rca.report)                  # markdown: what broke, and why

ans = result.ask("did the database or the network fail first?")
print(ans.report)                  # AI answers about YOUR anomalies

result.save_html("report.html", rca=rca)   # one-page dashboard for the browser
result.save_rca("rca.md", rca=rca)         # the AI story as a file
```

- **`rca()`** - hands the anomalies to the AI and gets back a plain-language explanation of the most likely root cause. Great for pasting into an incident ticket.
- **`ask("...")`** - free-form questions about what was found ("which service failed first?", "is this a disk problem?").
- **`save_html(path)`** - writes a self-contained dashboard file: level charts, the worst anomalies, and the AI story if you pass one. Open in any browser, email it to anyone - no LogLens needed to view it.
- **`save_rca(path)`** - the AI explanation as a markdown file.

The same methods exist on a live session: `det.rca()`, `det.ask(...)`, `det.save_html(...)` - so a long-running watcher can end its day by writing its own incident report.

One-time setup (same as the CLI): set `LOGLENS_LLM_PROVIDER`, `LOGLENS_LLM_MODEL` and `LOGLENS_LLM_API_KEY`, or pass `provider=`, `model=`, `api_key=` directly to any of these methods. Model choice note: `analyze()` accepts `mode="fast"` (default) or `mode="deep"` (neural, slower, best for subtle cases) - the same modes as the CLI.

---

## Always-on monitoring & alerts (`loglens.init`)

**What it does, in one line:** add ONE line to your app, and the moment anything serious goes wrong, a message lands in your Slack, Teams, or email - with a one-sentence explanation of what probably broke.

If you've heard of Sentry, this is that idea: your app watches *itself* and calls for help. If you haven't - imagine a smoke detector for your application. You install it once and forget about it; it only makes noise when there's smoke.

### Step 1 - tell LogLens where to send alerts (a `.env` file)

Create a file called `.env` next to your app and fill in whichever channels you use (one is enough - all configured ones get used):

```bash
# Slack: create an "incoming webhook" in Slack and paste its URL
LOGLENS_SLACK_WEBHOOK=https://hooks.slack.com/services/XXX/YYY/ZZZ

# Microsoft Teams: same idea - an incoming webhook URL from Teams
LOGLENS_TEAMS_WEBHOOK=https://outlook.office.com/webhook/...

# Email (works with Gmail, Outlook, any SMTP)
LOGLENS_EMAIL_SMTP_HOST=smtp.gmail.com
LOGLENS_EMAIL_SMTP_PORT=587
LOGLENS_EMAIL_USER=alerts@mycompany.com
LOGLENS_EMAIL_PASSWORD=your-app-password
LOGLENS_EMAIL_TO=oncall@mycompany.com, dev-team@mycompany.com
```

### Step 2 - one line in your `main.py`

```python
import loglens
loglens.init(app_name="checkout-api")
```

Done. That's the whole setup.

### What happens from then on

- Every log message your app writes is watched live.
- If your app **crashes** (an error nobody caught), that's captured and alerted too - even as the process dies.
- When something serious happens, every configured channel gets a message like:

```
🔴 [checkout-api] CRITICAL · db (score 0.95)
database connection refused during checkout
↳ likely cause: a dependency is down or refusing connections (seen in db)
at 2024-03-10T14:30:00Z
```

That "likely cause" line is the point: whoever sees the alert instantly knows *what kind* of problem it is, before opening a single log file. If you've configured an AI provider (see [AI (LLM) configuration](#ai-llm-configuration)), the AI writes that line; if not, LogLens writes it itself from built-in knowledge - **so it always works, zero AI setup required**.

### It's polite by design

- **No spam:** the same problem repeating 500 times becomes **one** alert (then again after a cool-down, default 5 minutes). Max 30 alerts per hour, total.
- **No risk to your app:** alerts are sent from a background thread. If Slack is down, if the email fails, if anything in alerting breaks - your application never notices.
- **Adjustable bar:** by default only ERROR-and-worse can alert. `loglens.init(app_name="x", min_alert_level="CRITICAL")` makes it stricter.

### When would I use this vs the other tools?

| Situation | Use |
|-----------|-----|
| "I want to be *told* when my running app breaks" | `loglens.init()` ← this |
| "I want to *watch* a container's logs right now" | `loglens watch` |
| "I have a log file and want answers" | `analyze()` / `loglens analyze` |

---

## `ask`

Ask a free-form question about a log file. LogLens detects anomalies locally, then sends only grouped anomaly summaries to the LLM to answer your question.

```bash
loglens ask "<QUESTION>" --source <PATH> [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `QUESTION` | string | *(required, positional)* | The question, e.g. `"why did db-service degrade?"` |
| `--source` | string | *(required)* | Log file path. |
| `--deep` | flag | off | Use neural embeddings for detection. |
| `--provider` | string | env | LLM provider: `openai`, `azure`, or `groq`. |
| `--llm-model` | string | env | LLM model / Azure deployment name. |
| `--api-key` | string | env | LLM API key. |

### Examples

```bash
loglens ask "why did the payment service start timing out?" --source app.log

loglens ask "what is the root cause of the outage?" --source prod.log --deep

loglens ask "which service failed first?" --source app.log --provider groq
```

> Requires an LLM key (see [AI configuration](#ai-llm-configuration)). Detection stays 100% local; only anomaly summaries are sent.

---

## `benchmark`

Evaluate detection **accuracy** against a labeled dataset (precision / recall / F1). Use this to validate the detector against ground-truth data like Loghub.

```bash
loglens benchmark <DATASET> [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `DATASET` | string | *(required, positional)* | Path to labeled log file. |
| `--format` | string | `bgl` | Label format: `bgl`, `jsonl`, or `labeled`. |
| `--limit` | int | all | Max lines to load. |
| `--grid` | flag | off | Grid-search `feature_weight × threshold` for the best F1. |
| `--supervised` | flag | off | Train + evaluate a supervised RandomForest head. |
| `--min-f1` | float | -| Fail (exit 1) if baseline F1 falls below this -useful in CI. |

### Examples

```bash
# Basic accuracy on a BGL-labeled file
loglens benchmark data/bgl/BGL.log --limit 500000

# Grid-search the best hyperparameters
loglens benchmark data/bgl/BGL.log --grid

# Compare against a supervised head
loglens benchmark data/bgl/BGL.log --supervised

# CI gate: fail the build if F1 drops below 0.90
loglens benchmark data/bgl/BGL.log --min-f1 0.90
```

### Output

A table with Precision / Recall / F1 for the rule+embeddings baseline (and the supervised head if requested), plus grid-search best params when `--grid` is used.

---

## `bench`

Profile **speed and memory** across modes -the "insight in seconds on one box" story.

```bash
loglens bench <SOURCE> [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `SOURCE` | string | *(required, positional)* | Log file to benchmark. |
| `--modes` | string | `fast,turbo` | Comma-separated modes: `fast`, `deep`, `turbo`. |
| `--workers` | int | 4 | Number of parallel workers. |
| `--out` | string | -| Write markdown results to this file. |

### Examples

```bash
# Compare fast vs turbo
loglens bench app.log --modes fast,turbo

# All three modes, save a markdown table for the README
loglens bench app.log --modes fast,deep,turbo --out BENCHMARK.md

# High core count
loglens bench huge.log --modes turbo --workers 16
```

### Output

A table with: Mode, Lines, Time (s), Lines/s, Anomalies, Peak RAM (MB). With `--out`, the same table is written as markdown.

---

## AI (LLM) configuration

The `--rca` flag and the `ask` command require an LLM. LogLens supports **OpenAI**, **Azure OpenAI**, and **Groq**. Configure via environment variables (recommended) or flags.

### Environment variables

```bash
export LOGLENS_LLM_PROVIDER=openai      # openai | azure | groq
export LOGLENS_LLM_API_KEY=sk-...
export LOGLENS_LLM_MODEL=gpt-4o-mini    # or Azure deployment name
```

### Or via flags

```bash
loglens analyze --source app.log --rca \
  --provider openai --llm-model gpt-4o-mini --api-key sk-...
```

### Privacy

Only **grouped anomaly summaries** (representative line + `×N` count + score) are sent to the LLM -never your full log file. Detection itself runs entirely locally.

---

## Common workflows

**1. Triage a production incident fast**

```bash
loglens analyze --source /var/log/prod.log --turbo --rca --html incident.html
```
Scan the whole file in seconds, get grouped families, an AI root-cause narrative, and a shareable offline dashboard.

**2. Investigate a specific service**

```bash
loglens ask "why is db-service slow?" --source prod.log --deep
```

**3. Regression-gate in CI**

```bash
loglens benchmark data/labeled.log --format jsonl --min-f1 0.90
```

**4. Publish performance numbers**

```bash
loglens bench sample.log --modes fast,turbo,deep --out BENCHMARK.md
```

**5. Debug a near-miss (why wasn't X flagged?)**

```bash
loglens analyze --source app.log --explain 20
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | Failure -no valid entries, missing deep-mode dependency, LLM/RCA error, or benchmark F1 below `--min-f1`. |

---

*For architecture and reproducible accuracy details, see [README.md](../README.md) and [BENCHMARK.md](BENCHMARK.md).*