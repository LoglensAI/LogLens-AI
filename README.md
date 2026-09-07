<div align="center">

# 🔍 LogLens AI

### AI-powered log anomaly detection that reads your logs like a senior engineer.

**Detect anomalies by _meaning_ · explain them in plain English · group them into incidents · watch services live · alert Sentry-style - 100% local, zero setup, $0/GB.**

[![PyPI version](https://img.shields.io/pypi/v/loglensai?color=3b82f6&label=pip%20install%20loglensai&logo=pypi&logoColor=white)](https://pypi.org/project/loglensai/)
[![Python](https://img.shields.io/pypi/pyversions/loglensai?color=3776ab&logo=python&logoColor=white)](https://pypi.org/project/loglensai/)
[![Docker](https://img.shields.io/badge/docker-loglensai%2Floglens-2496ed?logo=docker&logoColor=white)](https://hub.docker.com/r/loglensai/loglens)
[![License: MIT](https://img.shields.io/badge/License-MIT-3fb950.svg)](LICENSE)
[![F1 Score](https://img.shields.io/badge/BGL%20F1-0.957-8957e5)](docs/BENCHMARK.md)
[![Recall](https://img.shields.io/badge/recall-1.000%20(0%20missed)-3fb950)](docs/BENCHMARK.md)

```bash
pip install loglensai
```

**→ first real insight in seconds. No account. No agent. No cloud. No bill.**

[Website](https://loglensai.com) · [Documentation](https://loglensai.com/docs) · [Benchmarks](docs/BENCHMARK.md) · [Docker Hub](https://hub.docker.com/r/loglensai/loglens)

</div>

---

## Why LogLens AI

Most log platforms give you a score and a bill. **LogLens AI gives you answers - and runs entirely on your own machine.** It's the only log anomaly detector with **published, reproducible F1**, plus **explainable, grouped incidents**, **live watching**, **one-line self-alerting for your own apps**, and an **optional AI root-cause layer**.

|  | **LogLens AI** | Splunk | Datadog | Elastic ML | DeepLog (research) |
|---|:---:|:---:|:---:|:---:|:---:|
| ⏱️ Setup time | **seconds** | days–weeks | hours–days | hours | N/A |
| 💰 Cost | **$0/GB** | ~$150/GB/yr | ~$0.10–1.27/GB | license | free |
| 🔒 Runs offline / air-gapped | **✅** | partial | ❌ | partial | ✅ |
| 📊 Published, reproducible accuracy | **✅ F1 0.957** | ❌ | ❌ | ❌ | ✅ (HDFS only) |
| 💬 Explains *why* a line is anomalous | **✅** | scores only | scores only | scores only | ❌ |
| 🧩 Groups repeats into incident families | **✅** | partial | partial | ❌ | ❌ |
| 👀 Live watch (docker / k8s / journald) | **✅** | ✅ | ✅ | partial | ❌ |
| 🚨 Self-alerting for your app (1 line) | **✅** | ❌ | agent | ❌ | ❌ |
| 🤖 AI root-cause narratives (BYO key) | **✅** | paid add-on | paid | ❌ | ❌ |
| 📄 Self-contained offline HTML report | **✅** | ❌ | ❌ | ❌ | ❌ |

> **In one line:** *the only log anomaly detector with published, reproducible F1 - free, local, explained, grouped into incidents, and able to watch and alert on your services in real time.*

---

## 🚀 Install

**With pip (recommended):**

```bash
pip install loglensai            # fast + turbo detection, watch, alerts, SDK, RCA
pip install "loglensai[deep]"    # + neural (transformer) semantic mode
```

**With Docker (nothing to install, multi-arch amd64 + arm64):**

```bash
docker run --rm -v "$PWD:/data" loglensai/loglens analyze --source app.log
```

Requires Python 3.10+. MIT licensed.

---

## ⚡ Quick start

```bash
# analyze any log file - format auto-detected, incidents grouped
loglens analyze --source app.log

# maximum throughput on huge files
loglens analyze --source app.log --turbo

# neural semantic mode - best precision
loglens analyze --source app.log --deep

# full incident workflow: turbo scan + AI root-cause + offline HTML report
loglens analyze --source app.log --turbo --rca --html report.html

# watch a running service live - get ONLY the problems, instantly
loglens watch "docker logs -f my-api"

# ask your logs a question in plain English
loglens ask "why did the payment service start timing out?" --source app.log

# reproducible accuracy benchmark against labeled data
loglens benchmark labeled.log --min-f1 0.90
```

**Add Sentry-style self-alerting to your own app in _one line_:**

```python
import loglens
loglens.init(app_name="checkout-api")   # → Slack / Teams / Email on serious events
```

📖 Full command & SDK reference → **[loglensai.com/docs](https://loglensai.com/docs)** and [DOCUMENTATION.md](docs/DOCUMENTATION.md).

---

## 📊 Benchmarks - measured, reproducible, honest

All numbers on real labeled datasets from [Loghub](https://github.com/logpai/loghub). Reproduce them yourself → [BENCHMARK.md](docs/BENCHMARK.md).

### Accuracy - Loghub BGL (500,000 lines, 206,847 labeled alerts)

| Mode | Engine | Precision | Recall | **F1** | Speed | Missed alerts |
|------|--------|:---------:|:------:|:------:|:-----:|:-------------:|
| ⚡ **fast** | from-scratch statistical | 0.901 | **1.000** | 0.948 | ~6,700 l/s | **0** |
| 🚀 **turbo** | optimized statistical | 0.901 | **1.000** | 0.948 | ~7,300 l/s | **0** |
| 🧠 **deep** | AI semantic embeddings | **0.917** | **1.000** | **0.957** | ~3,400 l/s | **0** |

- 🎯 **Zero missed alerts** - 1.000 recall across all 206,847 alerts, every mode.
- 🧠 **Deep mode measurably beats the baseline** - semantic embeddings cut false positives ~18%. Provable AI value, not marketing.
- 🚀 **Turbo matches fast-mode accuracy exactly** at higher throughput - speed with no accuracy tradeoff.

### Generality - no retuning (Sandia Thunderbird, 500k all-normal lines)

| Mode | False-alarm rate | Specificity | Speed |
|------|:----------------:|:-----------:|:-----:|
| fast | 0.68% | **99.32%** | ~8,600 l/s |
| deep | 0.67% | **99.33%** | ~1,800 l/s |

### Needle-in-a-haystack - 30/30 injected incidents caught

Kernel panic, OOM, disk failure, security breach and data corruption injected into routine logs across **6 formats** (Apache, Spark, HDFS, HealthApp, OpenStack, Thunderbird): **100% recall, zero configuration.**

---

## ✨ Features

### 🔬 Detection core
- **Three engines, one unified score** - `fast` (from-scratch statistical: TF-IDF template embeddings, weighted density clustering, severity/rarity/chronic scoring - no ML libs in the core), `turbo` (same accuracy, parallel byte-range scanning + template dedup), and `deep` (transformer semantic embeddings that understand log *meaning*, run on unique templates for speed).
- **Incident families** - repeated anomalies collapse into one incident with an `×N` count. No scrolling through 200 identical errors.
- **Explainable by default** - every flag ships with a plain-language reason (rare + severe + burst context), not just a number.
- **10+ log formats auto-detected** - Apache, Linux, Mac, HDFS, Spark, Zookeeper, OpenStack, Thunderbird, BGL, HealthApp & generic. No config, ever.
- **Flexible ingestion** - files, URLs, and live commands.

### 📡 Live & always-on
- **`loglens watch`** - point it at `docker logs -f`, `kubectl logs -f`, or `journalctl -f` and it prints **only the problems**, instantly. CRITICAL/FATAL surface immediately; Ctrl-C prints a summary (optionally with AI root-cause + HTML dashboard).
- **Self-alerting in one line (`loglens.init`)** - Sentry-style alerts to **Slack / Teams / Email** the moment something serious happens, *including uncaught crashes*. De-duplicated, rate-limited, sent from a background thread so it never risks your app. Works with **zero AI setup** (built-in cause hints) and gets richer with a BYO LLM key.

### 🤖 AI layer (bring your own key)
- **AI root-cause analysis (`--rca`)** - BYO key (OpenAI / Azure / Groq). Sends only **grouped anomaly summaries** to the LLM - never your full log - so it's cheap, private, and coherent.
- **Natural-language Q&A (`loglens ask`)** - ask *"why did db-service degrade?"* and get an answer grounded in the detected anomalies.

### 🐍 Python SDK
```python
from loglens import analyze
result = analyze("app.log")                 # or lines=[...], cmd="docker logs api"
for a in result.anomalies:
    print(a.level, a.score, a.message, a.reasons)
print(result.rca().report)                  # AI root-cause (BYO key)
```
- `analyze()` / `analyze_async()` - "here are logs, give me the problems."
- `LogLensHandler` - drop into Python's `logging` so your app raises its own alarm.
- `LiveDetector` - feed a custom stream line-by-line, get anomalies out (powers `watch`).
- `.rca()`, `.ask(...)`, `.save_html(...)`, `.save_rca(...)` on any result or live session.

### 📈 Reporting & benchmarking
- **Self-contained HTML report (`--html`)** - dark-themed dashboard, severity + per-service breakdown, score distribution. Fully offline (no CDN), embeds the RCA narrative.
- **Speed benchmark (`loglens bench`)** - lines/sec, time-to-insight, peak RAM across modes.
- **Reproducible accuracy benchmark (`loglens benchmark`)** - precision / recall / F1 on labeled data, grid-search, and a `--min-f1` CI gate.
- **100% local & private** - detection never leaves your machine; air-gap friendly.

---

## 🧭 How it works

1. **Parse** - streaming parser auto-detects the log format.
2. **Template** - messages mined into templates; per-template volume statistics.
3. **Embed** - TF-IDF (fast/turbo) or transformer (deep); one vector per unique template for speed.
4. **Detect** - an ensemble score blends severity prior, template rarity, embedding distance, chronic-pattern damping, and a global-rarity bonus into a calibrated continuous score.
5. **Group** - repeated anomalies collapse into incident families (`×N`).
6. **Explain** - each anomaly reported with its human-readable reason; optionally an LLM writes the root-cause narrative.
7. **Deliver** - terminal, live `watch`, Slack/Teams/Email via `init`, or offline HTML report.

---

## 🐳 Docker

Multi-arch images (`linux/amd64` + `linux/arm64`) on [Docker Hub](https://hub.docker.com/r/loglensai/loglens):

```bash
# analyze a file (mount the folder that holds it)
docker run --rm -v "$PWD:/data" loglensai/loglens analyze --source app.log

# live-watch another container (mount the docker socket)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro \
  loglensai/loglens watch "docker logs -f my-api" --rca
```

Tags: `latest`, `0.3`, `0.3.3` (slim), and `deep` (adds neural mode).

---

## 🗺️ Roadmap

- 🔧 Chronic-noise damping improvements for Linux/Mac daemon logs.
- 📦 Prebuilt GitHub Action for CI log gating.
- 📊 More alert channels - PagerDuty, Opsgenie, generic webhooks.
- 🌐 Optional lightweight web UI for the HTML dashboards.

---

## 📜 Honesty notes

- Accuracy measured on Loghub line-level labels (token `-` = normal).
- Deep mode embeds unique templates only - a real optimization, disclosed.
- `--rca`, `ask`, and alert cause-hints send only grouped anomaly summaries to the LLM, never the full log.
- Alerting works fully offline with built-in cause hints; an LLM key only enriches the narrative.
- All results reproducible with the included harness. See [BENCHMARK.md](docs/BENCHMARK.md).

---

## 🤝 Contributing & support

Issues and PRs welcome. If LogLens AI saves you a 2 a.m. page, please **⭐ star the repo** - it genuinely helps.

- 🌐 Website: [loglensai.com](https://loglensai.com)
- 📦 PyPI: [pypi.org/project/loglensai](https://pypi.org/project/loglensai/)
- 🐳 Docker Hub: [hub.docker.com/r/loglensai/loglens](https://hub.docker.com/r/loglensai/loglens)
- 📖 Docs: [loglensai.com/docs](https://loglensai.com/docs)

## License

MIT - see [LICENSE](LICENSE). Use it in production, commercially, anywhere.

---

<div align="center">

**`pip install loglensai`** - your first insight is seconds away.

*log anomaly detection · AI log analysis · self-hosted observability · Splunk alternative · Datadog alternative · root-cause analysis · SRE / DevOps · Kubernetes log monitoring · Sentry for logs*

</div>