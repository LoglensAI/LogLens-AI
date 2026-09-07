# LogLens AI - Local, Explainable Log Anomaly Detection 🔍

> **The self-hosted, AI-powered alternative to Splunk & Datadog for log anomaly detection.**
> Finds real incidents by *meaning*, explains **why** in plain English, groups them into incident families, watches your containers live, and alerts you Sentry-style - **100% local, $0/GB, zero setup.**

[![PyPI](https://img.shields.io/pypi/v/loglensai?color=3b82f6&label=pip%20install%20loglensai)](https://pypi.org/project/loglensai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-3fb950.svg)](https://opensource.org/licenses/MIT)
[![Website](https://img.shields.io/badge/web-loglensai.com-38bdf8)](https://loglensai.com)
[![Multi-arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-8957e5)](https://loglensai.com)

```bash
docker run --rm -v "$PWD:/data" loglensai/loglens analyze --source app.log
```

**First real insight in seconds - no account, no agent, no cloud, no bill.**

---

## ⚡ Why teams pull LogLens AI

Traditional log platforms hand you a score and an invoice. LogLens AI hands you **answers** - and runs entirely on your own box.

| | **LogLens AI** | Splunk | Datadog | Elastic ML |
|---|:---:|:---:|:---:|:---:|
| 💰 Cost | **$0 / GB** | ~$150/GB/yr | ~$0.10–1.27/GB | license |
| ⏱️ Setup time | **seconds** | days–weeks | hours–days | hours |
| 🔒 Runs offline / air-gapped | **✅** | partial | ❌ | partial |
| 📊 Published, reproducible accuracy | **✅ F1 0.957** | ❌ | ❌ | ❌ |
| 💬 Explains *why* a line is anomalous | **✅** | scores only | scores only | scores only |
| 🧩 Groups repeats into incidents | **✅** | partial | partial | ❌ |
| 👀 Live watch (docker/k8s/journald) | **✅** | ✅ | ✅ | partial |
| 🚨 Self-alerting in **1 line** of code | **✅** | ❌ | agent | ❌ |
| 🤖 AI root-cause narratives | **✅** | paid add-on | paid | ❌ |

---

## 📊 Proven accuracy - run it yourself

Measured on real, labeled production logs (Loghub **BGL: 500,000 lines, 206,847 alerts**). Fully reproducible with the built-in `benchmark` command - don't trust us, verify it.

| Mode | Precision | Recall | **F1** | Speed | Missed alerts |
|------|:---------:|:------:|:------:|:-----:|:-------------:|
| ⚡ **fast** | 0.901 | **1.000** | 0.948 | ~6,700 l/s | **0** |
| 🚀 **turbo** | 0.901 | **1.000** | 0.948 | ~7,300 l/s | **0** |
| 🧠 **deep** (AI) | **0.917** | **1.000** | **0.957** | ~3,400 l/s | **0** |

- 🎯 **Zero missed alerts** - 1.000 recall across all 206,847 incidents, every mode.
- 🧪 **30/30 injected incidents caught** across 6 log formats - 100% recall, zero config.
- 🛡️ **99.3% specificity** on 500k all-normal lines (no retuning) - it doesn't cry wolf.

---

## 🚀 Quick start

**Analyze a log file** (mount the folder that holds it at `/data`):

```bash
docker run --rm -v "$PWD:/data" loglensai/loglens analyze --source app.log
```

**Turbo scan + AI root-cause + shareable offline HTML report:**

```bash
docker run --rm -v "$PWD:/data" \
  -e LOGLENS_LLM_PROVIDER=openai -e LOGLENS_LLM_API_KEY=sk-... \
  loglensai/loglens analyze --source app.log --turbo --rca --html report.html
```

**Ask your logs a question in plain English:**

```bash
docker run --rm -v "$PWD:/data" \
  -e LOGLENS_LLM_PROVIDER=openai -e LOGLENS_LLM_API_KEY=sk-... \
  loglensai/loglens ask "why did the payment service start timing out?" --source app.log
```

Everything after the image name goes straight to the CLI - explore it all with:

```bash
docker run --rm loglensai/loglens --help
```

---

## 👀 Live incident feed for your running containers

Watch any container's logs and surface **only the problems**, the instant they happen - CRITICAL/FATAL lines appear immediately, noise is filtered out:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  loglensai/loglens watch "docker logs -f my-api" --rca
```

Ctrl-C prints an incident summary card - plus an AI root-cause story with `--rca`. Works with `kubectl logs -f` and `journalctl -f` too.

---

## 🚨 Sentry-style alerts to Slack / Teams / Email

Point LogLens at a service and get an alert - with a **one-line root cause** - the moment something breaks, including uncaught crashes. De-duplicated and rate-limited, so an error storm becomes **one** alert, not five hundred:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e LOGLENS_SLACK_WEBHOOK=https://hooks.slack.com/services/XXX/YYY/ZZZ \
  loglensai/loglens watch "docker logs -f my-api" --rca
```

```
🔴 [my-api] CRITICAL · db (score 0.95)
database connection refused during checkout
↳ likely cause: a dependency is down or refusing connections (seen in db)
```

**Channel & AI environment variables:**

```
# Alerts (configure any/all)
LOGLENS_SLACK_WEBHOOK
LOGLENS_TEAMS_WEBHOOK
LOGLENS_EMAIL_SMTP_HOST / _SMTP_PORT / _USER / _PASSWORD / _TO

# Optional LLM - enriches root-cause (BYO key; only grouped summaries sent, never full logs)
LOGLENS_LLM_PROVIDER   openai | azure | groq
LOGLENS_LLM_MODEL
LOGLENS_LLM_API_KEY
```

---

## 🏷️ Image tags

| Tag | Contents | Best for |
|-----|----------|----------|
| `latest`, `0.3`, `0.3.3` | fast + turbo detection, live watch, alerts, SDK, ask, RCA, HTML reports | **most users** |
| `deep` | everything above **+ neural (transformer) semantic mode** for best precision | highest accuracy |

Every image is **multi-architecture** - `linux/amd64` and `linux/arm64` (Apple Silicon, AWS Graviton, Raspberry Pi).

```bash
docker run --rm -v "$PWD:/data" loglensai/loglens:deep analyze --source app.log --deep
```

---

## 🐙 One-shot & always-on with Compose

```yaml
services:
  watch:
    image: loglensai/loglens:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./logs:/data
    env_file: [ .env ]        # Slack/Teams/Email + optional LLM key
    command: ["watch", "docker logs -f my-api", "--rca"]
    restart: unless-stopped
```

---

## ✨ What's inside

- 🧠 **Three detection engines, one unified score** - statistical `fast`, throughput-tuned `turbo`, and transformer-based `deep`.
- 🧩 **Incident grouping** - 200 identical errors collapse into one incident family with an `×N` count.
- 💬 **Explainable by default** - every anomaly ships with a plain-language reason, not just a number.
- 📄 **10+ log formats auto-detected** - Apache, Linux, HDFS, Spark, Zookeeper, OpenStack, Thunderbird, BGL, HealthApp & more. Zero config.
- 🐍 **Full Python SDK** - `analyze()`, `LiveDetector`, drop-in `logging` handler, `.rca()` / `.ask()` / `.save_html()`.
- 📈 **Self-contained offline HTML dashboards** - dark-themed, no CDN, embeds the AI root-cause narrative.
- 🔒 **Private & air-gap friendly** - detection never leaves the container.

---

## 🛡️ Enterprise-ready by design

- **Runs as a non-root user**, minimal Python-slim base, small attack surface.
- **Multi-arch** signed builds published via CI on every tagged release.
- **No telemetry, no phone-home** - your logs stay yours.
- **`/data` volume** for inputs and cached models; stateless and reproducible.
- **MIT licensed** - use it in production, commercially, anywhere.

---

## 🔗 Links & keywords

**Website:** https://loglensai.com · **Docs:** https://loglensai.com/docs · **PyPI:** https://pypi.org/project/loglensai/ · **Source:** https://github.com/ParasRajput810/LogLens-AI

*log anomaly detection · AI log analysis · self-hosted log monitoring · Splunk alternative · Datadog alternative · open-source observability · root cause analysis · SRE / DevOps tooling · container log monitoring · Kubernetes log analysis · Sentry for logs · air-gapped log analytics · incident detection · MIT licensed*

---

<div align="center">

**⭐ If LogLens AI saves you a 2 a.m. page, star the repo and share the pull.**

`docker pull loglensai/loglens` · MIT · Built for engineers, by engineers.

</div>