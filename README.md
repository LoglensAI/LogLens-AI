<div align="center">

<img src="https://raw.githubusercontent.com/LoglensAI/LogLens-AI/main/images/avatar.png" alt="LogLens AI" width="400">

**Detect anomalies by meaning. Explain why they matter. Group them into incidents. Monitor services in real time.**

<p>
  <a href="https://pypi.org/project/loglensai/">PyPI</a> ·
  <a href="https://loglensai.com/docs">Documentation</a> ·
  <a href="https://loglensai.com">Website</a> ·
  <a href="https://hub.docker.com/r/loglensai/loglens">Docker Hub</a> ·
  <a href="docs/BENCHMARKS.md">Benchmarks</a>
</p>

<!-- Release & build -->
<p>
  <a href="https://pypi.org/project/loglensai/"><img src="https://img.shields.io/pypi/v/loglensai?label=PyPI&color=3b82f6&logo=pypi&logoColor=white" alt="PyPI version"></a>
  <a href="https://pypi.org/project/loglensai/"><img src="https://img.shields.io/pypi/pyversions/loglensai?color=3776ab&logo=python&logoColor=white" alt="Python versions"></a>
  <a href="https://github.com/LoglensAI/LogLens-AI/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/LoglensAI/LogLens-AI/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white" alt="CI status"></a>
  <a href="https://github.com/LoglensAI/LogLens-AI/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-3fb950.svg" alt="MIT License"></a>
</p>

<!-- Reach: downloads & impressions -->
<p>
  <a href="https://pypi.org/project/loglensai/"><img src="https://img.shields.io/pypi/dm/loglensai?label=pip%20installs%2Fmonth&color=3b82f6&logo=pypi&logoColor=white" alt="PyPI downloads per month"></a>
  <a href="https://pepy.tech/project/loglensai"><img src="https://static.pepy.tech/badge/loglensai" alt="Total PyPI downloads"></a>
  <a href="https://hub.docker.com/r/loglensai/loglens"><img src="https://img.shields.io/docker/pulls/loglensai/loglens?label=docker%20pulls&color=2496ed&logo=docker&logoColor=white" alt="Docker pulls"></a>
  <a href="https://hub.docker.com/r/loglensai/loglens"><img src="https://img.shields.io/docker/image-size/loglensai/loglens/latest?label=image&color=2496ed&logo=docker&logoColor=white" alt="Docker image size"></a>
  <a href="https://github.com/LoglensAI/LogLens-AI/stargazers"><img src="https://img.shields.io/github/stars/LoglensAI/LogLens-AI?logo=github&color=eac54f" alt="GitHub stars"></a>
  <img src="https://visitor-badge.laobi.icu/badge?page_id=LoglensAI.LogLens-AI&label=views&color=8957e5" alt="Repository views">
</p>

</div>



## Overview

Modern applications can generate thousands or millions of log lines. Finding the few lines that actually represent a failure, degradation, or security event is often more difficult than generating the logs themselves.

LogLens AI approaches this problem as an **anomaly detection and incident analysis pipeline**.

Instead of treating every log line independently, it:

1. Parses and normalizes incoming logs.
2. Learns recurring log templates.
3. Represents templates using statistical or semantic embeddings.
4. Detects unusual behavior.
5. Groups related anomalies into incident families.
6. Explains why each anomaly was detected.
7. Optionally generates an AI-assisted root-cause narrative.
8. Delivers the result through the CLI, live monitoring, alerts, or offline HTML reports.

The detection pipeline runs locally, making the project suitable for environments where logs should remain on the machine or infrastructure that produced them.

## Table of Contents

* [Overview](#overview)
* [Key Features](#key-features)

  * [Semantic Anomaly Detection](#semantic-anomaly-detection)
  * [Explainable Results](#explainable-results)
  * [Incident Grouping](#incident-grouping)
  * [Real-Time Monitoring](#real-time-monitoring)
  * [Application Self-Alerting](#application-self-alerting)
  * [Optional AI Root-Cause Analysis](#optional-ai-root-cause-analysis)
  * [Offline HTML Reports](#offline-html-reports)
  * [Multiple Detection Engines](#multiple-detection-engines)
* [Installation](#installation)

  * [Python (pip)](#python-pip)
  * [Docker](#docker)
  * [Warm daemon](#warm-daemon)
* [Quick Start](#quick-start)
* [Python SDK](#python-sdk)
* [How It Works](#how-it-works)

  * [1. Parse](#1-parse)
  * [2. Template Extraction](#2-template-extraction)
  * [3. Representation](#3-representation)
  * [4. Anomaly Detection](#4-anomaly-detection)
  * [5. Incident Grouping](#5-incident-grouping)
  * [6. Explanation](#6-explanation)
  * [7. Delivery](#7-delivery)
* [Benchmarks](#benchmarks)

  * [BGL Dataset](#bgl-dataset)
  * [Generalization Test](#generalization-test)
  * [Injected Incident Test](#injected-incident-test)
* [Privacy and Data Handling](#privacy-and-data-handling)
* [Docker](#docker)
* [Project Structure](#project-structure)
* [Roadmap](#roadmap)
* [Reproducibility](#reproducibility)
* [Contributing](#contributing)
* [License](#license)


## Key Features

### Semantic anomaly detection

Detect unusual log behavior using the semantic characteristics of log messages rather than relying exclusively on fixed keywords or hand-written rules.

### Explainable results

Every detected anomaly includes human-readable reasons based on factors such as:

* Severity
* Template rarity
* Frequency changes
* Semantic distance
* Burst behavior
* Historical patterns

The goal is not simply to say **"this line is anomalous"**, but to provide context for **why it was flagged**.

### Incident grouping

Repeated anomalies can represent a single underlying incident.

LogLens AI groups related events into incident families so that hundreds of repeated errors can be represented as one actionable incident rather than hundreds of individual alerts.

### Real-time monitoring

Monitor running services directly from the command line.

Supported sources include:

* Docker logs
* Kubernetes logs
* journald
* Custom streaming commands

The live watcher focuses on anomalous events instead of forcing developers to manually scan an entire log stream.

### Application self-alerting

Applications can integrate LogLens AI directly through the Python SDK.

The integration can surface serious events through:

* Slack
* Microsoft Teams
* Email

Alerting is designed to be asynchronous, rate-limited, and de-duplicated so that the monitoring layer does not become a reliability risk for the application itself.

### Optional AI root-cause analysis

LogLens AI can optionally use a user-provided LLM API key to generate higher-level incident explanations.

Supported providers include:

* OpenAI
* Azure
* Groq

The RCA layer operates on grouped anomaly summaries rather than transmitting the complete log stream.

### Offline HTML reports

Generate self-contained HTML reports containing:

* Incident summaries
* Severity breakdowns
* Service-level information
* Score distributions
* Detected anomalies
* Optional RCA narratives

Reports can be viewed without a cloud dashboard or external web service.

### Multiple detection engines

LogLens AI provides three detection modes:

| Mode    | Approach                              | Primary goal                   |
| ------- | ------------------------------------- | ------------------------------ |
| `fast`  | Statistical / TF-IDF                  | Fast general-purpose detection |
| `turbo` | Optimized statistical pipeline        | Higher throughput              |
| `deep`  | Transformer-based semantic embeddings | Deeper semantic analysis       |

The core detection pipeline does not require an external AI service.

---

## Installation

LogLens installs as a **self-contained binary** on Linux, macOS and Windows - no
Python needed. Neural (`--deep`) mode is **built in**, and a warm daemon makes
repeat runs near-instant. Full details for every platform are in
**[INSTALL.md](INSTALL.md)**.

| Platform | Install |
|---|---|
| **Linux** (Debian/Ubuntu) | `curl -1sLf 'https://dl.cloudsmith.io/public/loglensai/loglensai-363o/setup.deb.sh' \| sudo -E bash && sudo apt install loglens` |
| **Linux** (Fedora/RHEL) | `curl -1sLf 'https://dl.cloudsmith.io/public/loglensai/loglensai-363o/setup.rpm.sh' \| sudo -E bash && sudo dnf install loglens` |
| **macOS** | `brew install loglensai/tap/loglens` |
| **Windows** | `winget install LoglensAI.LogLens` |

Updates arrive through the normal channel afterwards (`sudo apt upgrade`,
`brew upgrade`, `winget upgrade`).

### Python (pip)

Great for developers and CI. Requires **Python 3.10+**.

```bash
pipx install loglensai            # or: pip install loglensai
pip install "loglensai[deep]"     # add transformer-based semantic detection
```

> With `pip` the warm daemon is off by default - enable it with `LOGLENS_DAEMON=1`
> or `loglens daemon start`. Installer builds turn it on automatically.

### Docker

Multi-architecture images for **amd64** and **arm64**:

```bash
docker run --rm -v "$PWD:/data" loglensai/loglens analyze --source app.log
```

### Warm daemon

A resident process keeps LogLens fast between runs (skips the ~1.7 s ML-import
cost per invocation). Native installs start it automatically; manage it with
`loglens daemon start|stop|status|restart`.

See **[INSTALL.md](INSTALL.md)** for per-OS guides, the portable tarballs,
Scoop, code-signing notes, and environment toggles.

---

## Quick Start

```bash
# Analyze a log file
loglens analyze --source app.log

# Use the optimized high-throughput detector
loglens analyze --source app.log --turbo

# Use semantic transformer-based detection
loglens analyze --source app.log --deep

# Generate an offline incident report with optional RCA
loglens analyze --source app.log --turbo --rca --html report.html

# Monitor a running Docker service
loglens watch "docker logs -f my-api"

# Ask a natural-language question about detected anomalies
loglens ask "why did the payment service start timing out?" --source app.log

# Run the reproducible benchmark
loglens benchmark labeled.log --min-f1 0.90
```

---

## Python SDK

LogLens AI can also be integrated directly into Python applications. 

For eg:- 

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

The SDK provides interfaces for:

* Batch log analysis
* Asynchronous analysis
* Python `logging` integration
* Live stream detection
* Root-cause analysis
* Natural-language questions
* HTML report generation
* Alerting

For example, an application can initialize the monitoring layer with:

`loglens.init(app_name="checkout-api")`

This allows LogLens AI to monitor application events and surface serious anomalies without requiring a separate logging agent.

See the [SDK documentation](https://loglensai.com/docs) for the complete API reference.

---

## How It Works

LogLens AI processes logs through several stages.

### 1. Parse

The input stream is parsed using an automatically detected log format.

Supported formats include Apache, Linux, Mac, HDFS, Spark, Zookeeper, OpenStack, Thunderbird, BGL, HealthApp, and generic logs.

### 2. Template extraction

Similar log messages are converted into reusable templates.

For example, multiple messages such as:

`Connection failed for user 18372`

and

`Connection failed for user 92451`

can be represented by a common structural template rather than treated as completely unrelated events.

### 3. Representation

The detection engine represents log templates using either:

* TF-IDF-based representations for `fast` and `turbo`
* Transformer embeddings for `deep`

Semantic representations are generated at the template level where possible, reducing unnecessary computation on repeated messages.

### 4. Anomaly detection

The detection system combines multiple signals, including:

* Severity
* Template rarity
* Embedding distance
* Frequency
* Chronic-pattern damping
* Global rarity

These signals are combined into a continuous anomaly score.

### 5. Incident grouping

Related anomaly events are grouped into incident families.

This reduces alert noise and provides a higher-level view of what is happening within the system.

### 6. Explanation

Each anomaly is accompanied by human-readable reasoning describing the signals that contributed to the detection.

### 7. Delivery

Results can be delivered through:

* CLI output
* Live monitoring
* Slack
* Microsoft Teams
* Email
* Offline HTML reports
* Python SDK

Optional LLM-based RCA can add a higher-level narrative to the detected incident.

---

## Benchmarks

LogLens AI includes a reproducible benchmarking harness based on labeled datasets from [Loghub](https://github.com/logpai/loghub).

### BGL Dataset

The current benchmark evaluates 500,000 BGL log lines containing 206,847 labeled alerts.

| Mode    | Engine                | Precision | Recall |    F1 | Approx. throughput |
| ------- | --------------------- | --------: | -----: | ----: | -----------------: |
| `fast`  | Statistical           |     0.901 |  1.000 | 0.948 |     ~6,700 lines/s |
| `turbo` | Optimized statistical |     0.901 |  1.000 | 0.948 |     ~7,300 lines/s |
| `deep`  | Semantic embeddings   |     0.917 |  1.000 | 0.957 |     ~3,400 lines/s |

These figures are benchmark results on the specified dataset and configuration; they should not be interpreted as universal performance guarantees.

**Reproduce it yourself** (don't take our word for it):

```bash
loglens benchmark path/to/BGL.log --format bgl --supervised
```

On the bundled 2,000-line sample (`benchmarks/BGL_2k.log`), the supervised head scores **F1 0.932** (precision 0.902, recall 0.965) and the unsupervised path reaches **1.000 recall** - see [BENCHMARKS.md](docs/BENCHMARKS.md) for the full measured baseline (accuracy, throughput, memory).

The complete methodology and reproduction instructions are available in [BENCHMARKS.md](docs/BENCHMARKS.md).

### Generalization Test

A separate evaluation uses 500,000 normal lines from the Sandia Thunderbird dataset without retuning the detector.

| Mode   | False-alarm rate | Specificity | Approx. throughput |
| ------ | ---------------: | ----------: | -----------------: |
| `fast` |            0.68% |      99.32% |     ~8,600 lines/s |
| `deep` |            0.67% |      99.33% |     ~1,800 lines/s |

### Injected Incident Test

The project also includes a synthetic "needle-in-a-haystack" evaluation involving 30 injected incidents across six log formats.

The tested incidents include scenarios such as:

* Kernel panic
* Out-of-memory conditions
* Disk failures
* Security events
* Data corruption

The current evaluation detected all 30 injected incidents.

For methodology and reproduction details, see [BENCHMARK.md](docs/BENCHMARK.md).

---

## Privacy and Data Handling

LogLens AI is designed around a local-first architecture.

The core detection process does not require logs to be uploaded to a cloud observability platform.

Optional AI functionality requires an external LLM provider and is therefore subject to that provider's network and data-handling policies.

When RCA or natural-language analysis is enabled, LogLens AI sends **grouped anomaly summaries rather than the complete raw log stream**.

Alerting can also operate without an LLM using the built-in detection and explanation mechanisms.

---

## Docker

The project publishes multi-architecture images supporting:

* Linux amd64
* Linux arm64

Analyze a mounted log file:

`docker run --rm -v "$PWD:/data" loglensai/loglens analyze --source app.log`

For live Docker monitoring, the Docker socket can be mounted read-only and used as the source for the watcher.

Available image variants include the standard release and an optional image containing the neural detection dependencies.

---

## Project Structure

The project is organized around several major components:

**Detection engine**
Parsing, template extraction, feature generation, anomaly scoring, and incident grouping.

**CLI**
Commands for analysis, monitoring, benchmarking, reporting, and natural-language queries.

**Python SDK**
Programmatic integration for applications and custom pipelines.

**Live monitoring**
Streaming detection for Docker, Kubernetes, journald, and custom commands.

**Alerting**
Asynchronous notification delivery with deduplication and rate limiting.

**AI layer**
Optional root-cause analysis and natural-language interaction.

**Reporting**
Offline HTML reports and benchmark outputs.

---

## Roadmap

Planned improvements include:

* Improved chronic-noise handling for Linux and macOS daemon logs
* A prebuilt GitHub Action for CI log analysis
* Additional alert integrations such as PagerDuty and Opsgenie
* Generic webhook support
* A lightweight optional web interface for generated reports

---

## Reproducibility

Benchmark results are intended to be reproducible.

The repository includes the evaluation harness and benchmark documentation needed to run the supported experiments independently.

See:

* [Benchmark methodology](docs/BENCHMARK.md)
* [Documentation](https://loglensai.com/docs)

---

## Contributing

Contributions are welcome.

You can contribute through:

* Bug reports
* Feature requests
* Documentation improvements
* Benchmark improvements
* New log format support
* Detection algorithms
* Integrations
* Pull requests

Please open an issue before starting a major architectural change so the proposed direction can be discussed.

## License

LogLens AI is released under the **MIT License**.

See [LICENSE](LICENSE) for details.

---

<div align="center">

**LogLens AI**

*Understand your logs. Find the incident. Fix the problem.*

</div>