import asyncio
import functools
import json
import os
import sys
from typing import TYPE_CHECKING, Any, cast

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from loglens import __version__
from loglens.domain.models import LogEntry
from loglens.domain.severity import (
    CATEGORY_ORDER,
    RICH_STYLE_DEFAULT,
    RICH_STYLES,
    get_severity,
)
from loglens.infrastructure.output.terminal import LiveProgress

# When output is piped to a consumer that closes early (e.g. `loglens ... | head`),
# restore the default SIGPIPE behaviour so we exit quietly like grep/cat instead of
# dumping a BrokenPipeError traceback. POSIX-only; a no-op on Windows.
try:
    import signal

    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
except (ImportError, AttributeError, ValueError):
    pass

if TYPE_CHECKING:
    # These names are injected into module globals at runtime by _load() to keep
    # CLI startup fast (heavy imports deferred). Declared here so type-checkers
    # and IDEs can resolve them without importing at runtime.
    from loglens.application.live import LiveDetector
    from loglens.detection.benchmark import (
        run_benchmark,
    )
    from loglens.detection.deep_embeddings import DeepEmbeddingEngine
    from loglens.detection.detector import cluster_summary, detect_anomalies
    from loglens.detection.embeddings import EmbeddingEngine
    from loglens.detection.grouping import group_anomalies
    from loglens.detection.ingestion import AsyncCommandReader, CommandError, stream_lines
    from loglens.detection.parser import parse_line, sniff_format
    from loglens.detection.speedbench import bench_file, to_markdown
    from loglens.detection.templates import TemplateRegistry
    from loglens.detection.turbo import scan_file as turbo_scan
    from loglens.detection.worker import run_worker_pool
    from loglens.infrastructure.llm import LLMConfig, LLMError, run_ask, run_rca, save_report
    from loglens.infrastructure.output.html_report import render_html_report

_LOADED = False


def _load():
    global _LOADED
    if _LOADED:
        return
    g = globals()
    from loglens.detection.benchmark import run_benchmark  # noqa: F401
    from loglens.detection.detector import (  # noqa: F401
        DetectorConfig,
        cluster_summary,
        detect_anomalies,
    )
    from loglens.detection.embeddings import EmbeddingEngine  # noqa: F401
    from loglens.detection.grouping import group_anomalies  # noqa: F401
    from loglens.detection.ingestion import (  # noqa: F401
        AsyncCommandReader,
        CommandError,
        stream_lines,
    )
    from loglens.detection.parser import parse_line, sniff_format  # noqa: F401
    from loglens.detection.speedbench import bench_file, to_markdown  # noqa: F401
    from loglens.detection.templates import TemplateRegistry  # noqa: F401
    from loglens.detection.turbo import scan_file as turbo_scan  # noqa: F401
    from loglens.detection.worker import run_worker_pool  # noqa: F401
    from loglens.infrastructure.output.html_report import render_html_report  # noqa: F401

    try:
        from loglens.detection.deep_embeddings import DeepEmbeddingEngine  # noqa: F401
    except ImportError:
        DeepEmbeddingEngine = None
    from loglens.application.live import LiveDetector  # noqa: F401
    from loglens.infrastructure.llm import (  # noqa: F401
        LLMConfig,
        LLMError,
        run_ask,
        run_rca,
        save_report,
    )

    for k, v in list(locals().items()):
        if k != "g":
            g[k] = v
    _LOADED = True


app = typer.Typer(
    name="loglens",
    help=(
        "LogLens AI — intelligent, local log analysis and anomaly detection.\n\n"
        "Run [bold]loglens COMMAND --help[/bold] to see a command's flags and examples "
        "(e.g. [cyan]loglens analyze --help[/cyan])."
    ),
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

console = Console()

INFO_KEYWORDS = {"error", "fail", "timeout", "refused", "crash", "panic", "oom", "kill"}

# --- CI/CD helpers: machine-readable output + build gating -------------------- #
# Severity a --fail-on threshold maps to (fail if any anomaly is this bad or worse).
_FAIL_ON_RANK = {
    "emergency": 0,
    "fatal": 1,
    "alert": 1,
    "critical": 2,
    "error": 3,
    "warning": 4,
    "warn": 4,
    "any": 99,  # any anomaly at all
}


_INCIDENT_CRIT_LEVELS = {"EMERGENCY", "ALERT", "FATAL", "CRITICAL"}
_INCIDENT_SEVERE_RATIO = 0.30  # fraction of parsed lines that are severe → burst
_INCIDENT_BURST_FAMILIES = 5  # this many critical families → clear burst


def _assess_incident(
    items: list[dict[str, Any]], lines_parsed: int
) -> tuple[bool, float, list[str]]:
    """Decide whether the run is an incident, with a 0-1 score and reasons.

    An incident fires when ANY of: at least one CRITICAL/FATAL family, a severe
    burst (≥30% of parsed lines severe), or many critical families. This replaces
    the old "≥30% of all lines" rule, which never fired on realistic logs where a
    few catastrophic families sit among mostly-normal traffic.
    """
    crit = [it for it in items if str(it.get("level", "")).upper() in _INCIDENT_CRIT_LEVELS]
    errs = [it for it in items if str(it.get("level", "")).upper() in ("ERROR",)]
    severe_lines = sum(int(it.get("count", 1) or 1) for it in (*crit, *errs))
    ratio = (severe_lines / lines_parsed) if lines_parsed else 0.0
    max_score = max((float(it.get("score", 0) or 0) for it in items), default=0.0)

    incident = False
    score = 0.0
    reasons: list[str] = []
    if crit:
        incident = True
        reasons.append(
            f"{len(crit)} critical/fatal anomaly famil{'y' if len(crit) == 1 else 'ies'}"
        )
        score = max(score, min(1.0, 0.6 + 0.04 * len(crit)))
    if ratio >= _INCIDENT_SEVERE_RATIO:
        incident = True
        reasons.append(f"{ratio * 100:.0f}% of parsed lines are severe (burst)")
        score = max(score, min(1.0, 0.3 + ratio))
    if len(crit) >= _INCIDENT_BURST_FAMILIES:
        reasons.append(f"burst of {len(crit)} critical families")
        score = max(score, 0.85)
    if incident:
        score = max(score, max_score)
    return incident, round(min(1.0, score), 4), reasons


def _template_id(template: str) -> str:
    """Stable short id for a template/family, so tooling can join across runs."""
    import hashlib

    return hashlib.sha1((template or "").encode("utf-8")).hexdigest()[:12]


def _seed_everything(seed: int) -> None:
    import os
    import random as _random

    os.environ["PYTHONHASHSEED"] = str(seed)
    _random.seed(seed)
    try:
        import numpy as _np

        _np.random.seed(seed)
    except Exception:  # numpy always present in practice; never fail a run on this
        pass


async def _collect_entries(
    source: str, sniff_n: int = 500
) -> tuple[list[Any], int, str, float, dict[str, Any]]:
    line_count = 0
    entries: list[Any] = []
    sample_buf: list[str] = []
    fmt: str | None = None
    confidence = 0.0
    layout: dict[str, Any] = {}

    async for line in stream_lines(source):
        line_count += 1
        if fmt is None:
            sample_buf.append(line)
            if len(sample_buf) >= sniff_n:
                fmt, confidence, layout = sniff_format(sample_buf)
                for buffered in sample_buf:
                    e = parse_line(buffered, fmt, layout)
                    if e is not None:
                        entries.append(e)
                sample_buf = []
            continue
        e = parse_line(line, fmt, layout)
        if e is not None:
            entries.append(e)

    if fmt is None:  # source smaller than the sniff window
        fmt, confidence, layout = sniff_format(sample_buf)
        for buffered in sample_buf:
            e = parse_line(buffered, fmt, layout)
            if e is not None:
                entries.append(e)

    return entries, line_count, fmt or "PLAINTEXT", confidence, layout


def _family_item(
    g, members: list, line_of: dict[int, int], rmap: dict | None = None
) -> dict[str, Any]:
    line_numbers = sorted(line_of[id(m)] for m in members if id(m) in line_of)
    timestamps = [m.timestamp for m in members if getattr(m, "timestamp", "")]
    samples = [(getattr(m, "raw", "") or m.message) for m in members[:3]]
    tid = _template_id(getattr(g, "template", "") or g.sample)
    reasons = list(getattr(g, "reasons", []) or [])

    from loglens.detection.diagnosis import diagnose as _diagnose

    _d = _diagnose(g.sample, [], level=g.level)

    confidence = None
    r_status = "unknown"
    r_value = None
    r_features: list[str] = []
    if rmap is not None:
        from loglens.detection.routineness import confidence_label

        r = rmap.get(getattr(g, "template", ""))
        confidence, _ = confidence_label(g.max_score, r)
        if r is not None:
            r_status = r.status
            r_value = round(r.r, 4) if r.r is not None else None
            r_features = r.features_used
            if r.note:
                reasons = [*reasons, r.note]

    _agg = {"N": 0.0, "B": 0.0, "P": 0.0, "C": 0.0, "S": 0.0}
    for m in members:
        ms = (getattr(m, "metadata", None) or {}).get("scores")
        if ms:
            for k in _agg:
                _agg[k] = max(_agg[k], float(ms.get(k, 0.0)))
    scores_block: dict[str, float | None] = {k: round(v, 4) for k, v in _agg.items()}
    scores_block["R"] = r_value

    provisional = bool(confidence and confidence.startswith("Low"))

    return {
        "id": tid,
        "template_id": tid,
        "template": getattr(g, "template", ""),
        "level": g.level,
        "service": g.service,
        "score": round(g.max_score, 4),
        "count": g.count,
        "first_seen": (min(timestamps) if timestamps else None),
        "last_seen": (max(timestamps) if timestamps else None),
        "line_numbers": line_numbers[:1000],  # capped; count carries the true total
        "sample_lines": samples,
        "message": g.sample,
        "calibrated_p": None,  # populated once conformal calibration lands (P3.G)
        "scores": scores_block,  # per-detector sub-scores {N,B,P,R,C,S} (D12)
        "impact": _d.impact,  # blocking | non-blocking | unknown (message+severity based here)
        "trace_kind": _d.trace_kind,  # deep trace reconstruction only in `explain`
        "origin": _d.origin,  # your_code | dependency | upstream_service | system | unknown
        "origin_detail": _d.origin_detail,  # the specific package / service / signal
        "confidence": confidence,  # triage badge (blends score + routineness)
        "r_value": r_value,  # routineness 0..1 (higher = more routine); None if unknown
        "r_status": r_status,  # measured | partial(k/4) | unknown
        "r_features_used": r_features,
        "r_applied": False,  # R is descriptive — it never changes the score (D11)
        "provisional": provisional,  # low-confidence family — treat as tentative
        "retracted": False,  # reserved for the streaming path (superseded families)
        "incident_id": None,  # set by _emit_json when the run is an incident (D12)
        "reasons": reasons,
        "detector_votes": {},  # populated once the ensemble lands (P3.F)
    }


def _build_incidents(source: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from loglens.detection.incidents import Family, group_incidents
    from loglens.detection.timeutil import parse_ts

    fams = [
        Family(
            template_id=it.get("template_id", ""),
            level=it.get("level", ""),
            service=it.get("service", ""),
            count=int(it.get("count", 1)),
            first_dt=parse_ts(it.get("first_seen") or ""),
            last_dt=parse_ts(it.get("last_seen") or ""),
            origin=it.get("origin", "unknown"),
            origin_detail=it.get("origin_detail"),
            message=it.get("message", ""),
        )
        for it in items
    ]
    incidents, mapping = group_incidents(fams, source=source)
    for it in items:
        it["incident_id"] = mapping.get(it.get("template_id", ""))
    return [
        {
            "id": inc.id,
            "level": inc.level,
            "events": inc.events,
            "families": inc.family_ids,
            "services": inc.services,
            "first_seen": inc.first_dt.isoformat() if inc.first_dt else None,
            "last_seen": inc.last_dt.isoformat() if inc.last_dt else None,
            "span_seconds": inc.span_seconds,
            "root_cause": {
                "template_id": inc.root_cause_id,
                "message": inc.root_cause_message,
                "origin": inc.root_cause_origin,
                "origin_detail": inc.root_cause_detail,
            },
        }
        for inc in incidents
    ]


def _emit_json(
    source: str,
    mode: str,
    lines_read: int | None,
    lines_parsed: int,
    incident: bool,  # kept for signature stability; recomputed from items below
    items: list[dict[str, Any]],
) -> None:
    """Print a machine-readable analysis result to stdout (for CI/CD)."""
    is_incident, incident_score, incident_reasons = _assess_incident(items, lines_parsed)

    # Incident grouping (D13): cluster the severe families into distinct incidents by
    # time-gap, each with a root-cause hint + the services it touched, and stamp every
    # participating family with its incident_id (replaces D12's single run-level id).
    incidents = _build_incidents(source, items)

    payload = {
        "schema": "loglens.v1",
        "version": __version__,
        "source": source,
        "mode": mode,
        "lines_read": lines_read,
        "lines_parsed": lines_parsed,
        "incident": is_incident,
        "incident_score": incident_score,
        "incident_reasons": incident_reasons,
        "incidents": incidents,
        "anomaly_count": len(items),
        "anomalies": items,
    }
    print(json.dumps(payload, indent=2))


def _apply_fail_on(fail_on: str, items: list[dict[str, Any]]) -> None:
    """Exit non-zero if any anomaly meets/exceeds the --fail-on severity.

    Exit code 2 == the gate tripped (a CI build should fail). Unknown thresholds
    are reported and ignored so a typo never silently passes a broken build.
    """
    key = (fail_on or "").strip().lower()
    if not key or key == "none":
        return
    from loglens.domain.severity import get_severity

    threshold = _FAIL_ON_RANK.get(key)
    if threshold is None:
        console.print(
            f"[yellow][LogLens][/yellow] Unknown --fail-on '{fail_on}' "
            f"(use: {', '.join(sorted(_FAIL_ON_RANK))}). Not gating."
        )
        return
    if key == "any":
        tripped = len(items) > 0
        worst = "any anomaly"
    else:
        breaching = [it for it in items if get_severity(str(it.get("level", ""))) <= threshold]
        tripped = len(breaching) > 0
        worst = f"{len(breaching)} anomaly(ies) at or above {key.upper()}"
    if tripped:
        console.print(f"[bold red][LogLens][/bold red] fail-on tripped: {worst} 🚨", style="red")
        raise typer.Exit(code=2)


def _level_color(lvl: str) -> str:
    lvl = lvl.upper()
    if lvl in ("ERROR", "CRITICAL", "FATAL", "EMERGENCY"):
        return "bold red"
    elif lvl in ("WARN", "WARNING"):
        return "bold yellow"
    return "dim"


def _severity(a) -> int:
    # Canonical rank: 0 = most severe. Sort ascending for worst-first.
    return get_severity(a.level)


def _select_engine(deep: bool):
    if deep:
        if DeepEmbeddingEngine is None:
            console.print(
                "[bold red]Deep mode requires sentence-transformers.[/bold red]\n"
                "Install with: [yellow]pip install sentence-transformers[/yellow]"
            )
            raise typer.Exit(code=1)
        return DeepEmbeddingEngine()
    return EmbeddingEngine()


def _groups_to_rca_entries(groups) -> list:
    return [
        LogEntry(
            level=g.level,
            service=g.service,
            message=f"{g.sample} (occurred ×{g.count:,}, score {g.max_score:.2f})",
            raw=g.sample,
        )
        for g in groups
    ]


def _print_llm_config_hint():
    console.print(
        "[dim]Configure with env vars: LOGLENS_LLM_PROVIDER (openai|azure|groq), "
        "LOGLENS_LLM_API_KEY, LOGLENS_LLM_MODEL — or flags --provider/--api-key/--llm-model.[/dim]"
    )


def _do_rca(rca_input, scores, reasons, source, provider, llm_model, api_key, rca_out=""):
    try:
        cfg = LLMConfig.from_env(provider=provider, model=llm_model, api_key=api_key)
        console.print(
            f"\n[bold cyan][LogLens][/bold cyan] 🤖 Running AI root-cause analysis via "
            f"[bold]{cfg.provider}[/bold] ([dim]{cfg.model}[/dim])..."
        )
        result = run_rca(rca_input, cfg, scores=scores, reasons=reasons, source_name=source)
        console.print()
        console.print(
            Panel(
                Markdown(result.report),
                title=f"🧠 AI Root-Cause Analysis ({result.provider} / {result.model})",
                border_style="cyan",
            )
        )
        u = result.usage
        console.print(
            f"[dim]Privacy: sent {result.anomalies_sent} anomaly summaries to the LLM — "
            f"never the full log file. "
            f"Tokens: {u.total_tokens:,} (prompt {u.prompt_tokens:,} / completion {u.completion_tokens:,})[/dim]"
        )
        if rca_out:
            save_report(result, rca_out, source_name=source)
            console.print(
                f"[bold cyan][LogLens][/bold cyan] RCA report saved: [green]{rca_out}[/green]"
            )
        return result
    except LLMError as e:
        console.print(f"[bold red][LogLens][/bold red] RCA failed: {e}")
        _print_llm_config_hint()
        return None


def _write_html(html_out, source, total_lines, anomalies, rca_result=None, scores=None):
    level_counts: dict = {}
    for a in anomalies:
        lvl = a.level.upper()
        level_counts[lvl] = level_counts.get(lvl, 0) + 1
    rca_md = rca_result.report if rca_result else None
    rca_meta = (
        {
            "provider": rca_result.provider,
            "model": rca_result.model,
            "tokens": rca_result.usage.total_tokens,
        }
        if rca_result
        else None
    )
    html_doc = render_html_report(
        source=source,
        total_lines=total_lines,
        anomalies=anomalies,
        level_counts=level_counts,
        rca_markdown=rca_md,
        rca_meta=rca_meta,
        scores=scores,
    )
    with open(html_out, "w", encoding="utf-8") as f:
        f.write(html_doc)
    console.print(f"[bold cyan][LogLens][/bold cyan] HTML report saved: [green]{html_out}[/green]")


def _build_info() -> dict[str, str]:
    import platform

    commit = build_date = ""
    try:
        from loglens import _build as _b  # generated in CI, optional

        commit = getattr(_b, "COMMIT", "") or ""
        build_date = getattr(_b, "BUILD_DATE", "") or ""
    except Exception:  # noqa: BLE001
        pass
    commit = (commit or os.environ.get("LOGLENS_COMMIT", "") or "unknown").strip()
    build_date = (build_date or os.environ.get("LOGLENS_BUILD_DATE", "") or "unknown").strip()
    return {
        "version": __version__,
        "commit": commit,
        "build_date": build_date,
        "python": platform.python_version(),
    }


@app.command()
def version(
    as_json: bool = typer.Option(
        False, "--json", help="Machine-readable version info (version, commit, build date, python)."
    ),
):
    """Print the installed LogLens version (with --json for build provenance)."""
    info = _build_info()
    if as_json:
        print(json.dumps(info))
        return
    console.print(f"[bold cyan]LogLens AI[/bold cyan] version [bold]{info['version']}[/bold]")
    if info["commit"] != "unknown" or info["build_date"] != "unknown":
        console.print(
            f"[dim]commit {info['commit']} · built {info['build_date']} · "
            f"python {info['python']}[/dim]"
        )


@app.command("help")
def help_command(ctx: typer.Context):
    """Show the list of commands (same as `loglens --help`)."""
    root = ctx.find_root()
    console.print(root.get_help())


@app.command()
def analyze(
    source: str = typer.Option(..., help="Log source: file path, URL, or stdin"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Stop after ingestion, show stats only"),
    verbose: bool = typer.Option(False, "--verbose", help="Show sample parsed entry"),
    workers: int = typer.Option(4, "--workers", help="Number of parallel workers"),
    deep: bool = typer.Option(False, "--deep", help="Use neural embeddings (accurate, slower)"),
    limit: int = typer.Option(20, "--limit", help="Max anomaly families to display (default: 20)"),
    sort_by: str = typer.Option(
        "recent",
        "--sort-by",
        help="Order anomaly families by: recent (newest first, default) | severity | time | service",
    ),
    turbo: bool = typer.Option(
        False,
        "--turbo",
        help="Fast multiprocess scan for huge files (byte-range + template dedup, skips embeddings)",
    ),
    explain: int = typer.Option(
        0,
        "--explain",
        help="Show top-N scored entries (flagged or not) with score and reasons — for debugging near-misses",
    ),
    model: str = typer.Option(
        "",
        "--model",
        help="Path to a trained model from `loglens train` — uses the supervised head instead of the raw threshold",
    ),
    no_model: bool = typer.Option(
        False,
        "--no-model",
        help="Ignore the bundled default model and use pure unsupervised detection",
    ),
    rca: bool = typer.Option(
        False,
        "--rca",
        help="AI root-cause analysis of detected anomalies (requires LLM key: openai | azure | groq)",
    ),
    provider: str = typer.Option(
        "", "--provider", help="LLM provider: openai | azure | groq (or env LOGLENS_LLM_PROVIDER)"
    ),
    llm_model: str = typer.Option(
        "", "--llm-model", help="LLM model / Azure deployment name (or env LOGLENS_LLM_MODEL)"
    ),
    api_key: str = typer.Option(
        "", "--api-key", help="LLM API key (prefer env LOGLENS_LLM_API_KEY)"
    ),
    rca_out: str = typer.Option(
        "", "--rca-out", help="Save the RCA report to a markdown file (e.g. rca_report.md)"
    ),
    html_out: str = typer.Option(
        "",
        "--html",
        help="Save a standalone HTML report (e.g. report.html). Includes RCA if --rca is set.",
    ),
    output_format: str = typer.Option(
        "terminal",
        "--format",
        help="Output format: terminal (default) | json. Use json for CI/CD (machine-readable).",
    ),
    fail_on: str = typer.Option(
        "",
        "--fail-on",
        help="Exit non-zero (code 2) if any anomaly is this severity or worse: "
        "critical | error | warning | fatal | any. For gating CI/CD builds.",
    ),
    seed: int = typer.Option(
        0,
        "--seed",
        help="Random seed for reproducible runs — same input + same seed → identical output.",
    ),
    learn: bool = typer.Option(
        True,
        "--learn/--no-learn",
        help="Remember this source's normal baseline and improve on every run "
        "(zero-touch self-learning). --no-learn scores cold and writes nothing.",
    ),
    profile: str = typer.Option(
        "", "--profile", help="Name the learned baseline (else it's keyed to the source path)."
    ),
    state_dir: str = typer.Option(
        "", "--state-dir", help="Where baselines are stored (default: ~/.loglens/baselines)."
    ),
):
    """Analyze a log file for anomalies (fast / turbo / deep, with CI/CD gating)."""
    _load()
    _seed_everything(seed)
    as_json = output_format.strip().lower() == "json"
    console.quiet = as_json
    if as_json:
        pass  # stdout stays clean for the JSON payload

    from loglens.detection.filetype import InvalidSourceError, check_source

    try:
        check_source(source)
    except InvalidSourceError as _e:
        console.print(f"[bold red][LogLens][/bold red] {_e}")
        raise typer.Exit(code=1) from None

    async def _run():

        if turbo:
            console.print(f"\n[bold cyan][LogLens][/bold cyan] Source: [yellow]{source}[/yellow]")
            console.print(
                "[bold cyan][LogLens][/bold cyan] Mode: [bold magenta]⚡ Turbo (parallel scan)[/bold magenta] "
                "[dim]— unsupervised; signals: frequency + severity + keywords "
                "(skips embeddings, timing & the model)[/dim]"
            )
            loop = asyncio.get_running_loop()
            with console.status("[bold magenta]⚡ Turbo scanning…[/bold magenta]", spinner="dots"):
                res = await loop.run_in_executor(
                    None,
                    functools.partial(turbo_scan, source, workers=(workers if workers else None)),
                )
            console.print(f"[bold cyan][LogLens][/bold cyan] Workers: [bold]{res.workers}[/bold]")
            console.print(
                f"[bold cyan][LogLens][/bold cyan] Lines: [bold]{res.parsed_lines:,}[/bold] parsed "
                "[dim](turbo counts parsed lines directly)[/dim]"
            )
            console.print(
                f"[bold cyan][LogLens][/bold cyan] Unique templates: [bold]{len(res.templates):,}[/bold]  "
                f"(redundancy [green]{res.redundancy() * 100:.1f}%[/green])"
            )
            anomalies = res.anomalies()
            _assess_items = [
                {"level": a.level, "count": a.count, "score": a.score} for a in anomalies
            ]
            is_incident, inc_score, inc_reasons = _assess_incident(_assess_items, res.parsed_lines)
            incident_flag = " [bold red blink]⚠ INCIDENT[/bold red blink]" if is_incident else ""
            console.print(
                f"[bold cyan][LogLens][/bold cyan] Anomalies: "
                f"[bold red]{len(anomalies):,}[/bold red] 🚨{incident_flag}"
            )
            if is_incident:
                console.print(
                    f"[bold red][LogLens][/bold red] Incident score: "
                    f"[bold]{inc_score:.2f}[/bold] [dim]— {'; '.join(inc_reasons)}[/dim]"
                )
            console.print(
                "[dim]      (turbo is a fast unsupervised scan — counts differ from the "
                "default supervised model by design; drop --turbo for the model's verdict)[/dim]"
            )

            display = anomalies[:limit]
            if display:
                console.print()
                blocks = []
                for a in display:
                    col = _level_color(a.level)
                    head = (
                        f"[{col}][{a.level}][/{col}] [yellow]{a.service}[/yellow] "
                        f"[dim](×{a.count:,}, score {a.score:.2f})[/dim]  {a.sample[:100]}"
                    )
                    why = "; ".join(a.reasons) or "no signals"
                    blocks.append(f"{head}\n   [dim]↳ why: {why}[/dim]")
                console.print(
                    Panel(
                        "\n\n".join(blocks),
                        title=f"[bold red]TOP ANOMALIES ({len(anomalies)} total)[/bold red]",
                        border_style="red",
                    )
                )
                if len(anomalies) > limit:
                    console.print(
                        f"[dim]... and {len(anomalies) - limit} more "
                        f"(use --limit {limit * 2} to see more)[/dim]"
                    )
            else:
                console.print("\n[bold green] No anomalies detected![/bold green]")

            rca_result = None
            rca_entries = []
            if anomalies:
                rca_entries = [
                    LogEntry(
                        level=a.level,
                        service=a.service,
                        message=f"{a.sample} (occurred ×{a.count:,}, score {a.score})",
                        raw=a.sample,
                    )
                    for a in anomalies
                ]

            if rca and rca_entries:
                rca_result = _do_rca(
                    rca_entries, [], [], source, provider, llm_model, api_key, rca_out
                )
            elif rca:
                console.print("[dim]RCA skipped — no anomalies to analyze.[/dim]")

            if html_out:
                turbo_scores = [float(a.score) for a in anomalies] if anomalies else None
                _write_html(
                    html_out, source, res.parsed_lines, rca_entries, rca_result, scores=turbo_scores
                )

            from loglens.detection.diagnosis import diagnose as _diagnose_turbo

            def _turbo_item(a):
                _d = _diagnose_turbo(a.sample, [], level=a.level)
                return {
                    "id": _template_id(getattr(a, "template", "") or a.sample),
                    "template_id": _template_id(getattr(a, "template", "") or a.sample),
                    "template": getattr(a, "template", ""),
                    "level": a.level,
                    "service": a.service,
                    "score": round(a.score, 4),
                    "count": a.count,
                    "first_seen": None,
                    "last_seen": None,
                    "line_numbers": [],
                    "sample_lines": [a.sample],
                    "message": a.sample,
                    "calibrated_p": None,
                    "scores": {"N": 0.0, "B": 0.0, "P": 0.0, "C": 0.0, "S": 0.0, "R": None},
                    "impact": _d.impact,
                    "trace_kind": _d.trace_kind,
                    "origin": _d.origin,
                    "origin_detail": _d.origin_detail,
                    "confidence": None,
                    "r_value": None,
                    "r_status": "unknown",
                    "r_features_used": [],
                    "r_applied": False,
                    "provisional": False,
                    "retracted": False,
                    "incident_id": None,
                    "reasons": list(a.reasons or []),
                    "detector_votes": {},
                }

            turbo_items = [_turbo_item(a) for a in anomalies]
            if as_json:
                # incident/score/reasons are recomputed from items inside _emit_json.
                _emit_json(source, "turbo", None, res.parsed_lines, False, turbo_items)
            _apply_fail_on(fail_on, turbo_items)
            return  # turbo done — skip the classic pipeline

        console.print(f"\n[bold cyan][LogLens][/bold cyan] Source: [yellow]{source}[/yellow]")
        entries, line_count, fmt, fmt_conf, _layout = await _collect_entries(source)
        sample_entry = entries[0] if entries else None
        console.print(
            f"[bold cyan][LogLens][/bold cyan] Detected format: [yellow]{fmt}[/yellow] "
            f"[dim](confidence {fmt_conf:.0%})[/dim]"
        )
        console.print(
            f"[bold cyan][LogLens][/bold cyan] Lines: [bold]{line_count:,}[/bold] read "
            f"→ [bold]{len(entries):,}[/bold] parsed"
        )

        if dry_run:
            console.print("[bold cyan][LogLens][/bold cyan] --dry-run: stopping before processing.")
            return

        if not entries:
            console.print("[bold red]No valid log entries found.[/bold red]")
            return

        if deep:
            console.print(
                "[bold cyan][LogLens][/bold cyan] Mode: [bold magenta]🧠 Deep (neural embeddings)[/bold magenta] "
                "[dim]— signals: neural embeddings + clustering + timing + severity + keywords[/dim]"
            )
        else:
            console.print(
                "[bold cyan][LogLens][/bold cyan] Mode: [bold green]⚙ Fast (TF-IDF embeddings)[/bold green] "
                "[dim]— signals: TF-IDF clustering + timing + severity + keywords[/dim]"
            )
        engine = _select_engine(deep)

        console.print(
            f"[bold cyan][LogLens][/bold cyan] Computing embeddings for [bold]{len(entries):,}[/bold] entries..."
        )
        if deep and hasattr(engine, "embed_templates"):
            registry = TemplateRegistry(entries)
            console.print(
                f"[bold cyan][LogLens][/bold cyan] Unique templates: "
                f"[bold]{len(registry):,}[/bold] "
                f"[dim](encoding templates, not lines)[/dim]"
            )
            with console.status(
                "[bold magenta]🧠 Encoding templates with the neural model…[/bold magenta]",
                spinner="dots",
            ):
                vectors = engine.embed_templates(entries, registry)
        else:
            # Large inputs embed in chunks — show a live bar so it never looks hung.
            if len(entries) > 50_000 and not as_json:
                emb_prog = LiveProgress(total=len(entries))
                emb_prog.start()
                try:
                    vectors = engine.embed(
                        entries, progress=lambda done, total: emb_prog.update(done)
                    )
                finally:
                    emb_prog.stop()
            else:
                with console.status(
                    "[bold cyan]⚙ Computing embeddings…[/bold cyan]", spinner="dots"
                ):
                    vectors = engine.embed(entries)
        console.print(
            f"[bold cyan][LogLens][/bold cyan] Embeddings ready: "
            f"[bold green]shape={vectors.shape}[/bold green]"
        )

        from loglens.application import baseline_store as _bstore

        _bkey = _bstore.baseline_key(source, profile)
        _sdir = state_dir or None
        _baseline = _bstore.load_baseline(_bkey, _sdir) if learn else None

        # --- anomaly detection ---
        with console.status(
            "[bold cyan]🔍 Detecting anomalies (clustering + scoring)…[/bold cyan]", spinner="dots"
        ):
            normal, anomalies, labels = detect_anomalies(
                entries, vectors, config=DetectorConfig(seed=seed), baseline=_baseline
            )
        summary = cluster_summary(labels)

        if learn:
            _anom_ids = {id(a) for a in anomalies}
            _flagged_mask = [id(e) in _anom_ids for e in entries]
            _updated = _bstore.update_baseline(_baseline, entries, _flagged_mask)
            try:
                _bstore.save_baseline(_bkey, _updated, _sdir)
                console.print(
                    f"[bold cyan][LogLens][/bold cyan] 📚 baseline updated: "
                    f"[bold]{_updated['total']:,}[/bold] normal lines learned across "
                    f"[bold]{_updated['learned_runs']}[/bold] run(s), "
                    f"{len(_updated['templates']):,} known templates"
                    + ("" if _baseline else " [dim](first run — cold; next run is smarter)[/dim]")
                )
            except OSError as _exc:
                console.print(f"[dim][LogLens] baseline not saved: {_exc}[/dim]")

            try:
                import numpy as _np

                from loglens.application import autotrain as _autotrain
                from loglens.detection.benchmark import build_feature_matrix as _bfm

                _scores_at = _np.array(
                    [getattr(e, "anomaly_score", 0.0) for e in entries], dtype=float
                )
                _feats = _bfm(entries, _scores_at)
                _ymask = _np.array([1 if f else 0 for f in _flagged_mask], dtype=int)
                _auto_path, _auto_ready = _autotrain.record_and_maybe_fit(
                    _bkey, _feats, _ymask, _sdir
                )
            except Exception:
                _auto_path, _auto_ready = None, False

        # --- supervised: explicit model, else bundled default, else unsupervised ---
        # `--model auto` uses the head auto-trained from this source's own usage.
        # (Local copies so we never rebind the enclosing analyze() params.)
        model_sel = model
        no_model_eff = no_model
        if model_sel.strip().lower() == "auto":
            from loglens.application import autotrain as _at

            _amp = _at.auto_model_path(_bstore.baseline_key(source, profile), state_dir or None)
            if os.path.isfile(_amp):
                model_sel = _amp
            else:
                console.print(
                    "[yellow][LogLens][/yellow] No auto-trained head yet — keep running "
                    "`analyze` (with learning on) to build one; using unsupervised for now."
                )
                model_sel = ""
                no_model_eff = True
        model_path = model_sel
        used_default = False
        if not model_sel and not no_model_eff:
            try:
                from importlib.resources import files

                cand = files("loglens") / "assets" / "default_model.pkl"
                if cand.is_file():
                    model_path = str(cand)
                    used_default = True
            except Exception as exc:
                console.print(
                    "[yellow][LogLens][/yellow] Could not locate the bundled model "
                    f"({type(exc).__name__}: {exc}); continuing with unsupervised "
                    "detection."
                )
                model_path = ""

        if model_path:
            import numpy as _np

            from loglens.detection.benchmark import SupervisedHead, build_feature_matrix

            try:
                head = SupervisedHead.load(model_path)
            except Exception as exc:
                console.print(f"[bold red]Could not load model '{model_path}': {exc}[/bold red]")
                raise typer.Exit(code=1) from exc
            if used_default:
                console.print(
                    "[bold cyan][LogLens][/bold cyan] Model:      "
                    "[magenta]bundled default[/magenta] "
                    "[dim](trained on infra logs; `loglens train` for your own; "
                    "--no-model to disable)[/dim]"
                )
            else:
                console.print(
                    f"[bold cyan][LogLens][/bold cyan] Model:      "
                    f"[magenta]{model_path}[/magenta] [dim](supervised head)[/dim]"
                )
            _scores = _np.array([getattr(e, "anomaly_score", 0.0) for e in entries], dtype=float)
            _preds = head.predict(build_feature_matrix(entries, _scores))
            anomalies = [e for e, p in zip(entries, _preds, strict=False) if int(p) == 1]

        if explain:
            ranked = sorted(entries, key=lambda e: getattr(e, "anomaly_score", 0.0), reverse=True)[
                :explain
            ]
            console.print()
            console.print(
                Panel(
                    "\n".join(
                        f"[bold]{getattr(e, 'anomaly_score', 0.0):.3f}[/bold] "
                        f"[{'red' if getattr(e, 'anomaly_score', 0) >= 0.70 else 'yellow'}]"
                        f"[{e.level}][/] [cyan]{e.service}[/cyan] {e.message[:70]}\n"
                        f"        [dim]{'; '.join(getattr(e, 'anomaly_reasons', [])) or 'no signals'}[/dim]"
                        for e in ranked
                    ),
                    title=f"[bold cyan]TOP {len(ranked)} SCORED ENTRIES "
                    f"(threshold 0.70)[/bold cyan]",
                    border_style="cyan",
                )
            )

        # Use len(anomalies) — actual score-flagged count, not just noise points
        n_anomalies = len(anomalies)
        incident_flag = ""
        inc_score = 0.0
        inc_reasons: list[str] = []
        if n_anomalies > 0:
            _assess_items = [
                {"level": a.level, "count": 1, "score": getattr(a, "anomaly_score", 0.0)}
                for a in anomalies
            ]
            is_incident, inc_score, inc_reasons = _assess_incident(_assess_items, len(entries))
            if is_incident:
                incident_flag = " [bold red blink]⚠ INCIDENT[/bold red blink]"

        # --- category-wise breakdown ---
        level_counts: dict = {}
        for a in anomalies:
            lvl = a.level.upper()
            level_counts[lvl] = level_counts.get(lvl, 0) + 1

        console.print(
            f"[bold cyan][LogLens][/bold cyan] Clusters found: [bold]{summary['clusters']}[/bold]"
        )
        console.print(
            f"[bold cyan][LogLens][/bold cyan] Anomalies detected: "
            f"[bold red]{n_anomalies:,}[/bold red] 🚨{incident_flag}"
        )
        if incident_flag:
            console.print(
                f"[bold red][LogLens][/bold red] Incident score: "
                f"[bold]{inc_score:.2f}[/bold] [dim]— {'; '.join(inc_reasons)}[/dim]"
            )

        # print breakdown tree
        ordered_levels = [lvl for lvl in CATEGORY_ORDER if lvl in level_counts]
        # also catch any unexpected levels
        for lvl in level_counts:
            if lvl not in ordered_levels:
                ordered_levels.append(lvl)
        for idx, lvl in enumerate(ordered_levels):
            is_last = idx == len(ordered_levels) - 1
            branch = "└──" if is_last else "├──"
            color = RICH_STYLES.get(lvl, RICH_STYLE_DEFAULT)
            console.print(
                f"[bold cyan]          {branch}[/bold cyan] "
                f"[{color}]{lvl:<10}[/{color}] : [bold]{level_counts[lvl]:,}[/bold]"
            )

        # --- worker pool ---
        progress = LiveProgress(total=len(entries))
        processed_count = 0

        def process_fn(entry):
            nonlocal processed_count
            processed_count += 1
            if not as_json:
                progress.update(processed_count)

        if not as_json:
            progress.start()

        async def entry_stream():
            for e in entries:
                yield e

        stats = await run_worker_pool(
            entry_stream(),
            process_fn,
            num_workers=workers,
        )

        if not as_json:
            progress.stop()

        console.print(
            f"\n[bold cyan][LogLens][/bold cyan] Processed: [bold green]{stats['processed']:,}[/bold green]"
        )
        console.print(
            f"[bold cyan][LogLens][/bold cyan] Skipped:   [bold red]{stats['skipped']}[/bold red]"
        )

        # --- severity ranking (suppress INFO false positives) ---
        filtered_anomalies = [
            a
            for a in anomalies
            if a.level.upper() != "INFO" or any(kw in a.message.lower() for kw in INFO_KEYWORDS)
        ]

        if sort_by == "severity":
            filtered_anomalies.sort(key=_severity)
        elif sort_by == "service":
            filtered_anomalies.sort(key=lambda a: a.service)

        # --- Phase 1: template grouping (families, ×N) ---
        groups = group_anomalies(filtered_anomalies)

        from loglens.detection.routineness import compute_routineness, confidence_label
        from loglens.detection.timeutil import humanize_delta, humanize_span, parse_ts

        _rmap = compute_routineness(entries, baseline=_baseline)

        _gtimes: dict[int, tuple] = {}
        _anchor = None
        for g in groups:
            dts = [parse_ts(filtered_anomalies[i].timestamp) for i in g.indices]
            dts = [d for d in dts if d is not None]
            first_dt, last_dt = (min(dts), max(dts)) if dts else (None, None)
            _gtimes[id(g)] = (first_dt, last_dt)
            if last_dt and (_anchor is None or last_dt > _anchor):
                _anchor = last_dt

        _MIN_DT = __import__("datetime").datetime.min
        if sort_by == "recent":
            groups.sort(key=lambda g: _gtimes[id(g)][1] or _MIN_DT, reverse=True)
        elif sort_by == "time":
            groups.sort(key=lambda g: _gtimes[id(g)][0] or _MIN_DT)
        elif sort_by == "service":
            groups.sort(key=lambda g: (g.service, -g.max_score))

        def _conf_color(label: str) -> str:
            head = label.split()[0]
            return {"High": "red", "Medium": "yellow", "Low": "green"}.get(head, "dim")

        def _when_str(gid: int, count: int) -> str:
            first_dt, last_dt = _gtimes[gid]
            if last_dt is None:
                return "no timestamp"
            parts = [f"last {last_dt.strftime('%Y-%m-%d %H:%M:%S')}"]
            if _anchor is not None:
                parts.append(humanize_delta(_anchor - last_dt))
            if count > 1 and first_dt is not None and first_dt != last_dt:
                parts.append(f"span {humanize_span(first_dt, last_dt)}")
            return " · ".join(parts)

        if groups:
            display = groups[:limit]
            console.print()
            from loglens.detection.diagnosis import diagnose as _diagnose

            blocks = []
            for g in display:
                col = _level_color(g.level)
                r = _rmap.get(g.template)
                conf, _ = confidence_label(g.max_score, r)
                _d = _diagnose(g.sample, [], level=g.level)
                _chip, _icol = _IMPACT_STYLE.get(_d.impact, ("❓ Unknown", "dim"))
                head = (
                    f"[{_icol}]{_chip.split()[0]}[/{_icol}] "
                    f"[{col}][{g.level}][/{col}] [yellow]{g.service}[/yellow] "
                    f"[dim](×{g.count:,} · score {g.max_score:.2f} · {_when_str(id(g), g.count)})[/dim]"
                    f"  {g.sample[:100]}"
                )
                why = "; ".join(getattr(g, "reasons", []) or []) or "no signals"
                if r is not None and r.note:
                    why = f"{why}; {r.note}"
                badge = (
                    f"   [dim]↳ why: {why}[/dim]  "
                    f"[[{_conf_color(conf)}]confidence: {conf}[/{_conf_color(conf)}]]"
                )
                blocks.append(f"{head}\n{badge}")
            console.print(
                Panel(
                    "\n\n".join(blocks),
                    title=f"[bold red]ANOMALY FAMILIES ({len(groups)} families, "
                    f"{len(filtered_anomalies)} events)[/bold red] "
                    f"[dim]— newest first[/dim]"
                    if sort_by == "recent"
                    else f"[bold red]ANOMALY FAMILIES ({len(groups)} families, "
                    f"{len(filtered_anomalies)} events)[/bold red]",
                    border_style="red",
                )
            )
            if len(groups) > limit:
                console.print(
                    f"[dim]... and {len(groups) - limit} more families "
                    f"(use --limit {limit * 2} to see more, or `loglens explain` for detail)[/dim]"
                )
            suppressed = len(anomalies) - len(filtered_anomalies)
            if suppressed:
                console.print(f"[dim]{suppressed} INFO-level false positives suppressed[/dim]")
        else:
            console.print("\n[bold green] No anomalies detected![/bold green]")

        if not as_json and not model.strip():
            from loglens.application import autotrain as _at2

            _amp2 = _at2.auto_model_path(_bstore.baseline_key(source, profile), state_dir or None)
            if os.path.isfile(_amp2):
                console.print(
                    "[dim][LogLens] 🤖 A supervised head trained on your usage is ready — "
                    "rerun with [magenta]--model auto[/magenta] for a second opinion.[/dim]"
                )
            elif groups:
                console.print(
                    "[dim][LogLens] Not the results you expected? LogLens is auto-building a "
                    "supervised head from your usage (use it later with [magenta]--model auto"
                    "[/magenta]); for labelled data, [magenta]loglens train <file>[/magenta].[/dim]"
                )

        # --- AI root-cause analysis (classic path) ---
        # Phase 1: send ONE representative entry per family (×N in message) — far cheaper tokens
        rca_result = None
        rca_input = []
        if groups:
            rca_input = _groups_to_rca_entries(groups)
        if rca:
            if rca_input:
                scores = [g.max_score for g in groups]
                reasons = ["; ".join(g.reasons) for g in groups]
                rca_result = _do_rca(
                    rca_input, scores, reasons, source, provider, llm_model, api_key, rca_out
                )
            else:
                console.print("[dim]RCA skipped — no anomalies to analyze.[/dim]")

        # --- HTML report (Phase 3: with score distribution) ---
        if html_out:
            entry_scores = [getattr(e, "anomaly_score", 0.0) for e in entries]
            _write_html(
                html_out, source, len(entries), filtered_anomalies, rca_result, scores=entry_scores
            )

        line_of = {id(e): i + 1 for i, e in enumerate(entries)}
        classic_items = [
            _family_item(g, [filtered_anomalies[i] for i in g.indices], line_of, _rmap)
            for g in groups
        ]
        if as_json:
            _emit_json(
                source,
                "deep" if deep else "fast",
                line_count,
                len(entries),
                bool(incident_flag),
                classic_items,
            )
        _apply_fail_on(fail_on, classic_items)

        if verbose and sample_entry:
            table = Table(title="Sample Parsed Entry")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")
            table.add_row("timestamp", sample_entry.timestamp)
            table.add_row("level", sample_entry.level)
            table.add_row("service", sample_entry.service)
            table.add_row("message", sample_entry.message)
            console.print(table)

    asyncio.run(_run())


_IMPACT_STYLE = {
    "blocking": ("⛔ Blocking", "red"),
    "non-blocking": ("⚠ Non-blocking", "yellow"),
    "unknown": ("❓ Unknown", "dim"),
}


def _explain_frames_str(frames: list) -> str:
    """Render a frame chain as ``a.py:10 in f → b.py:20 (lib)``, library frames dimmed."""
    from rich.markup import escape

    parts = []
    for f in frames[:8]:
        loc = escape(f.basename + (f":{f.line}" if f.line is not None else ""))
        if f.func:
            loc += f" in {escape(f.func)}"
        parts.append(f"[dim]{loc} (lib)[/dim]" if f.is_library else loc)
    return " → ".join(parts)


@app.command()
def explain(
    source: str = typer.Option(..., "--source", help="Log source: file path, URL, or stdin"),
    last: str = typer.Option(
        "24h",
        "--last",
        help="Look back this far from the newest event: 24h, 6h, 2d, 90m (default 24h).",
    ),
    since: str = typer.Option(
        "", "--since", help="Absolute lower bound, e.g. '2024-01-01 00:00:00' (overrides --last)."
    ),
    until: str = typer.Option(
        "", "--until", help="Absolute upper bound (default: the newest event in the log)."
    ),
    now: bool = typer.Option(
        False,
        "--now",
        help="Anchor the window to wall-clock now instead of the log's newest event.",
    ),
    top: int = typer.Option(20, "--top", help="Max error cards to show (most recent first)."),
    buckets: int = typer.Option(24, "--buckets", help="Sparkline resolution across the window."),
    plain: bool = typer.Option(
        False,
        "--plain",
        help="Non-technical view: show What / Impact / When / File only (hide trace & internals).",
    ),
    impact_filter: str = typer.Option(
        "",
        "--impact",
        help="Only show families with this impact: blocking | non-blocking | unknown.",
    ),
    output_format: str = typer.Option("terminal", "--format", help="terminal (default) | json"),
    seed: int = typer.Option(
        0, "--seed", help="Reproducible runs (same input + seed → identical)."
    ),
    profile: str = typer.Option("", "--profile", help="Baseline name (for novelty/routineness)."),
    state_dir: str = typer.Option("", "--state-dir", help="Where baselines are stored."),
    no_learn: bool = typer.Option(
        False, "--no-learn", help="Ignore the learned baseline (explain reads it, never writes)."
    ),
):
    """Explain anomalies as descriptive incident cards — when it happened, how often
    (frequency + timeline), and where (polished stack trace / source location) —
    within a time window (default: the last 24h of the log)."""
    import datetime as _dt

    from rich.markup import escape

    from loglens.application.api import analyze_entries as _analyze_entries
    from loglens.detection.grouping import group_anomalies as _group
    from loglens.detection.routineness import compute_routineness, confidence_label
    from loglens.detection.run import RunConfig
    from loglens.detection.timeutil import (
        bucketize,
        humanize_delta,
        humanize_span,
        parse_duration,
        parse_ts,
        sparkline,
    )
    from loglens.detection.trace import primary_site, raw_block, reconstruct_trace

    _load()
    _seed_everything(seed)
    as_json = output_format.strip().lower() == "json"
    console.quiet = as_json

    from loglens.detection.filetype import InvalidSourceError, check_source

    try:
        check_source(source)
    except InvalidSourceError as _e:
        console.print(f"[bold red][LogLens][/bold red] {_e}")
        raise typer.Exit(code=1) from None

    from loglens.application import baseline_store as _bstore

    _sdir = state_dir or None
    _baseline = None
    if not no_learn:
        _baseline = _bstore.load_baseline(_bstore.baseline_key(source, profile), _sdir)

    entries, _line_count, _fmt, _fmt_conf, _layout = asyncio.run(_collect_entries(source))
    res = _analyze_entries(entries, RunConfig(mode="fast"), baseline=_baseline, fmt=_fmt)
    entries = res.entries
    anoms = list(res.anomalies)
    rmap = compute_routineness(entries, baseline=_baseline)

    dated = [(a, parse_ts(getattr(a, "timestamp", ""))) for a in anoms]
    parsed = [(a, d) for a, d in dated if d is not None]
    undated = [a for a, d in dated if d is None]

    newest = max((d for _, d in parsed), default=None)
    anchor = _dt.datetime.now() if now else newest
    win_hi = parse_ts(until) if until else anchor
    dur = parse_duration(last) or _dt.timedelta(hours=24)
    win_lo = parse_ts(since) if since else (win_hi - dur if win_hi else None)

    if win_lo is not None and win_hi is not None:
        in_window = [(a, d) for a, d in parsed if win_lo <= d <= win_hi]
        windowed = True
    else:  # no usable timestamps — explain everything, and say so
        in_window = parsed
        windowed = False

    win_anoms = [a for a, _ in in_window]
    win_dts = {id(a): d for a, d in in_window}
    groups = _group(
        win_anoms,
        scores=[a.score for a in win_anoms],
        reasons=[list(a.reasons) for a in win_anoms],
    )

    def _members(g):
        return [win_anoms[i] for i in g.indices]

    def _g_times(g):
        ds = [win_dts[id(m)] for m in _members(g) if win_dts.get(id(m)) is not None]
        return (min(ds), max(ds)) if ds else (None, None)

    # order newest-first
    _MIN = _dt.datetime.min
    groups.sort(key=lambda g: _g_times(g)[1] or _MIN, reverse=True)

    from loglens.detection.diagnosis import diagnose

    def _recovery_after(idx: int | None, service: str) -> bool:
        from loglens.detection.diagnosis import _RECOVERY

        if idx is None:
            return False
        for e in entries[idx + 1 : idx + 400]:
            if getattr(e, "service", "") == service:
                low = (getattr(e, "raw", "") or e.message).lower()
                if any(w in low for w in _RECOVERY):
                    return True
        return False

    # --- build structured records (used by both terminal + json) ----------- #
    records = []
    for g in groups:
        members = _members(g)
        first_dt, last_dt = _g_times(g)
        rep = max(members, key=lambda m: m.score)  # representative for the trace
        frames = (
            reconstruct_trace(entries, rep.index) if getattr(rep, "index", None) is not None else []
        )
        site = primary_site(frames)
        _ridx = getattr(rep, "index", None)
        diag_text = (
            raw_block(entries, _ridx)
            if _ridx is not None
            else (getattr(rep, "raw", "") or rep.message)
        )
        diag = diagnose(
            diag_text,
            frames,
            level=g.level,
            recovery_follows=_recovery_after(getattr(rep, "index", None), g.service),
        )
        r = rmap.get(g.template)
        conf, conf_adj = confidence_label(g.max_score, r)
        times = [win_dts[id(m)] for m in members if win_dts.get(id(m)) is not None]
        spark = ""
        if windowed and win_lo and win_hi and times:
            spark = sparkline(bucketize(times, win_lo, win_hi, buckets))
        records.append(
            {
                "level": g.level,
                "service": g.service,
                "template": g.template,
                "template_id": _template_id(g.template or g.sample),
                "message": g.sample,
                "score": round(g.max_score, 4),
                "count": g.count,
                "first_seen": first_dt.isoformat() if first_dt else None,
                "last_seen": last_dt.isoformat() if last_dt else None,
                "frequency": g.count,
                "sparkline": spark,
                "trace_kind": diag.trace_kind,
                "impact": diag.impact,
                "impact_reason": diag.impact_reason,
                "exception_type": diag.exception_type,
                "origin": diag.origin,
                "origin_detail": diag.origin_detail,
                "headline": diag.headline,
                "where": diag.where_human,
                "site": site.location() if site else None,
                "trace": [f.location() for f in frames[:8]],
                "confidence": conf,
                "confidence_value": round(conf_adj, 4),
                "r_value": round(r.r, 4) if r and r.r is not None else None,
                "r_status": r.status if r else "unknown",
                "reasons": list(getattr(g, "reasons", []) or [])
                + ([r.note] if r and r.note else []),
                "_first_dt": first_dt,
                "_last_dt": last_dt,
                "_frames": frames,
                "_site": site,
                "_diag": diag,
            }
        )

    explain_incidents = _build_incidents(source, records)

    _imp = impact_filter.strip().lower()
    if _imp:
        records = [r for r in records if r["impact"] == _imp]

    if as_json:
        payload = {
            "schema": "loglens.explain.v1",
            "version": __version__,
            "source": source,
            "window": {
                "from": win_lo.isoformat() if win_lo else None,
                "to": win_hi.isoformat() if win_hi else None,
                "anchored_to": "wall-clock" if now else "newest-event",
                "applied": windowed,
            },
            "anomaly_families": len(records),
            "events_in_window": len(win_anoms),
            "undated_events": len(undated),
            "impact_summary": {
                k: sum(1 for r in records if r["impact"] == k)
                for k in ("blocking", "non-blocking", "unknown")
            },
            "incidents": explain_incidents,
            "anomalies": [
                {k: v for k, v in rec.items() if not k.startswith("_")} for rec in records
            ],
        }
        print(json.dumps(payload, indent=2))
        return

    _conf_color = {"High": "red", "Medium": "yellow", "Low": "green"}

    _shown_events = sum(r["count"] for r in records)
    _filter_note = f" · filtered to {_imp}" if _imp else ""

    console.print()
    if windowed and win_lo is not None and win_hi is not None:
        console.print(
            f"[bold cyan][LogLens][/bold cyan] Explaining [bold]{_shown_events}[/bold] anomaly "
            f"events in [bold]{len(records)}[/bold] families "
            f"[dim]· window {win_lo.strftime('%Y-%m-%d %H:%M')} → {win_hi.strftime('%Y-%m-%d %H:%M')} "
            f"({'wall-clock' if now else 'newest event'} − {last if not since else 'since ' + since})"
            f"{_filter_note}[/dim]"
        )
    else:
        console.print(
            f"[bold cyan][LogLens][/bold cyan] Explaining [bold]{_shown_events}[/bold] anomaly "
            f"events in [bold]{len(records)}[/bold] families "
            f"[dim]· no parseable timestamps — showing all (time window not applied){_filter_note}[/dim]"
        )
    if undated:
        console.print(
            f"[dim][LogLens] {len(undated)} undated event(s) excluded from the window view.[/dim]"
        )

    if not records:
        console.print("\n[bold green] No anomalies in this window.[/bold green]")
        return

    recurring = sorted(records, key=lambda r: r["count"], reverse=True)
    if recurring and recurring[0]["count"] > 1:
        t = Table(
            title="Most frequent in window", title_style="bold cyan", box=None, pad_edge=False
        )
        t.add_column("×", justify="right", style="bold")
        t.add_column("Level")
        t.add_column("Service", style="yellow")
        t.add_column("Error")
        for rec in recurring[:5]:
            if rec["count"] < 2:
                continue
            col = _level_color(rec["level"])
            t.add_row(
                f"{rec['count']:,}",
                f"[{col}]{rec['level']}[/{col}]",
                rec["service"],
                escape(rec["message"][:60]),
            )
        console.print()
        console.print(t)

    _tally = {
        k: sum(1 for r in records if r["impact"] == k)
        for k in ("blocking", "non-blocking", "unknown")
    }
    console.print(
        f"[dim][LogLens] Impact:[/dim] [red]⛔ {_tally['blocking']} blocking[/red] · "
        f"[yellow]⚠ {_tally['non-blocking']} non-blocking[/yellow] · "
        f"[dim]❓ {_tally['unknown']} unknown[/dim]"
    )

    _origin_word = {
        "your_code": "your code",
        "dependency": "dependency",
        "upstream_service": "upstream service",
        "system": "system",
        "unknown": "unknown",
    }
    if explain_incidents:
        lines = []
        for inc in explain_incidents:
            col = _level_color(inc["level"])
            span = inc["span_seconds"]
            span_s = f"{span // 60}m" if span >= 60 else f"{span}s"
            chain = " → ".join(inc["services"][:6]) or "—"
            rc = inc["root_cause"]
            ow = _origin_word.get(rc["origin"], rc["origin"])
            detail = f" ({escape(rc['origin_detail'])})" if rc.get("origin_detail") else ""
            lines.append(
                f"[bold]{inc['id']}[/bold]  [{col}]{inc['level']}[/{col}] · "
                f"{inc['events']} events · {span_s} · [yellow]{escape(chain)}[/yellow]\n"
                f"   [dim]root cause:[/dim] [bold]{ow}[/bold]{detail} [dim]— "
                f"{escape(rc['message'][:70])}[/dim]"
            )
        console.print()
        console.print(
            Panel(
                "\n\n".join(lines),
                title=f"[bold red]INCIDENTS ({len(explain_incidents)})[/bold red]",
                border_style="red",
                title_align="left",
            )
        )

    anchor_dt = win_hi or newest
    for rec in records[:top]:
        col = _level_color(rec["level"])
        ilabel, icolor = _IMPACT_STYLE.get(rec["impact"], ("❓ Unknown", "dim"))
        lines = []

        lines.append(f"[bold]What[/bold]    {escape(rec['headline'])}")

        impact_help = {
            "blocking": "halted this request / flow",
            "non-blocking": "system kept running",
            "unknown": "impact unclear",
        }[rec["impact"]]
        lines.append(
            f"[bold]Impact[/bold]  [{icolor}]{ilabel}[/{icolor}] — {impact_help}  "
            f"[dim]({escape(rec['impact_reason'])})[/dim]"
        )

        ow = _origin_word.get(rec["origin"], rec["origin"])
        odetail = (
            f" [magenta]{escape(rec['origin_detail'])}[/magenta]"
            if rec.get("origin_detail")
            else ""
        )
        lines.append(f"[bold]Origin[/bold]  {ow}{odetail}")

        if rec["_last_dt"]:
            when = f"last [bold]{rec['_last_dt'].strftime('%Y-%m-%d %H:%M:%S')}[/bold]"
            if anchor_dt:
                when += f" [dim]({humanize_delta(anchor_dt - rec['_last_dt'])})[/dim]"
            if rec["count"] > 1 and rec["_first_dt"] and rec["_first_dt"] != rec["_last_dt"]:
                when += (
                    f" [dim]· first {rec['_first_dt'].strftime('%H:%M:%S')} "
                    f"· span {humanize_span(rec['_first_dt'], rec['_last_dt'])}[/dim]"
                )
        else:
            when = "[dim]no timestamp[/dim]"
        lines.append(f"[bold]When[/bold]    {when}")

        freq = f"[bold]{rec['count']:,}×[/bold] in window"
        if rec["sparkline"]:
            freq += f"   [cyan]{rec['sparkline']}[/cyan]"
        lines.append(f"[bold]Freq[/bold]    {freq}")

        diag = rec["_diag"]
        site = rec["_site"]
        if diag.trace_kind == "application" and site:
            loc = f"[magenta]{escape(site.file)}[/magenta]"
            loc += f" [bold]→ line {site.line}[/bold]" if site.line is not None else ""
            loc += f" [dim]in {escape(site.func)}[/dim]" if site.func else ""
            lines.append(f"[bold]File[/bold]    {loc}  [green]← your code[/green]")
        elif diag.trace_kind == "library" and site:
            lines.append(
                f"[bold]File[/bold]    [magenta]{escape(site.file)}[/magenta]"
                + (f":{site.line}" if site.line is not None else "")
                + "  [dim]← inside a library (called from your code)[/dim]"
            )
        elif diag.trace_kind == "location_only" and site:
            lines.append(
                f"[bold]File[/bold]    [magenta]{escape(site.location())}[/magenta]  "
                "[dim]← mentioned in the log[/dim]"
            )
        elif diag.trace_kind == "exception_only":
            lines.append(
                f"[bold]Cause[/bold]   {escape(diag.exception_type or 'exception')}  "
                "[dim]← no source file in this log[/dim]"
            )
        else:  # plain — no trace at all: show the raw line so it's still actionable
            lines.append(f"[bold]Detail[/bold]  [dim]{escape(rec['message'][:100])}[/dim]")

        if not plain:
            if rec["_frames"]:
                lines.append(f"[bold]Trace[/bold]   {_explain_frames_str(rec['_frames'])}")
            why = "; ".join(rec["reasons"]) or "no signals"
            lines.append(f"[bold]Why[/bold]     [dim]{escape(why)}[/dim]")
            cc = _conf_color.get(rec["confidence"].split()[0], "dim")
            lines.append(
                f"[bold]Conf[/bold]    [{cc}]{rec['confidence']}[/{cc}]  "
                f"[dim](score {rec['score']:.2f})[/dim]"
            )

        chip = ilabel.split()[0]  # the emoji
        title = (
            f"[{icolor}]{chip}[/{icolor}] [{col}]{rec['level']}[/{col}] · "
            f"[yellow]{rec['service']}[/yellow] · {escape(rec['message'][:70])}"
        )
        console.print()
        console.print(Panel("\n".join(lines), title=title, title_align="left", border_style=col))

    if len(records) > top:
        console.print(
            f"[dim]... and {len(records) - top} more families "
            f"(use --top {top * 2}, or narrow with --last / --since / --impact)[/dim]"
        )


@app.command()
def ask(
    question: str = typer.Argument(
        ..., help='Free-form question about the log, e.g. "why did db-service degrade?"'
    ),
    source: str = typer.Option(..., help="Log source: file path"),
    deep: bool = typer.Option(False, "--deep", help="Use neural embeddings for detection"),
    provider: str = typer.Option("", "--provider", help="LLM provider: openai | azure | groq"),
    llm_model: str = typer.Option("", "--llm-model", help="LLM model / Azure deployment name"),
    api_key: str = typer.Option(
        "", "--api-key", help="LLM API key (prefer env LOGLENS_LLM_API_KEY)"
    ),
):
    """Ask a natural-language question about a log (AI, needs an LLM key)."""
    _load()

    async def _run():
        console.print(f"\n[bold cyan][LogLens][/bold cyan] Source: [yellow]{source}[/yellow]")
        entries, _line_count, _fmt, _fmt_conf, _layout = await _collect_entries(source)
        if not entries:
            console.print("[bold red]No valid log entries found.[/bold red]")
            raise typer.Exit(code=1)

        engine = _select_engine(deep)
        if deep:
            registry = TemplateRegistry(entries)
            vectors = engine.embed_templates(entries, registry)
        else:
            vectors = engine.embed(entries)

        console.print(
            f"[bold cyan][LogLens][/bold cyan] Detecting anomalies locally on [bold]{len(entries):,}[/bold] entries..."
        )
        normal, anomalies, labels = detect_anomalies(entries, vectors)
        console.print(
            f"[bold cyan][LogLens][/bold cyan] Anomalies found: [bold red]{len(anomalies):,}[/bold red]"
        )

        try:
            cfg = LLMConfig.from_env(provider=provider, model=llm_model, api_key=api_key)
            console.print(
                f"[bold cyan][LogLens][/bold cyan] 🤖 Asking [bold]{cfg.provider}[/bold] ([dim]{cfg.model}[/dim])..."
            )

            groups = group_anomalies(anomalies)
            ranked = [
                LogEntry(
                    level=g.level,
                    service=g.service,
                    message=f"{g.sample} (occurred ×{g.count:,}, score {g.max_score:.2f})",
                    raw=g.sample,
                )
                for g in groups
            ]
            scores = [g.max_score for g in groups]
            reasons = ["; ".join(g.reasons) for g in groups]
            result = run_ask(
                question, ranked, cfg, scores=scores, reasons=reasons, source_name=source
            )
            console.print()
            console.print(
                Panel(
                    Markdown(result.report),
                    title=f"💬 {question[:80]}",
                    border_style="cyan",
                )
            )
            u = result.usage
            console.print(
                f"[dim]Sent {result.anomalies_sent} anomaly summaries. "
                f"Tokens: {u.total_tokens:,} (prompt {u.prompt_tokens:,} / completion {u.completion_tokens:,})[/dim]"
            )
        except LLMError as e:
            console.print(f"[bold red][LogLens][/bold red] Ask failed: {e}")
            _print_llm_config_hint()
            raise typer.Exit(code=1) from None

    asyncio.run(_run())


@app.command()
def benchmark(
    dataset: str = typer.Argument(..., help="Path to labeled log file"),
    fmt: str = typer.Option("bgl", "--format", help="Label format: bgl | jsonl | labeled"),
    limit: int = typer.Option(None, "--limit", help="Max lines to load (default: all)"),
    grid: bool = typer.Option(False, "--grid", help="Grid-search feature_weight x threshold"),
    supervised: bool = typer.Option(
        False, "--supervised", help="Train + eval supervised (RandomForest) head"
    ),
    min_f1: float = typer.Option(None, "--min-f1", help="Fail (exit 1) if baseline F1 below this"),
):
    """Measure detection accuracy (precision/recall/F1) on a labeled dataset."""
    _load()
    console.print(
        f"\n[bold cyan][LogLens][/bold cyan] Benchmarking: [yellow]{dataset}[/yellow] "
        f"([dim]format={fmt}[/dim])"
    )

    with console.status("[cyan]Parsing, embedding, detecting...[/cyan]"):
        out = cast(
            "dict[str, Any]",
            run_benchmark(dataset, fmt=fmt, limit=limit, do_grid=grid, do_supervised=supervised),
        )

    if out.get("entries", 0) == 0:
        console.print("[bold red]No entries loaded — check path/format.[/bold red]")
        raise typer.Exit(code=1)

    console.print(
        f"[bold cyan][LogLens][/bold cyan] Loaded [bold]{out['entries']:,}[/bold] entries, "
        f"[bold red]{out['positives']:,}[/bold red] labeled anomalies\n"
    )

    table = Table(title="Detection Accuracy", show_header=True, header_style="bold cyan")
    table.add_column("Method", style="white")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1", justify="right", style="bold")

    def _row(name, m):
        table.add_row(name, f"{m['precision']:.3f}", f"{m['recall']:.3f}", f"{m['f1']:.3f}")

    baseline = out["baseline"]
    _row("Rule + embeddings (baseline)", baseline)
    if "supervised" in out:
        _row("Supervised head (RandomForest)", out["supervised"])
    console.print(table)

    if "grid_best_f1" in out:
        p = out["grid_best_params"]
        console.print(
            f"\n[bold cyan][LogLens][/bold cyan] Grid-search best F1: "
            f"[bold green]{out['grid_best_f1']:.3f}[/bold green] @ "
            f"feature_weight=[yellow]{p['feature_weight']}[/yellow], "
            f"threshold=[yellow]{p['flag_threshold']}[/yellow]"
        )
        console.print("[dim]  → bake these into embeddings.py / detector.py defaults[/dim]")

    if min_f1 is not None:
        f1 = baseline["f1"]
        if f1 < min_f1:
            console.print(f"\n[bold red]✗ FAIL: F1 {f1:.3f} < required {min_f1:.3f}[/bold red]")
            raise typer.Exit(code=1)
        console.print(f"\n[bold green]✓ PASS: F1 {f1:.3f} >= {min_f1:.3f}[/bold green]")


@app.command()
def train(
    dataset: str = typer.Argument(..., help="Path to a LABELED log file to learn from"),
    out: str = typer.Option(
        "loglens-model.pkl", "--out", "-o", help="Where to save the trained model"
    ),
    fmt: str = typer.Option("bgl", "--format", help="Label format: bgl | jsonl | labeled"),
    limit: int = typer.Option(None, "--limit", help="Max lines to load (default: all)"),
    no_cv: bool = typer.Option(
        False, "--no-cv", help="Skip cross-validation (faster, no accuracy estimate)"
    ),
):
    """Train a supervised model on labeled logs, for use with `analyze --model`."""
    from loglens.detection.benchmark import cross_validate_supervised, load_labeled, train_and_save

    console.print(
        f"\n[bold cyan][LogLens][/bold cyan] Training on: "
        f"[yellow]{dataset}[/yellow] [dim](format={fmt})[/dim]"
    )

    entries, labels = load_labeled(dataset, fmt=fmt, limit=limit)
    if len(entries) == 0:
        console.print("[bold red]No entries loaded — check the path and --format.[/bold red]")
        raise typer.Exit(code=1)

    n_pos = int(labels.sum())
    console.print(
        f"[bold cyan][LogLens][/bold cyan] Loaded [bold]{len(entries):,}[/bold] entries, "
        f"[bold red]{n_pos:,}[/bold red] labeled anomalies"
    )
    if n_pos == 0 or n_pos == len(entries):
        console.print("[bold red]Need both normal and anomalous lines to train.[/bold red]")
        raise typer.Exit(code=1)

    if not no_cv:
        with console.status("[cyan]Cross-validating (5-fold)...[/cyan]"):
            cv = cast(
                "dict[str, Any]",
                cross_validate_supervised(entries, labels, n_splits=5, model="rf"),
            )
        f1, pr, rc = cv["f1"], cv["precision"], cv["recall"]
        console.print(
            f"[bold cyan][LogLens][/bold cyan] Cross-validated: "
            f"[bold green]F1 {f1['mean']:.3f} ± {f1['std']:.3f}[/bold green] "
            f"[dim](precision {pr['mean']:.3f}, recall {rc['mean']:.3f})[/dim]"
        )

    with console.status("[cyan]Fitting final model on all data...[/cyan]"):
        train_and_save(entries, labels, out, model="rf")

    console.print(f"[bold green]✓ Model saved →[/bold green] [yellow]{out}[/yellow]")
    console.print(f"[dim]  Use it: loglens analyze --source app.log --model {out}[/dim]")


@app.command()
def bench(
    source: str = typer.Argument(..., help="Log file to benchmark against"),
    modes: str = typer.Option("fast,turbo", "--modes", help="Comma-separated: fast,deep,turbo"),
    workers: int = typer.Option(4, "--workers"),
    out: str = typer.Option(None, "--out", help="Write markdown results to this file"),
):
    """Measure processing speed (throughput) across modes on a log file."""
    _load()
    mode_list = [m.strip() for m in modes.split(",") if m.strip()]
    console.print(
        f"\n[bold cyan][LogLens][/bold cyan] Benchmarking [yellow]{source}[/yellow] — modes: {mode_list}"
    )
    results = bench_file(source, mode_list, workers=workers)

    table = Table(title="LogLens Speed Benchmark", header_style="bold cyan")
    for col in ["Mode", "Lines", "Time (s)", "Lines/s", "Anomalies", "Peak RAM (MB)"]:
        table.add_column(col, justify="right")
    for r in results:
        table.add_row(
            r.mode,
            f"{r.lines:,}",
            str(r.seconds),
            f"{r.lines_per_s:,}",
            str(r.anomalies),
            str(r.peak_mb),
        )
    console.print(table)

    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(to_markdown(results, source))
        console.print(f"[bold cyan][LogLens][/bold cyan] Results saved: [green]{out}[/green]")


@app.command("bench-suite")
def bench_suite(
    directory: str = typer.Option(
        "testlogs", "--dir", help="Directory containing log files + a labels.json ground truth"
    ),
    mode: str = typer.Option("fast", "--mode", help="Detection mode: fast | deep"),
    seed: int = typer.Option(0, "--seed", help="Seed for reproducible scoring"),
    exclude: str = typer.Option(
        "", "--exclude", help="Comma-separated filenames to skip (e.g. big.log)"
    ),
    out: str = typer.Option("", "--out", help="Write a JSON report to this path"),
    md_out: str = typer.Option("", "--md", help="Write a markdown report to this path"),
    min_f1: float = typer.Option(
        None, "--min-f1", help="Exit non-zero (code 1) if micro-F1 is below this — a CI gate"
    ),
    window: int = typer.Option(
        100, "--window", help="Window size (lines) for window-level F1 — the BGL/HDFS standard"
    ),
    supervised: bool = typer.Option(
        False, "--supervised", help="Also benchmark the supervised head (5-fold CV RandomForest)"
    ),
    as_json: bool = typer.Option(False, "--json", help="Print the full JSON report to stdout"),
):
    """Score detection accuracy + throughput over a labeled suite (LogLens Bench)."""
    _load()
    _seed_everything(seed)
    # Unconditional: reset the shared console so a prior JSON run can't silence this one.
    console.quiet = as_json

    from loglens.application.suite_bench import run_suite, to_markdown

    try:
        report = run_suite(
            directory,
            mode=mode,
            seed=seed,
            exclude=[e.strip() for e in exclude.split(",") if e.strip()],
            window=window,
            supervised=supervised,
        )
    except FileNotFoundError as exc:
        console.print(f"[bold red][LogLens][/bold red] {exc}")
        raise typer.Exit(code=1) from None

    if not report.files:
        console.print(f"[bold red][LogLens][/bold red] No labeled files found in {directory!r}.")
        raise typer.Exit(code=1)

    if as_json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        table = Table(title=f"LogLens Bench — {directory}", header_style="bold cyan")
        cols = ["File", "Lines", "Lbl", "Line F1", "Win F1", "Win P", "Tmpl F1"]
        if supervised:
            cols.append("Sup F1")
        cols += ["Compress", "Lines/s"]
        for col in cols:
            table.add_column(col, justify="right")
        for fm in report.files:
            row = [
                fm.name,
                f"{fm.lines:,}",
                str(fm.labeled),
                f"{fm.f1:.3f}",
                f"{fm.window_f1:.3f}",
                f"{fm.window_precision:.3f}",
                f"{fm.template_f1:.3f}",
            ]
            if supervised:
                row.append("—" if fm.sup_f1 is None else f"{fm.sup_f1:.3f}")
            row += [f"{fm.compression:.1f}×", f"{fm.lines_per_sec:,.0f}"]
            table.add_row(*row)
        console.print(table)
        m, ma, tot = report.micro, report.macro, report.totals
        console.print(
            f"\n[bold cyan][LogLens][/bold cyan] "
            f"[bold green]Window F1 {ma.get('window_f1', 0):.3f}[/bold green] "
            f"(P {ma.get('window_precision', 0):.3f} R {ma.get('window_recall', 0):.3f}, "
            f"win={window} lines) · Template F1 {ma.get('template_f1', 0):.3f} · "
            f"Line micro-F1 {m.get('f1', 0):.3f}"
        )
        if supervised and "supervised_f1" in ma:
            console.print(
                f"[bold cyan][LogLens][/bold cyan] Supervised head (5-fold CV): "
                f"[bold green]F1 {ma['supervised_f1']:.3f}[/bold green] "
                f"(P {ma['supervised_precision']:.3f} R {ma['supervised_recall']:.3f})"
            )
        console.print(
            f"[dim][LogLens] {tot.get('lines', 0):,} lines @ "
            f"{tot.get('lines_per_sec', 0):,.0f} lines/s[/dim]"
        )

    if out:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(report.to_dict(), fh, indent=2)
        console.print(f"[bold cyan][LogLens][/bold cyan] JSON report → [green]{out}[/green]")
    if md_out:
        with open(md_out, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(report))
        console.print(f"[bold cyan][LogLens][/bold cyan] Markdown report → [green]{md_out}[/green]")

    if min_f1 is not None and report.micro.get("f1", 0.0) < min_f1:
        console.print(
            f"[bold red]✗ FAIL: micro-F1 {report.micro.get('f1', 0):.3f} < {min_f1:.3f}[/bold red]"
        )
        raise typer.Exit(code=1)


@app.command("bench-fetch")
def bench_fetch(
    system: str = typer.Option(..., "--system", help="Dataset: bgl | hdfs"),
    out: str = typer.Option("benchdata", "--out", help="Output directory (log + labels.json)"),
    sample: bool = typer.Option(
        False, "--sample", help="BGL only: download the 2k labeled sample from GitHub"
    ),
    src: str = typer.Option(
        "", "--from", help="Path to a full local dataset log (BGL.log or HDFS.log from Zenodo)"
    ),
    labels: str = typer.Option(
        "", "--labels", help="HDFS only: path to anomaly_label.csv (block → Normal/Anomaly)"
    ),
    max_lines: int = typer.Option(0, "--max-lines", help="Cap lines converted (0 = all)"),
):
    """Fetch/convert a LogHub dataset into a bench suite, then run `bench-suite --dir`."""
    _load()
    sysname = system.strip().lower()
    cap = max_lines or None

    from loglens.application import loghub

    try:
        if sysname == "bgl":
            if sample:
                console.print("[bold cyan][LogLens][/bold cyan] Downloading BGL 2k sample…")
                name, total, anom = loghub.fetch_bgl_sample(out)
            elif src:
                name, total, anom = loghub.convert_bgl(src, out, max_lines=cap)
            else:
                console.print(
                    "[bold red][LogLens][/bold red] BGL needs --sample or --from <BGL.log>"
                )
                raise typer.Exit(code=1)
        elif sysname == "hdfs":
            if not src or not labels:
                console.print(
                    "[bold red][LogLens][/bold red] HDFS needs --from <HDFS.log> and "
                    "--labels <anomaly_label.csv>"
                )
                raise typer.Exit(code=1)
            name, total, anom = loghub.convert_hdfs(src, labels, out, max_lines=cap)
        else:
            console.print(f"[bold red][LogLens][/bold red] Unknown system {system!r} (bgl | hdfs)")
            raise typer.Exit(code=1)
    except FileNotFoundError as exc:
        console.print(f"[bold red][LogLens][/bold red] {exc}")
        raise typer.Exit(code=1) from None
    except OSError as exc:
        console.print(f"[bold red][LogLens][/bold red] download/convert failed: {exc}")
        raise typer.Exit(code=1) from None

    console.print(
        f"[bold green]✓[/bold green] Wrote [yellow]{out}/{name}[/yellow] — "
        f"[bold]{total:,}[/bold] lines, [bold red]{anom:,}[/bold red] labeled anomalies"
    )
    console.print(f"[dim]  Now run: loglens bench-suite --dir {out}[/dim]")


@app.command()
def watch(
    cmd: str = typer.Argument(..., help='Command to run and watch, e.g. "docker logs -f my-api"'),
    window: int = typer.Option(500, "--window", help="Rolling window size (entries)"),
    mode: str = typer.Option("fast", "--mode", help="fast or deep"),
    sensitivity: str = typer.Option("normal", "--sensitivity", help="low, normal, or high"),
    threshold: float = typer.Option(None, "--threshold", help="Explicit flag threshold"),
    quiet: bool = typer.Option(False, "--quiet", help="Only print anomalies, no status line"),
    rca: bool = typer.Option(
        False, "--rca", help="After stopping, run AI root-cause analysis on everything caught"
    ),
    rca_out: str = typer.Option(None, "--rca-out", help="Also save the RCA as a markdown file"),
    html_report: str = typer.Option(
        None,
        "--html-report",
        help="After stopping, write a shareable HTML dashboard of the session",
    ),
):
    """Watch a live command's output and flag anomalies in real time."""
    _load()

    det = LiveDetector(window=window, mode=mode, sensitivity=sensitivity, threshold=threshold)
    style = {
        "EMERGENCY": "bold white on red",
        "FATAL": "bold red",
        "CRITICAL": "red",
        "ERROR": "yellow",
        "WARN": "dark_orange",
    }

    def show(a):
        s = style.get(a.level.upper(), "cyan")
        svc = f" [magenta]{a.service}[/magenta]" if a.service not in ("", "unknown") else ""
        console.print(
            f"[dim]{a.timestamp or '—'}[/dim] [{s}]\\[{a.level}][/{s}]{svc} "
            f"[bold]{a.score:.2f}[/bold] {a.message}"
        )
        if a.reasons:
            console.print(f"          [dim]{'; '.join(a.reasons[:3])}[/dim]")

    async def _watch():
        reader = AsyncCommandReader(cmd)
        if not quiet:
            console.print(
                f"[bold cyan][LogLens][/bold cyan] watching: [bold]{cmd}[/bold] "
                f"[dim](window={window}, mode={mode}, Ctrl-C to stop)[/dim]"
            )
        n = 0
        async for line in reader:
            n += 1
            for a in det.feed(line):
                show(a)
            if not quiet and n % 500 == 0:
                s = det.summary()
                console.print(
                    f"[dim]… {s['entries']:,} lines, {s['anomalies']} anomalies so far[/dim]"
                )

    try:
        asyncio.run(_watch())
    except KeyboardInterrupt:
        pass
    except CommandError as exc:
        console.print(f"[bold red][LogLens][/bold red] {exc}")
        raise typer.Exit(code=1) from None

    for a in det.flush():
        show(a)
    s = cast("dict[str, Any]", det.summary())
    lvl = (
        ", ".join(f"{k}: {v}" for k, v in sorted(s["by_level"].items(), key=lambda kv: -kv[1]))
        or "none"
    )
    console.print(
        Panel(
            f"lines analyzed: [bold]{s['entries']:,}[/bold]\n"
            f"anomalies:      [bold]{s['anomalies']}[/bold]  ({lvl})\n"
            f"incident mode:  {'[bold red]YES[/bold red]' if s['incident'] else 'no'}",
            title="[bold cyan]WATCH SUMMARY[/bold cyan]",
            border_style="cyan",
        )
    )

    rca_result = None
    if rca or rca_out:
        try:
            console.print("[bold cyan][LogLens][/bold cyan] running AI root-cause analysis…")
            rca_result = det.rca(source_name=cmd)
            console.print(
                Panel(
                    Markdown(rca_result.report),
                    title=f"🧠 AI Root-Cause Analysis ({rca_result.provider} / {rca_result.model})",
                    border_style="cyan",
                )
            )
            if rca_out:
                save_report(rca_result, rca_out, source_name=cmd)
                console.print(
                    f"[bold cyan][LogLens][/bold cyan] RCA saved to [bold]{rca_out}[/bold]"
                )
        except LLMError as exc:
            console.print(f"[bold red][LogLens][/bold red] RCA failed: {exc}")
            console.print(
                "[dim]Set LOGLENS_LLM_PROVIDER / LOGLENS_LLM_MODEL / "
                "LOGLENS_LLM_API_KEY (see `loglens analyze --help`).[/dim]"
            )

    if html_report:
        det.save_html(html_report, rca=rca_result, source_name=cmd)
        console.print(
            f"[bold cyan][LogLens][/bold cyan] HTML report saved to [bold]{html_report}[/bold]"
        )


# --------------------------------------------------------------------------- #
# Daemon: a resident warm process that keeps scikit-learn imported so each
# `loglens analyze` is a sub-100 ms round-trip instead of paying ~1.7 s of
# import cost every run. See loglens.application.daemon for the transport.
# --------------------------------------------------------------------------- #

daemon_app = typer.Typer(
    name="daemon",
    help="Manage the resident warm process (keeps LogLens fast between runs).",
    add_completion=False,
)
app.add_typer(daemon_app, name="daemon")


@daemon_app.command("start")
def daemon_start(
    foreground: bool = typer.Option(
        False,
        "--foreground",
        "-f",
        help="Run the daemon in this terminal (blocks). "
        "Without this, it's started detached in the background.",
    ),
    idle_timeout: int = typer.Option(
        1800, "--idle-timeout", help="Shut down after this many seconds with no requests."
    ),
):
    """Start the LogLens daemon."""
    if foreground:
        from loglens.interface.daemon_server import serve

        raise typer.Exit(code=serve(idle_timeout=float(idle_timeout)))

    from loglens.application import daemon as d

    if d.is_running():
        st = d.status() or {}
        console.print(
            f"[bold cyan][LogLens][/bold cyan] daemon already running "
            f"(pid [bold]{st.get('pid', '?')}[/bold], v{st.get('version', '?')})."
        )
        return
    console.print("[bold cyan][LogLens][/bold cyan] starting daemon…")
    if d.ensure_running(spawn=True):
        st = d.status() or {}
        console.print(
            f"[bold green][LogLens][/bold green] daemon ready "
            f"(pid [bold]{st.get('pid', '?')}[/bold], {st.get('transport', '?')}). "
            "Your next analyze will be instant."
        )
    else:
        console.print(
            "[bold red][LogLens][/bold red] daemon failed to start; "
            "commands will still work (they'll just run in-process)."
        )
        raise typer.Exit(code=1)


@daemon_app.command("stop")
def daemon_stop():
    """Stop the LogLens daemon."""
    from loglens.application import daemon as d

    if d.stop():
        console.print("[bold cyan][LogLens][/bold cyan] daemon stopped.")
    else:
        console.print("[dim][LogLens] no daemon was running.[/dim]")


@daemon_app.command("status")
def daemon_status():
    """Show whether the LogLens daemon is running."""
    import time as _time

    from loglens.application import daemon as d

    st = d.status()
    if not st:
        console.print("[dim][LogLens] daemon: [bold]not running[/bold].[/dim]")
        raise typer.Exit(code=1)
    uptime = int(_time.time() - float(st.get("started", _time.time())))
    console.print(
        f"[bold green][LogLens][/bold green] daemon: [bold]running[/bold]  "
        f"pid [bold]{st.get('pid', '?')}[/bold] · v{st.get('version', '?')} · "
        f"{st.get('transport', '?')} · up {uptime}s"
    )


@daemon_app.command("restart")
def daemon_restart():
    """Restart the LogLens daemon (picks up a new version)."""
    from loglens.application import daemon as d

    d.stop()
    if d.ensure_running(spawn=True):
        console.print("[bold green][LogLens][/bold green] daemon restarted.")
    else:
        console.print("[bold red][LogLens][/bold red] daemon failed to restart.")
        raise typer.Exit(code=1)


# Commands worth serving from the warm daemon (heavy import cost to amortize).
_DAEMON_COMMANDS = {"analyze"}


def _daemon_enabled() -> bool:
    """Whether to route eligible commands through the daemon.

    Off by default for `pip` installs (no surprises); on by default for installed
    native binaries (``sys.frozen``), where "install and it's just fast" is the
    whole point. ``LOGLENS_DAEMON=1|0`` forces it either way.
    """
    v = os.environ.get("LOGLENS_DAEMON", "").strip().lower()
    if v in ("0", "off", "false", "no"):
        return False
    if v in ("1", "on", "true", "yes"):
        return True
    return bool(getattr(sys, "frozen", False))


def _should_forward(argv: list[str]) -> bool:
    if not argv or not _daemon_enabled():
        return False
    if any(tok in ("--help", "-h", "--version", "-V") for tok in argv):
        return False
    for tok in argv:  # first positional is the subcommand
        if not tok.startswith("-"):
            return tok in _DAEMON_COMMANDS
    return False


def main() -> None:
    argv = sys.argv[1:]
    if _should_forward(argv):
        try:
            from loglens.application import daemon as d

            code = d.run_via_daemon(argv, spawn=True)
        except Exception:  # noqa: BLE001 — any daemon issue -> run locally
            code = None
        if code is not None:
            raise SystemExit(code)
    app()


if __name__ == "__main__":
    main()
