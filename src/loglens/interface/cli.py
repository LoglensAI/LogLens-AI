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
    from loglens.detection.parser import detect_format, parse_line
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
    from loglens.detection.parser import detect_format, parse_line  # noqa: F401
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


def _emit_json(
    source: str,
    mode: str,
    lines_read: int | None,
    lines_parsed: int,
    incident: bool,
    items: list[dict[str, Any]],
) -> None:
    payload = {
        "version": __version__,
        "source": source,
        "mode": mode,
        "lines_read": lines_read,
        "lines_parsed": lines_parsed,
        "incident": incident,
        "anomaly_count": len(items),
        "anomalies": items,
    }
    print(json.dumps(payload, indent=2))


def _apply_fail_on(fail_on: str, items: list[dict[str, Any]]) -> None:
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


@app.command()
def version():
    console.print(f"[bold cyan]LogLens AI[/bold cyan] version [bold]{__version__}[/bold]")


@app.command("help")
def help_command(ctx: typer.Context):
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
        "severity", "--sort-by", help="Sort anomalies by: severity | time | service"
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
):
    _load()
    as_json = output_format.strip().lower() == "json"
    if as_json:
        console.quiet = True

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
            severe = sum(
                1
                for a in anomalies
                if a.level.upper() in ("EMERGENCY", "FATAL", "CRITICAL", "ERROR")
            )
            incident_flag = ""
            if res.parsed_lines and severe / res.parsed_lines >= 0.30:
                incident_flag = " [bold red blink]⚠ INCIDENT[/bold red blink]"
            console.print(
                f"[bold cyan][LogLens][/bold cyan] Anomalies: "
                f"[bold red]{len(anomalies):,}[/bold red] 🚨{incident_flag}"
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

            turbo_items = [
                {
                    "level": a.level,
                    "service": a.service,
                    "score": a.score,
                    "count": a.count,
                    "message": a.sample,
                    "reasons": a.reasons,
                }
                for a in anomalies
            ]
            turbo_incident = bool(res.parsed_lines and severe / res.parsed_lines >= 0.30)
            if as_json:
                _emit_json(source, "turbo", None, res.parsed_lines, turbo_incident, turbo_items)
            _apply_fail_on(fail_on, turbo_items)
            return  # turbo done — skip the classic pipeline

        line_count = 0
        fmt = None
        sample_entry = None
        entries = []

        console.print(f"\n[bold cyan][LogLens][/bold cyan] Source: [yellow]{source}[/yellow]")
        async for line in stream_lines(source):
            line_count += 1
            if line_count == 1:
                fmt = detect_format(line)
                console.print(
                    f"[bold cyan][LogLens][/bold cyan] Detected format: [yellow]{fmt}[/yellow]"
                )

            entry = parse_line(line, fmt)
            if entry:
                if sample_entry is None:
                    sample_entry = entry
                entries.append(entry)

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

        # --- anomaly detection ---
        with console.status(
            "[bold cyan]🔍 Detecting anomalies (clustering + scoring)…[/bold cyan]", spinner="dots"
        ):
            normal, anomalies, labels = detect_anomalies(entries, vectors)
        summary = cluster_summary(labels)

        # --- supervised: explicit model, else bundled default, else unsupervised ---
        model_path = model
        used_default = False
        if not model and not no_model:
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
        if n_anomalies > 0:
            severe = sum(
                1
                for a in anomalies
                if a.level.upper() in ("EMERGENCY", "FATAL", "CRITICAL", "ERROR")
            )
            severe_pct = severe / len(entries)
            if severe_pct >= 0.30:
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

        # Sort
        if sort_by == "severity":
            filtered_anomalies.sort(key=_severity)
        elif sort_by == "service":
            filtered_anomalies.sort(key=lambda a: a.service)
        # "time" = keep original order

        # --- Phase 1: template grouping (families, ×N) ---
        groups = group_anomalies(filtered_anomalies)

        if groups:
            display = groups[:limit]
            console.print()
            blocks = []
            for g in display:
                col = _level_color(g.level)
                head = (
                    f"[{col}][{g.level}][/{col}] [yellow]{g.service}[/yellow] "
                    f"[dim](×{g.count:,}, score {g.max_score:.2f})[/dim]  {g.sample[:100]}"
                )
                why = "; ".join(getattr(g, "reasons", []) or []) or "no signals"
                blocks.append(f"{head}\n   [dim]↳ why: {why}[/dim]")
            console.print(
                Panel(
                    "\n\n".join(blocks),
                    title=f"[bold red]ANOMALY FAMILIES ({len(groups)} families, "
                    f"{len(filtered_anomalies)} events)[/bold red]",
                    border_style="red",
                )
            )
            if len(groups) > limit:
                console.print(
                    f"[dim]... and {len(groups) - limit} more families "
                    f"(use --limit {limit * 2} to see more)[/dim]"
                )
            suppressed = len(anomalies) - len(filtered_anomalies)
            if suppressed:
                console.print(f"[dim]{suppressed} INFO-level false positives suppressed[/dim]")
        else:
            console.print("\n[bold green] No anomalies detected![/bold green]")

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

        classic_items = [
            {
                "level": g.level,
                "service": g.service,
                "score": round(g.max_score, 4),
                "count": g.count,
                "message": g.sample,
                "reasons": list(getattr(g, "reasons", []) or []),
            }
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
    _load()

    async def _run():
        console.print(f"\n[bold cyan][LogLens][/bold cyan] Source: [yellow]{source}[/yellow]")
        entries = []
        fmt = None
        async for line in stream_lines(source):
            if fmt is None:
                fmt = detect_format(line)
            entry = parse_line(line, fmt)
            if entry:
                entries.append(entry)
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
    from loglens.application import daemon as d

    if d.stop():
        console.print("[bold cyan][LogLens][/bold cyan] daemon stopped.")
    else:
        console.print("[dim][LogLens] no daemon was running.[/dim]")


@daemon_app.command("status")
def daemon_status():
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
