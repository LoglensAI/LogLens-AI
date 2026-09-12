import asyncio
import functools

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

from loglens.models import LogEntry
from loglens.pipeline.ingestion import stream_lines, AsyncCommandReader, CommandError
from loglens.pipeline.parser import detect_format, parse_line
from loglens.pipeline.worker import run_worker_pool
from loglens.output.terminal import LiveProgress
from loglens.output.html_report import render_html_report
from loglens.pipeline.detector import detect_anomalies, cluster_summary, DetectorConfig
from loglens.pipeline.benchmark import run_benchmark
from loglens.pipeline.speedbench import bench_file, to_markdown
from loglens.pipeline.turbo import scan_file as turbo_scan
from loglens.pipeline.templates import TemplateRegistry
from loglens.pipeline.grouping import group_anomalies, group_summaries
from loglens.pipeline.embeddings import EmbeddingEngine
from loglens.llm import LLMConfig, LLMError, run_rca, run_ask, save_report
from loglens.live import LiveDetector
from loglens import __version__

try:
    from loglens.pipeline.deep_embeddings import DeepEmbeddingEngine
except ImportError:
    DeepEmbeddingEngine = None

app = typer.Typer(
    name="loglens",
    help="LogLens AI Intelligent log analysis and anomaly detection",
    add_completion=False,
)

console = Console()

LEVEL_WEIGHT = {"EMERGENCY": 6, "FATAL": 5, "CRITICAL": 5, "ERROR": 4,
                "WARN": 3, "WARNING": 3, "INFO": 1, "DEBUG": 0}
CATEGORY_ORDER = ["EMERGENCY", "FATAL", "CRITICAL", "ERROR", "WARN",
                  "WARNING", "NOTICE", "INFO", "DEBUG"]
CATEGORY_COLOR = {
    "EMERGENCY": "bold red", "FATAL": "bold red", "CRITICAL": "bold red",
    "ERROR": "red", "WARN": "bold yellow", "WARNING": "bold yellow",
    "NOTICE": "yellow", "INFO": "dim", "DEBUG": "dim",
}
INFO_KEYWORDS = {"error", "fail", "timeout", "refused", "crash", "panic", "oom", "kill"}


def _level_color(lvl: str) -> str:
    lvl = lvl.upper()
    if lvl in ("ERROR", "CRITICAL", "FATAL", "EMERGENCY"):
        return "bold red"
    elif lvl in ("WARN", "WARNING"):
        return "bold yellow"
    return "dim"


def _severity(a) -> int:
    return LEVEL_WEIGHT.get(a.level.upper(), 2)


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
        console.print(Panel(
            Markdown(result.report),
            title=f"🧠 AI Root-Cause Analysis ({result.provider} / {result.model})",
            border_style="cyan",
        ))
        u = result.usage
        console.print(
            f"[dim]Privacy: sent {result.anomalies_sent} anomaly summaries to the LLM — "
            f"never the full log file. "
            f"Tokens: {u.total_tokens:,} (prompt {u.prompt_tokens:,} / completion {u.completion_tokens:,})[/dim]"
        )
        if rca_out:
            save_report(result, rca_out, source_name=source)
            console.print(f"[bold cyan][LogLens][/bold cyan] RCA report saved: [green]{rca_out}[/green]")
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
        {"provider": rca_result.provider, "model": rca_result.model,
         "tokens": rca_result.usage.total_tokens}
        if rca_result else None
    )
    html_doc = render_html_report(
        source=source, total_lines=total_lines, anomalies=anomalies,
        level_counts=level_counts, rca_markdown=rca_md, rca_meta=rca_meta,
        scores=scores,
    )
    with open(html_out, "w", encoding="utf-8") as f:
        f.write(html_doc)
    console.print(f"[bold cyan][LogLens][/bold cyan] HTML report saved: [green]{html_out}[/green]")


@app.command()
def version():
    console.print(f"[bold cyan]LogLens AI[/bold cyan] version [bold]{__version__}[/bold]")


@app.command()
def hello():
    console.print("[bold green] LogLens is alive![/bold green] Let's analyze some logs.")


@app.command()
def analyze(
    source: str = typer.Option(..., help="Log source: file path, URL, or stdin"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Stop after ingestion, show stats only"),
    verbose: bool = typer.Option(False, "--verbose", help="Show sample parsed entry"),
    workers: int = typer.Option(4, "--workers", help="Number of parallel workers"),
    deep: bool = typer.Option(False, "--deep", help="Use neural embeddings (accurate, slower)"),
    limit: int = typer.Option(20, "--limit", help="Max anomaly families to display (default: 20)"),
    sort_by: str = typer.Option("severity", "--sort-by", help="Sort anomalies by: severity | time | service"),
    turbo: bool = typer.Option(False, "--turbo", help="Fast multiprocess scan for huge files (byte-range + template dedup, skips embeddings)"),
    explain: int = typer.Option(0, "--explain", help="Show top-N scored entries (flagged or not) with score and reasons — for debugging near-misses"),
    model: str = typer.Option("", "--model", help="Path to a trained model from `loglens train` — uses the supervised head instead of the raw threshold"),
    rca: bool = typer.Option(False, "--rca", help="AI root-cause analysis of detected anomalies (requires LLM key: openai | azure | groq)"),
    provider: str = typer.Option("", "--provider", help="LLM provider: openai | azure | groq (or env LOGLENS_LLM_PROVIDER)"),
    llm_model: str = typer.Option("", "--llm-model", help="LLM model / Azure deployment name (or env LOGLENS_LLM_MODEL)"),
    api_key: str = typer.Option("", "--api-key", help="LLM API key (prefer env LOGLENS_LLM_API_KEY)"),
    rca_out: str = typer.Option("", "--rca-out", help="Save the RCA report to a markdown file (e.g. rca_report.md)"),
    html_out: str = typer.Option("", "--html", help="Save a standalone HTML report (e.g. report.html). Includes RCA if --rca is set."),
):
    async def _run():

        if turbo:
            console.print(f"\n[bold cyan][LogLens][/bold cyan] Source: [yellow]{source}[/yellow]")
            console.print("[bold cyan][LogLens][/bold cyan] Mode: [bold magenta]⚡ Turbo (parallel scan)[/bold magenta]")
            loop = asyncio.get_event_loop()
            res = await loop.run_in_executor(
                None,
                functools.partial(turbo_scan, source, workers=(workers if workers else None)),
            )
            console.print(f"[bold cyan][LogLens][/bold cyan] Workers: [bold]{res.workers}[/bold]")
            console.print(f"[bold cyan][LogLens][/bold cyan] Parsed lines: [bold]{res.parsed_lines:,}[/bold]")
            console.print(
                f"[bold cyan][LogLens][/bold cyan] Unique templates: [bold]{len(res.templates):,}[/bold]  "
                f"(redundancy [green]{res.redundancy() * 100:.1f}%[/green])"
            )
            anomalies = res.anomalies()
            severe = sum(1 for a in anomalies if a.level.upper() in ("EMERGENCY", "FATAL", "CRITICAL", "ERROR"))
            incident_flag = ""
            if res.parsed_lines and severe / res.parsed_lines >= 0.30:
                incident_flag = " [bold red blink]⚠ INCIDENT[/bold red blink]"
            console.print(
                f"[bold cyan][LogLens][/bold cyan] Anomalies: "
                f"[bold red]{len(anomalies):,}[/bold red] 🚨{incident_flag}"
            )

            display = anomalies[:limit]
            if display:
                console.print()
                console.print(Panel(
                    "\n".join(
                        f"[{_level_color(a.level)}] [{a.level}][/{_level_color(a.level)}] "
                        f"[yellow]{a.service}[/yellow] "
                        f"[dim](×{a.count:,}, score {a.score})[/dim] — {a.sample[:110]}"
                        for a in display
                    ),
                    title=f"[bold red]TOP ANOMALIES ({len(anomalies)} total)[/bold red]",
                    border_style="red",
                ))
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
                rca_result = _do_rca(rca_entries, [], [], source, provider, llm_model, api_key, rca_out)
            elif rca:
                console.print("[dim]RCA skipped — no anomalies to analyze.[/dim]")

            if html_out:
                turbo_scores = [float(a.score) for a in anomalies] if anomalies else None
                _write_html(html_out, source, res.parsed_lines, rca_entries, rca_result, scores=turbo_scores)

            return   # turbo done — skip the classic pipeline

        line_count = 0
        fmt = None
        sample_entry = None
        entries = []

        console.print(f"\n[bold cyan][LogLens][/bold cyan] Source: [yellow]{source}[/yellow]")
        async for line in stream_lines(source):
            line_count += 1
            if line_count == 1:
                fmt = detect_format(line)
                console.print(f"[bold cyan][LogLens][/bold cyan] Detected format: [yellow]{fmt}[/yellow]")

            entry = parse_line(line, fmt)
            if entry:
                if sample_entry is None:
                    sample_entry = entry
                entries.append(entry)

        console.print(f"[bold cyan][LogLens][/bold cyan] Lines ingested: [bold]{line_count:,}[/bold]")

        if dry_run:
            console.print("[bold cyan][LogLens][/bold cyan] --dry-run: stopping before processing.")
            return

        if not entries:
            console.print("[bold red]No valid log entries found.[/bold red]")
            return

        if deep:
            console.print("[bold cyan][LogLens][/bold cyan] Mode: [bold magenta] Deep (neural embeddings)[/bold magenta]")
            if DeepEmbeddingEngine is None:
                console.print(
                    "[bold red]Deep mode requires sentence-transformers.[/bold red]\n"
                    "Install with: [yellow]pip install sentence-transformers[/yellow]"
                )
                raise typer.Exit(code=1)
            engine = DeepEmbeddingEngine()
        else:
            console.print("[bold cyan][LogLens][/bold cyan] Mode: [bold green] Fast (TF-IDF embeddings)[/bold green]")
            engine = EmbeddingEngine()

        console.print(f"[bold cyan][LogLens][/bold cyan] Computing embeddings for [bold]{len(entries):,}[/bold] entries...")
        if deep and hasattr(engine, "embed_templates"):
            registry = TemplateRegistry(entries)
            console.print(
                f"[bold cyan][LogLens][/bold cyan] Unique templates: "
                f"[bold]{len(registry):,}[/bold] "
                f"[dim](encoding templates, not lines)[/dim]"
            )
            vectors = engine.embed_templates(entries, registry)
        else:
            vectors = engine.embed(entries)
        console.print(
            f"[bold cyan][LogLens][/bold cyan] Embeddings ready: "
            f"[bold green]shape={vectors.shape}[/bold green]"
        )

        # --- anomaly detection ---
        normal, anomalies, labels = detect_anomalies(entries, vectors)
        summary = cluster_summary(labels)

        # --- supervised override: re-flag using a trained model if provided ---
        if model:
            import numpy as _np
            from loglens.pipeline.benchmark import (SupervisedHead,
                                                    build_feature_matrix)
            try:
                head = SupervisedHead.load(model)
            except Exception as exc:
                console.print(f"[bold red]Could not load model '{model}': {exc}[/bold red]")
                raise typer.Exit(code=1)
            console.print(
                f"[bold cyan][LogLens][/bold cyan] Model:      "
                f"[magenta]{model}[/magenta] [dim](supervised head)[/dim]"
            )
            _scores = _np.array(
                [getattr(e, "anomaly_score", 0.0) for e in entries], dtype=float)
            _preds = head.predict(build_feature_matrix(entries, _scores))
            anomalies = [e for e, p in zip(entries, _preds) if int(p) == 1]

        if explain:
            ranked = sorted(entries,
                            key=lambda e: getattr(e, "anomaly_score", 0.0),
                            reverse=True)[:explain]
            console.print()
            console.print(Panel(
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
            ))

        # Use len(anomalies) — actual score-flagged count, not just noise points
        n_anomalies = len(anomalies)
        incident_flag = ""
        if n_anomalies > 0:
            severe = sum(1 for a in anomalies if a.level.upper() in ("EMERGENCY", "FATAL", "CRITICAL", "ERROR"))
            severe_pct = severe / len(entries)
            if severe_pct >= 0.30:
                incident_flag = " [bold red blink]⚠ INCIDENT[/bold red blink]"

        # --- category-wise breakdown ---
        level_counts: dict = {}
        for a in anomalies:
            lvl = a.level.upper()
            level_counts[lvl] = level_counts.get(lvl, 0) + 1

        console.print(f"[bold cyan][LogLens][/bold cyan] Clusters found: [bold]{summary['clusters']}[/bold]")
        console.print(
            f"[bold cyan][LogLens][/bold cyan] Anomalies detected: "
            f"[bold red]{n_anomalies:,}[/bold red] 🚨{incident_flag}"
        )

        # print breakdown tree
        ordered_levels = [l for l in CATEGORY_ORDER if l in level_counts]
        # also catch any unexpected levels
        for l in level_counts:
            if l not in ordered_levels:
                ordered_levels.append(l)
        for idx, lvl in enumerate(ordered_levels):
            is_last = idx == len(ordered_levels) - 1
            branch = "└──" if is_last else "├──"
            color = CATEGORY_COLOR.get(lvl, "white")
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
            progress.update(processed_count)

        progress.start()

        async def entry_stream():
            for e in entries:
                yield e

        stats = await run_worker_pool(
            entry_stream(),
            process_fn,
            num_workers=workers,
        )

        progress.stop()

        console.print(f"\n[bold cyan][LogLens][/bold cyan] Processed: [bold green]{stats['processed']:,}[/bold green]")
        console.print(f"[bold cyan][LogLens][/bold cyan] Skipped:   [bold red]{stats['skipped']}[/bold red]")

        # --- severity ranking (suppress INFO false positives) ---
        filtered_anomalies = [
            a for a in anomalies
            if a.level.upper() != "INFO" or any(kw in a.message.lower() for kw in INFO_KEYWORDS)
        ]

        # Sort
        if sort_by == "severity":
            filtered_anomalies.sort(key=_severity, reverse=True)
        elif sort_by == "service":
            filtered_anomalies.sort(key=lambda a: a.service)
        # "time" = keep original order

        # --- Phase 1: template grouping (families, ×N) ---
        groups = group_anomalies(filtered_anomalies)

        if groups:
            display = groups[:limit]
            console.print()
            console.print(Panel(
                "\n".join(
                    f"[{_level_color(g.level)}] [{g.level}][/{_level_color(g.level)}] "
                    f"[yellow]{g.service}[/yellow] "
                    f"[dim](×{g.count:,}, score {g.max_score:.2f})[/dim] — {g.sample[:110]}"
                    for g in display
                ),
                title=f"[bold red]ANOMALY FAMILIES ({len(groups)} families, "
                      f"{len(filtered_anomalies)} events)[/bold red]",
                border_style="red",
            ))
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
            rca_input = [
                LogEntry(
                    level=g.level,
                    service=g.service,
                    message=f"{g.sample} (occurred ×{g.count:,}, score {g.max_score:.2f})",
                    raw=g.sample,
                )
                for g in groups
            ]
        if rca:
            if rca_input:
                scores = [g.max_score for g in groups]
                reasons = ["; ".join(g.reasons) for g in groups]
                rca_result = _do_rca(rca_input, scores, reasons, source, provider, llm_model, api_key, rca_out)
            else:
                console.print("[dim]RCA skipped — no anomalies to analyze.[/dim]")

        # --- HTML report (Phase 3: with score distribution) ---
        if html_out:
            entry_scores = [getattr(e, "anomaly_score", 0.0) for e in entries]
            _write_html(html_out, source, len(entries), filtered_anomalies, rca_result,
                        scores=entry_scores)

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
    question: str = typer.Argument(..., help="Free-form question about the log, e.g. \"why did db-service degrade?\""),
    source: str = typer.Option(..., help="Log source: file path"),
    deep: bool = typer.Option(False, "--deep", help="Use neural embeddings for detection"),
    provider: str = typer.Option("", "--provider", help="LLM provider: openai | azure | groq"),
    llm_model: str = typer.Option("", "--llm-model", help="LLM model / Azure deployment name"),
    api_key: str = typer.Option("", "--api-key", help="LLM API key (prefer env LOGLENS_LLM_API_KEY)"),
):

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

        if deep:
            if DeepEmbeddingEngine is None:
                console.print(
                    "[bold red]Deep mode requires sentence-transformers.[/bold red]\n"
                    "Install with: [yellow]pip install sentence-transformers[/yellow]"
                )
                raise typer.Exit(code=1)
            engine = DeepEmbeddingEngine()
            registry = TemplateRegistry(entries)
            vectors = engine.embed_templates(entries, registry)
        else:
            engine = EmbeddingEngine()
            vectors = engine.embed(entries)

        console.print(f"[bold cyan][LogLens][/bold cyan] Detecting anomalies locally on [bold]{len(entries):,}[/bold] entries...")
        normal, anomalies, labels = detect_anomalies(entries, vectors)
        console.print(f"[bold cyan][LogLens][/bold cyan] Anomalies found: [bold red]{len(anomalies):,}[/bold red]")

        try:
            cfg = LLMConfig.from_env(provider=provider, model=llm_model, api_key=api_key)
            console.print(f"[bold cyan][LogLens][/bold cyan] 🤖 Asking [bold]{cfg.provider}[/bold] ([dim]{cfg.model}[/dim])...")
            
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
            result = run_ask(question, ranked, cfg, scores=scores, reasons=reasons, source_name=source)
            console.print()
            console.print(Panel(
                Markdown(result.report),
                title=f"💬 {question[:80]}",
                border_style="cyan",
            ))
            u = result.usage
            console.print(
                f"[dim]Sent {result.anomalies_sent} anomaly summaries. "
                f"Tokens: {u.total_tokens:,} (prompt {u.prompt_tokens:,} / completion {u.completion_tokens:,})[/dim]"
            )
        except LLMError as e:
            console.print(f"[bold red][LogLens][/bold red] Ask failed: {e}")
            _print_llm_config_hint()
            raise typer.Exit(code=1)

    asyncio.run(_run())


@app.command()
def benchmark(
    dataset: str = typer.Argument(..., help="Path to labeled log file"),
    fmt: str = typer.Option("bgl", "--format", help="Label format: bgl | jsonl | labeled"),
    limit: int = typer.Option(None, "--limit", help="Max lines to load (default: all)"),
    grid: bool = typer.Option(False, "--grid", help="Grid-search feature_weight x threshold"),
    supervised: bool = typer.Option(False, "--supervised", help="Train + eval supervised (RandomForest) head"),
    min_f1: float = typer.Option(None, "--min-f1", help="Fail (exit 1) if baseline F1 below this"),
):
    console.print(f"\n[bold cyan][LogLens][/bold cyan] Benchmarking: [yellow]{dataset}[/yellow] "
                  f"([dim]format={fmt}[/dim])")

    with console.status("[cyan]Parsing, embedding, detecting...[/cyan]"):
        out = run_benchmark(dataset, fmt=fmt, limit=limit,
                            do_grid=grid, do_supervised=supervised)

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
    out: str = typer.Option("loglens-model.pkl", "--out", "-o",
                            help="Where to save the trained model"),
    fmt: str = typer.Option("bgl", "--format",
                            help="Label format: bgl | jsonl | labeled"),
    limit: int = typer.Option(None, "--limit", help="Max lines to load (default: all)"),
    no_cv: bool = typer.Option(False, "--no-cv",
                               help="Skip cross-validation (faster, no accuracy estimate)"),
):
    """Train a supervised model on labeled logs, for use with `analyze --model`."""
    from loglens.pipeline.benchmark import (load_labeled, train_and_save,
                                            cross_validate_supervised)

    console.print(f"\n[bold cyan][LogLens][/bold cyan] Training on: "
                  f"[yellow]{dataset}[/yellow] [dim](format={fmt})[/dim]")

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
            cv = cross_validate_supervised(entries, labels, n_splits=5, model="rf")
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
    mode_list = [m.strip() for m in modes.split(",") if m.strip()]
    console.print(f"\n[bold cyan][LogLens][/bold cyan] Benchmarking [yellow]{source}[/yellow] — modes: {mode_list}")
    results = bench_file(source, mode_list, workers=workers)

    table = Table(title="LogLens Speed Benchmark", header_style="bold cyan")
    for col in ["Mode", "Lines", "Time (s)", "Lines/s", "Anomalies", "Peak RAM (MB)"]:
        table.add_column(col, justify="right")
    for r in results:
        table.add_row(r.mode, f"{r.lines:,}", str(r.seconds),
                      f"{r.lines_per_s:,}", str(r.anomalies), str(r.peak_mb))
    console.print(table)

    if out:
        with open(out, "w") as f:
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
    rca: bool = typer.Option(False, "--rca", help="After stopping, run AI root-cause analysis on everything caught"),
    rca_out: str = typer.Option(None, "--rca-out", help="Also save the RCA as a markdown file"),
    html_report: str = typer.Option(None, "--html-report", help="After stopping, write a shareable HTML dashboard of the session"),
):

    det = LiveDetector(window=window, mode=mode, sensitivity=sensitivity,
                       threshold=threshold)
    style = {"EMERGENCY": "bold white on red", "FATAL": "bold red",
             "CRITICAL": "red", "ERROR": "yellow", "WARN": "dark_orange"}

    def show(a):
        s = style.get(a.level.upper(), "cyan")
        svc = f" [magenta]{a.service}[/magenta]" if a.service not in ("", "unknown") else ""
        console.print(
            f"[dim]{a.timestamp or '—'}[/dim] [{s}]\\[{a.level}][/{s}]{svc} "
            f"[bold]{a.score:.2f}[/bold] {a.message}")
        if a.reasons:
            console.print(f"          [dim]{'; '.join(a.reasons[:3])}[/dim]")

    async def _watch():
        reader = AsyncCommandReader(cmd)
        if not quiet:
            console.print(f"[bold cyan][LogLens][/bold cyan] watching: [bold]{cmd}[/bold] "
                          f"[dim](window={window}, mode={mode}, Ctrl-C to stop)[/dim]")
        n = 0
        async for line in reader:
            n += 1
            for a in det.feed(line):
                show(a)
            if not quiet and n % 500 == 0:
                s = det.summary()
                console.print(f"[dim]… {s['entries']:,} lines, "
                              f"{s['anomalies']} anomalies so far[/dim]")

    try:
        asyncio.run(_watch())
    except KeyboardInterrupt:
        pass
    except CommandError as exc:
        console.print(f"[bold red][LogLens][/bold red] {exc}")
        raise typer.Exit(code=1)

    for a in det.flush():
        show(a)
    s = det.summary()
    lvl = ", ".join(f"{k}: {v}" for k, v in sorted(
        s["by_level"].items(), key=lambda kv: -kv[1])) or "none"
    console.print(Panel(
        f"lines analyzed: [bold]{s['entries']:,}[/bold]\n"
        f"anomalies:      [bold]{s['anomalies']}[/bold]  ({lvl})\n"
        f"incident mode:  {'[bold red]YES[/bold red]' if s['incident'] else 'no'}",
        title="[bold cyan]WATCH SUMMARY[/bold cyan]", border_style="cyan"))

    rca_result = None
    if rca or rca_out:
        try:
            console.print("[bold cyan][LogLens][/bold cyan] running AI root-cause analysis…")
            rca_result = det.rca(source_name=cmd)
            console.print(Panel(
                Markdown(rca_result.report),
                title=f"🧠 AI Root-Cause Analysis ({rca_result.provider} / {rca_result.model})",
                border_style="cyan"))
            if rca_out:
                save_report(rca_result, rca_out, source_name=cmd)
                console.print(f"[bold cyan][LogLens][/bold cyan] RCA saved to [bold]{rca_out}[/bold]")
        except LLMError as exc:
            console.print(f"[bold red][LogLens][/bold red] RCA failed: {exc}")
            console.print("[dim]Set LOGLENS_LLM_PROVIDER / LOGLENS_LLM_MODEL / "
                          "LOGLENS_LLM_API_KEY (see `loglens analyze --help`).[/dim]")

    if html_report:
        det.save_html(html_report, rca=rca_result, source_name=cmd)
        console.print(f"[bold cyan][LogLens][/bold cyan] HTML report saved to "
                      f"[bold]{html_report}[/bold]")


if __name__ == "__main__":
    app()