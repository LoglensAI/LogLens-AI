from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from loglens.application.reporting import ask_about_anomalies, html_for_anomalies, rca_for_anomalies
from loglens.detection.detector import DetectionResult
from loglens.detection.ingestion import stream_command, stream_lines
from loglens.detection.parser import StreamParser
from loglens.detection.run import RunConfig, run
from loglens.domain.models import Anomaly, LogEntry, _to_anomaly
from loglens.infrastructure.llm import save_report

__all__ = [
    "Anomaly",
    "AnalysisResult",
    "analyze",
    "analyze_async",
    "analyze_entries",
    "apply_supervised_head",
    "rca_for_anomalies",
    "ask_about_anomalies",
    "html_for_anomalies",
]


@dataclass
class AnalysisResult:
    anomalies: list[Anomaly]
    entries: list[LogEntry]
    detection: DetectionResult = field(repr=False)
    incident: bool = False
    incident_note: str = ""
    format: str | None = None

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def groups(self):
        return self.detection.groups

    def by_level(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for a in self.anomalies:
            out[a.level.upper()] = out.get(a.level.upper(), 0) + 1
        return out

    def summary(self) -> dict[str, Any]:
        return {
            "entries": self.total,
            "anomalies": len(self.anomalies),
            "incident": self.incident,
            "by_level": self.by_level(),
            "format": self.format,
        }

    def __len__(self) -> int:
        return len(self.anomalies)

    def __iter__(self):
        return iter(self.anomalies)

    def rca(self, *, provider: str = "", model: str = "", api_key: str = "", config=None):
        return rca_for_anomalies(
            self.anomalies,
            source_name=self.format or "analysis",
            provider=provider,
            model=model,
            api_key=api_key,
            config=config,
        )

    def ask(
        self, question: str, *, provider: str = "", model: str = "", api_key: str = "", config=None
    ):
        return ask_about_anomalies(
            question,
            self.anomalies,
            source_name=self.format or "analysis",
            provider=provider,
            model=model,
            api_key=api_key,
            config=config,
        )

    def save_html(self, path: str, *, rca=None, source_name: str = "") -> str:
        html = html_for_anomalies(
            self.anomalies, total_lines=self.total, source_name=source_name or "analysis", rca=rca
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def save_rca(self, path: str, *, rca=None, **kw) -> str:
        rca = rca or self.rca(**kw)
        save_report(rca, path, source_name="analysis")
        return path


def _wrap(entries: list[LogEntry], det: DetectionResult, fmt: str | None) -> AnalysisResult:
    order = np.argsort(-det.scores, kind="stable")
    anomalies = [
        _to_anomaly(entries[i], det.scores[i], det.reasons[i], int(i))
        for i in order
        if det.flagged[i]
    ]
    return AnalysisResult(
        anomalies=anomalies,
        entries=entries,
        detection=det,
        incident=det.incident_mode,
        incident_note=det.incident_note,
        format=fmt,
    )


def analyze_entries(
    entries,
    config: RunConfig | None = None,
    baseline: dict | None = None,
    fmt: str | None = None,
) -> AnalysisResult:
    entries = list(entries)
    det = run(entries, config or RunConfig(), baseline=baseline)
    return _wrap(entries, det, fmt)


def apply_supervised_head(res: AnalysisResult, model_path: str) -> AnalysisResult:
    from loglens.detection.benchmark import SupervisedHead, build_feature_matrix

    head = SupervisedHead.load(model_path)
    det = res.detection
    entries = res.entries
    scores = np.asarray(det.scores, dtype=float)
    if len(entries) == 0:
        return res
    preds = head.predict(build_feature_matrix(entries, scores))
    order = np.argsort(-scores, kind="stable")
    anomalies = [
        _to_anomaly(entries[i], det.scores[i], det.reasons[i], int(i))
        for i in order
        if int(preds[i]) == 1
    ]
    return AnalysisResult(
        anomalies=anomalies,
        entries=entries,
        detection=det,
        incident=res.incident,
        incident_note=res.incident_note,
        format=res.format,
    )


def _parse(lines: Iterable[str], fmt: str | None):
    parser = StreamParser(fmt=fmt)
    entries = list(parser.parse_all(lines))
    return entries, parser.first_format


def _needs_loop(source: str | None) -> bool:
    return source is not None and (
        source == "stdin" or source.startswith(("http://", "https://", "cmd:"))
    )


def _validate(source, lines, cmd) -> None:
    given = [n for n, v in (("source", source), ("lines", lines), ("cmd", cmd)) if v is not None]
    if len(given) != 1:
        raise ValueError(
            f"analyze() takes exactly one of: source, lines, cmd (got {', '.join(given) or 'none'})"
        )


async def analyze_async(
    source: str | None = None,
    *,
    lines: Iterable[str] | None = None,
    cmd: str | None = None,
    mode: str = "fast",
    sensitivity: str = "normal",
    threshold: float | None = None,
    fmt: str | None = None,
    config: RunConfig | None = None,
    baseline: dict | None = None,
) -> AnalysisResult:
    _validate(source, lines, cmd)
    cfg = config or RunConfig(mode=mode, sensitivity=sensitivity, threshold=threshold)
    if lines is not None:
        entries, detected = _parse(lines, fmt)
    else:
        # _validate guarantees exactly one of source/lines/cmd is set; here
        # lines is None, so if cmd is None then source is not.
        aiter = stream_command(cmd) if cmd is not None else stream_lines(str(source))
        parser = StreamParser(fmt=fmt)
        entries = []
        async for line in aiter:
            e = parser.feed(line)
            if e is not None:
                entries.append(e)
        tail = parser.flush()
        if tail is not None:
            entries.append(tail)
        detected = parser.first_format
    # run() is CPU-bound; keep the event loop responsive
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, lambda: analyze_entries(entries, cfg, baseline, fmt or detected)
    )


def analyze(
    source: str | None = None,
    *,
    lines: Iterable[str] | None = None,
    cmd: str | None = None,
    mode: str = "fast",
    sensitivity: str = "normal",
    threshold: float | None = None,
    fmt: str | None = None,
    config: RunConfig | None = None,
    baseline: dict | None = None,
) -> AnalysisResult:
    _validate(source, lines, cmd)
    cfg = config or RunConfig(mode=mode, sensitivity=sensitivity, threshold=threshold)

    if lines is not None:
        entries, detected = _parse(lines, fmt)
        return analyze_entries(entries, cfg, baseline, fmt or detected)
    if cmd is None and source is not None and not _needs_loop(source):
        with open(source, encoding="utf-8", errors="replace") as f:
            entries, detected = _parse((ln.rstrip("\n") for ln in f), fmt)
        return analyze_entries(entries, cfg, baseline, fmt or detected)

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(
            analyze_async(source=source, cmd=cmd, fmt=fmt, config=cfg, baseline=baseline)
        )
    raise RuntimeError(
        "analyze() with a URL/stdin/cmd source cannot run inside an active "
        "event loop; use `await analyze_async(...)` instead."
    )
