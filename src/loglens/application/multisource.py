from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from loglens.application.loadstats import LoadStats
from loglens.application.scheduler import effective_workers, plan_assignment
from loglens.application.sources import SourceSpec
from loglens.infrastructure.workerpool import TaskError, run_pool


def _analyze_source_task(payload: dict[str, Any]) -> dict[str, Any]:
    from loglens.application.api import analyze
    from loglens.detection.run import RunConfig

    cfg = RunConfig(
        mode=payload.get("mode", "fast"),
        sensitivity=payload.get("sensitivity", "normal"),
        threshold=payload.get("threshold"),
    )
    kind = payload["kind"]
    target = payload["target"]
    call_kw: dict[str, Any] = {"fmt": payload.get("fmt"), "config": cfg}
    if kind == "cmd":
        call_kw["cmd"] = target
    else:
        call_kw["source"] = target
    t0 = time.monotonic()
    res = analyze(**call_kw)
    elapsed = time.monotonic() - t0
    return {
        "id": payload["id"],
        "format": res.format,
        "lines_parsed": res.total,
        "anomalies": [a.to_dict() for a in res.anomalies],
        "by_level": res.by_level(),
        "incident": res.incident,
        "incident_note": res.incident_note,
        "elapsed": elapsed,
    }


@dataclass(slots=True)
class CrossIncident:
    start: float
    end: float
    sources: list[str]
    count: int
    worst_level: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": round(self.start, 3),
            "end": round(self.end, 3),
            "duration_seconds": round(self.end - self.start, 3),
            "sources": self.sources,
            "anomaly_count": self.count,
            "worst_level": self.worst_level,
        }


def correlate(per_source: list[dict[str, Any]], gap_seconds: float = 30.0) -> list[CrossIncident]:
    from loglens.detection.templates import parse_timestamp
    from loglens.domain.severity import get_severity

    events: list[tuple[float, str, str]] = []
    for src in per_source:
        sid = src["id"]
        for a in src["anomalies"]:
            ts = parse_timestamp(a.get("timestamp", "") or "")
            if ts is None:
                continue
            events.append((ts, sid, a.get("level", "INFO")))
    if not events:
        return []
    events.sort(key=lambda e: (e[0], e[1], e[2]))

    out: list[CrossIncident] = []
    win: list[tuple[float, str, str]] = [events[0]]
    for ev in events[1:]:
        if ev[0] - win[-1][0] <= gap_seconds:
            win.append(ev)
        else:
            inc = _window_to_incident(win, get_severity)
            if inc is not None:
                out.append(inc)
            win = [ev]
    inc = _window_to_incident(win, get_severity)
    if inc is not None:
        out.append(inc)
    return out


def _window_to_incident(win, get_severity) -> CrossIncident | None:
    srcs = sorted({s for _t, s, _l in win})
    if len(srcs) < 2:
        return None
    worst = min(win, key=lambda e: get_severity(e[2]))[2]
    return CrossIncident(
        start=win[0][0],
        end=win[-1][0],
        sources=srcs,
        count=len(win),
        worst_level=worst.upper(),
    )


@dataclass(slots=True)
class MultiResult:
    per_source: list[dict[str, Any]]  # sorted by source id
    cross_incidents: list[CrossIncident]
    stats: LoadStats
    workers: int

    @property
    def total_anomalies(self) -> int:
        return sum(len(s["anomalies"]) for s in self.per_source)

    @property
    def total_lines(self) -> int:
        return sum(s["lines_parsed"] for s in self.per_source)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "loglens.multi.v1",
            "workers": self.workers,
            "sources_analyzed": len(self.per_source),
            "total_lines": self.total_lines,
            "total_anomalies": self.total_anomalies,
            "cross_incidents": [c.to_dict() for c in self.cross_incidents],
            "sources": self.per_source,
            "load": self.stats.to_dict(),
        }


def analyze_sources(
    specs: list[SourceSpec],
    *,
    mode: str = "fast",
    sensitivity: str = "normal",
    threshold: float | None = None,
    workers: int | None = None,
    gap_seconds: float = 30.0,
    on_event=None,
) -> MultiResult:
    specs = list(specs)
    stats = LoadStats()
    if not specs:
        return MultiResult(per_source=[], cross_incidents=[], stats=stats, workers=0)

    n_workers = effective_workers(len(specs), requested=workers)
    assignment = plan_assignment(specs, n_workers)

    payloads = [
        {
            "id": s.id,
            "kind": s.kind,
            "target": s.target,
            "fmt": s.fmt,
            "mode": mode,
            "sensitivity": sensitivity,
            "threshold": threshold,
        }
        for s in specs
    ]

    for s in specs:
        st = stats.get(s.id)
        st.worker = assignment.worker_of.get(s.id)
        st.start()

    raw = run_pool(_analyze_source_task, payloads, n_workers, on_event=on_event)

    per_source: list[dict[str, Any]] = []
    by_id = {s.id: s for s in specs}
    for i, result in enumerate(raw):
        spec = specs[i]
        st = stats.get(spec.id)
        if isinstance(result, TaskError):
            st.finish(error=result.message)
            per_source.append(
                {
                    "id": spec.id,
                    "format": None,
                    "lines_parsed": 0,
                    "anomalies": [],
                    "by_level": {},
                    "incident": False,
                    "incident_note": "",
                    "error": result.message,
                }
            )
            continue
        st.lines_parsed = result["lines_parsed"]
        st.lines_in = result["lines_parsed"]
        st.compute_seconds = result.pop("elapsed", None)
        st.finish()
        per_source.append(result)

    per_source.sort(key=lambda r: r["id"])
    _ = by_id

    cross = correlate(per_source, gap_seconds=gap_seconds)
    return MultiResult(
        per_source=per_source,
        cross_incidents=cross,
        stats=stats,
        workers=n_workers,
    )
