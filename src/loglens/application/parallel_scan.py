from __future__ import annotations

import time
from typing import Any

from loglens.infrastructure.workerpool import TaskError, run_pool


def _analyze_slice(payload: dict[str, Any]) -> dict[str, Any]:
    from loglens.application.api import analyze_entries
    from loglens.detection.parser import parse_line
    from loglens.detection.run import RunConfig

    path = payload["path"]
    start = payload["start"]
    end = payload["end"]
    fmt = payload["fmt"]
    layout = payload["layout"]

    t0 = time.monotonic()
    entries = []
    with open(path, encoding="utf-8", errors="replace") as f:
        f.seek(start)
        pos = start
        for line in f:
            pos += len(line.encode("utf-8", "replace"))
            s = line.rstrip("\n")
            if s:
                e = parse_line(s, fmt, layout)
                if e is not None:
                    entries.append(e)
            if pos >= end:
                break

    res = analyze_entries(
        entries,
        RunConfig(
            mode=payload["mode"],
            sensitivity=payload["sensitivity"],
            threshold=payload["threshold"],
        ),
        fmt=fmt,
    )
    return {
        "anomalies": [a.to_dict() for a in res.anomalies],
        "lines": res.total,
        "by_level": res.by_level(),
        "incident": res.incident,
        "elapsed": round(time.monotonic() - t0, 3),
    }


def parallel_analyze_file(
    path: str,
    *,
    mode: str = "fast",
    sensitivity: str = "normal",
    threshold: float | None = None,
    workers: int,
    fmt: str | None = None,
    limit: int = 20,
    on_progress=None,
    on_event=None,
) -> dict[str, Any]:
    from loglens.detection.parser import sniff_format
    from loglens.detection.turbo import split_chunks

    head: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            head.append(line.rstrip("\n"))
            if len(head) >= 200:
                break
    detected, _conf, layout = sniff_format(head)
    fmt = fmt or detected

    chunks = split_chunks(path, max(1, workers))
    payloads = [
        {
            "path": path,
            "start": s,
            "end": e,
            "fmt": fmt,
            "layout": layout,
            "mode": mode,
            "sensitivity": sensitivity,
            "threshold": threshold,
        }
        for s, e in chunks
    ]

    raw = run_pool(
        _analyze_slice,
        payloads,
        max(1, workers),
        on_progress=on_progress,
        on_event=on_event,
    )

    anomalies: list[dict[str, Any]] = []
    total = 0
    by_level: dict[str, int] = {}
    incident = False
    faults = 0
    for r in raw:
        if isinstance(r, TaskError):
            faults += 1
            continue
        anomalies.extend(r["anomalies"])
        total += r["lines"]
        for k, v in r["by_level"].items():
            by_level[k] = by_level.get(k, 0) + v
        incident = incident or r["incident"]

    anomalies.sort(
        key=lambda a: (-float(a.get("score", 0.0)), a.get("level", ""), a.get("message", ""))
    )

    return {
        "schema": "loglens.parallel.v1",
        "source": path,
        "mode": mode,
        "format": fmt,
        "slices": len(chunks),
        "workers": min(workers, len(chunks)),
        "lines_parsed": total,
        "anomaly_count": len(anomalies),
        "by_level": dict(sorted(by_level.items())),
        "incident": incident,
        "faulted_slices": faults,
        "top_anomalies": anomalies[:limit],
        "approximate": True,  # per-slice detection — not identical to whole-file
    }