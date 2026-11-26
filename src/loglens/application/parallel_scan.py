from __future__ import annotations

import math
import os
import time
from typing import Any

from loglens.infrastructure.workerpool import TaskError, run_pool

_THREAD_VARS = (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
)


def _analyze_slice(payload: dict[str, Any]) -> dict[str, Any]:
    from loglens.application.api import analyze_entries
    from loglens.application.results_store import canonical_bucket, hour_bucket, to_epoch
    from loglens.detection.parser import parse_line
    from loglens.detection.run import RunConfig
    from loglens.detection.templates import template_key

    path = payload["path"]
    start, end = payload["start"], payload["end"]
    fmt, layout = payload["fmt"], payload["layout"]

    t0 = time.monotonic()
    entries = []
    with open(path, "rb") as fh:
        fh.seek(start)
        pos = start
        for raw in fh:
            pos += len(raw)
            s = raw.decode("utf-8", "replace").rstrip("\r\n")
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

    # Supervised head (optional): re-decide the flagged set per slice using the
    # trained model. Per-line, local features only — safe to run on a slice.
    model_path = payload.get("model") or ""
    if model_path:
        from loglens.application.api import apply_supervised_head

        res = apply_supervised_head(
            res, model_path, is_default=bool(payload.get("model_is_default"))
        )

    hist: dict[str, dict[int, int]] = {}
    min_ep: float | None = None
    max_ep: float | None = None
    for e in entries:
        ep = to_epoch(e.timestamp or "")
        if ep is None:
            continue
        if min_ep is None or ep < min_ep:
            min_ep = ep
        if max_ep is None or ep > max_ep:
            max_ep = ep
        b = canonical_bucket(e.level)
        hb = hour_bucket(ep)
        slot = hist.setdefault(b, {})
        slot[hb] = slot.get(hb, 0) + 1

    fams: dict[tuple[str, str], dict[str, Any]] = {}
    top_lines: list[dict[str, Any]] = []
    for a in res.anomalies:
        lvl = a.level.upper()
        key = (lvl, template_key(a.message or ""))
        ts = a.timestamp or ""
        ep = to_epoch(ts)
        f = fams.get(key)
        if f is None:
            fams[key] = {
                "level": lvl,
                "template": key[1],
                "count": 1,
                "score": float(a.score),
                "sample": a.message,
                "services": {a.service},
                "first_ts": ts,
                "last_ts": ts,
                "first_epoch": ep,
                "last_epoch": ep,
            }
        else:
            f["count"] += 1
            if float(a.score) > f["score"]:
                f["score"] = float(a.score)
                f["sample"] = a.message
            f["services"].add(a.service)
            if ts and (not f["first_ts"] or ts < f["first_ts"]):
                f["first_ts"] = ts
            if ts and ts > f["last_ts"]:
                f["last_ts"] = ts
            if ep is not None and (f["first_epoch"] is None or ep < f["first_epoch"]):
                f["first_epoch"] = ep
            if ep is not None and (f["last_epoch"] is None or ep > f["last_epoch"]):
                f["last_epoch"] = ep
    for a in sorted(res.anomalies, key=lambda x: -float(x.score))[:200]:
        top_lines.append(
            {
                "level": a.level.upper(),
                "score": float(a.score),
                "message": a.message,
                "service": a.service,
                "timestamp": a.timestamp or "",
            }
        )

    fam_list = []
    for f in fams.values():
        f["services"] = sorted(f["services"])[:5]
        fam_list.append(f)
    hist_out = {lvl: {str(hb): c for hb, c in slots.items()} for lvl, slots in hist.items()}
    return {
        "families": fam_list,
        "top_lines": top_lines,
        "lines": res.total,
        "by_level": res.by_level(),
        "incident": res.incident,
        "level_time_hist": hist_out,
        "min_epoch": min_ep,
        "max_epoch": max_ep,
        "elapsed": round(time.monotonic() - t0, 3),
    }


# Each slice runs the full detector on its own, so the slice size decides what
# "rare" means. It must not depend on the worker count, or the same file gives
# different answers on different machines. Workers only set how many slices
# run at once.
DEFAULT_SLICE_LINES = 25_000


def plan_slice_count(size_bytes: int, avg_line_bytes: float, slice_lines: int) -> int:
    """Number of slices for a file, from its size alone (never from workers)."""
    if size_bytes <= 0 or avg_line_bytes <= 0 or slice_lines <= 0:
        return 1
    est_lines = size_bytes / avg_line_bytes
    return max(1, math.ceil(est_lines / slice_lines))


def parallel_analyze_file(
    path: str,
    *,
    mode: str = "fast",
    sensitivity: str = "normal",
    threshold: float | None = None,
    workers: int,
    slice_lines: int = DEFAULT_SLICE_LINES,
    fmt: str | None = None,
    limit: int = 20,
    model: str | None = None,
    model_is_default: bool = False,
    on_progress=None,
    on_event=None,
) -> dict[str, Any]:
    """Analyse ``path`` in parallel slices; merge into families + top lines.

    The file is cut into slices of about ``slice_lines`` lines each, estimated
    from the average line length of the first lines. The slice layout depends
    only on the file, so the result is the same for any ``workers`` value.
    """
    from loglens.detection.parser import sniff_format
    from loglens.detection.textio import as_plain_utf8
    from loglens.detection.turbo import split_chunks

    display_path = path
    path = as_plain_utf8(path)  # byte-range slicing needs plain UTF-8

    for v in _THREAD_VARS:
        os.environ[v] = "1"

    head: list[str] = []
    head_bytes = 0
    with open(path, "rb") as fh:
        for raw_line in fh:
            head_bytes += len(raw_line)
            head.append(raw_line.decode("utf-8", "replace").rstrip("\r\n"))
            if len(head) >= 200:
                break
    detected, _conf, layout = sniff_format(head)
    fmt = fmt or detected

    avg_line_bytes = head_bytes / len(head) if head else 0.0
    n_slices = plan_slice_count(os.path.getsize(path), avg_line_bytes, slice_lines)
    chunks = split_chunks(path, n_slices)
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
            "model": model or "",
            "model_is_default": model_is_default,
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

    merged: dict[tuple[str, str], dict[str, Any]] = {}
    top_lines: list[dict[str, Any]] = []
    total = 0
    by_level: dict[str, int] = {}
    incident = False
    faults = 0
    level_time_hist: dict[str, dict[str, int]] = {}
    min_epoch: float | None = None
    max_epoch: float | None = None

    def _ep_min(a, b):
        return b if a is None else (a if b is None else min(a, b))

    def _ep_max(a, b):
        return b if a is None else (a if b is None else max(a, b))

    for r in raw:
        if isinstance(r, TaskError):
            faults += 1
            continue
        total += r["lines"]
        incident = incident or r["incident"]
        for k, v in r["by_level"].items():
            count = int(v)
            by_level[k] = by_level.get(k, 0) + count
        top_lines.extend(r["top_lines"])
        min_epoch = _ep_min(min_epoch, r.get("min_epoch"))
        max_epoch = _ep_max(max_epoch, r.get("max_epoch"))
        for lvl, slots in (r.get("level_time_hist") or {}).items():
            dst = level_time_hist.setdefault(lvl, {})
            for hb, c in slots.items():
                dst[hb] = dst.get(hb, 0) + c
        for f in r["families"]:
            key = (f["level"], f["template"])
            m = merged.get(key)
            if m is None:
                merged[key] = {**f, "services": set(f["services"])}
            else:
                m["count"] += f["count"]
                if f["score"] > m["score"]:
                    m["score"] = f["score"]
                    m["sample"] = f["sample"]
                m["services"].update(f["services"])
                if f["first_ts"] and (not m["first_ts"] or f["first_ts"] < m["first_ts"]):
                    m["first_ts"] = f["first_ts"]
                if f["last_ts"] > m["last_ts"]:
                    m["last_ts"] = f["last_ts"]
                m["first_epoch"] = _ep_min(m.get("first_epoch"), f.get("first_epoch"))
                m["last_epoch"] = _ep_max(m.get("last_epoch"), f.get("last_epoch"))

    families = []
    for m in merged.values():
        m["services"] = sorted(m["services"])[:5]
        families.append(m)
    # Deterministic: worst score, then biggest, then stable on level + template.
    families.sort(key=lambda f: (-f["score"], -f["count"], f["level"], f["template"]))
    top_lines.sort(key=lambda a: (-a["score"], a.get("level", ""), a.get("message", "")))

    flagged_lines = sum(f["count"] for f in families)
    return {
        "schema": "loglens.parallel.v2",
        "source": display_path,
        "mode": mode,
        "supervised": bool(model),
        "model": model or "",
        "format": fmt,
        "slices": len(chunks),
        "workers": min(workers, len(chunks)),
        "lines_parsed": total,
        "anomaly_lines": flagged_lines,
        "family_count": len(families),
        "by_level": dict(sorted(by_level.items())),
        "incident": incident,
        "faulted_slices": faults,
        "families": families,
        "top_lines": top_lines[: max(limit, 200)],
        "level_time_hist": level_time_hist,
        "time_span": {
            "first_epoch": min_epoch,
            "last_epoch": max_epoch,
            "first_ts": _epoch_to_str(min_epoch),
            "last_ts": _epoch_to_str(max_epoch),
        },
        "display_limit": limit,
        "approximate": True,
    }


def _epoch_to_str(epoch: float | None) -> str:
    if epoch is None:
        return ""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
