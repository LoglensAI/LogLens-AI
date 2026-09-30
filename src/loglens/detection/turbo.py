from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from loglens.detection.templates import template_key
from loglens.domain.scoring import Signals, threshold_for
from loglens.domain.scoring import score as policy_score

logger = logging.getLogger("loglens.turbo")


def mask_template(msg: str) -> str:
    """Template key for turbo's dedup. Delegates to the canonical masker so the
    turbo path collapses messages the same way as the main pipeline."""
    return template_key(msg) if msg else "<empty>"


def auto_workers(
    file_size: int,
    available_mem: int | None = None,
    cpu: int | None = None,
    mem_per_worker_mb: int = 512,
    max_cap: int = 16,
    safety_frac: float = 0.6,
) -> int:
    cpu = cpu or (os.cpu_count() or 1)
    if available_mem is None:
        try:
            import psutil

            available_mem = psutil.virtual_memory().available
        except (ImportError, AttributeError, OSError):
            # psutil missing or unable to read memory — fall back to a 2 GiB assumption.
            available_mem = 2 * 1024**3
    mem_budget = int(available_mem * safety_frac)
    mem_workers = max(1, mem_budget // (mem_per_worker_mb * 1024**2))
    file_workers = max(1, file_size // (16 * 1024**2))
    return int(max(1, min(cpu, mem_workers, file_workers, max_cap)))


def split_chunks(path: str, n: int) -> list[tuple[int, int]]:
    size = os.path.getsize(path)
    if n <= 1 or size == 0:
        return [(0, size)]
    step = size // n
    bounds = [0]
    with open(path, "rb") as f:
        for i in range(1, n):
            f.seek(i * step)
            f.readline()
            bounds.append(f.tell())
    bounds.append(size)
    return [(bounds[i], bounds[i + 1]) for i in range(len(bounds) - 1) if bounds[i] < bounds[i + 1]]


def _process_range(args) -> dict[tuple[str, str], list]:
    from loglens.detection.parser import detect_format, parse_line

    path, start, end = args
    local: dict[tuple[str, str], list] = {}
    fmt: str | None = None
    with open(path, encoding="utf-8", errors="replace") as f:
        f.seek(start)
        pos = start
        for line in f:
            pos += len(line.encode("utf-8", "replace"))
            stripped = line.rstrip("\n")
            if stripped:
                if fmt is None:
                    fmt = detect_format(stripped)
                e = parse_line(stripped, fmt)
                if e is not None:
                    key = (e.level, mask_template(e.message))
                    slot = local.get(key)
                    if slot is None:
                        local[key] = [1, e.message, e.level, e.service]
                    else:
                        slot[0] += 1
            if pos >= end:
                break
    return local


@dataclass
class Template:
    level: str
    template: str
    count: int
    sample: str
    service: str
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    threshold: float = threshold_for("normal")

    def is_anomaly(self) -> bool:
        return self.score >= self.threshold


@dataclass
class ScanResult:
    total_lines: int
    parsed_lines: int
    templates: list[Template]
    workers: int
    threshold: float = threshold_for("normal")

    def redundancy(self) -> float:
        u = len(self.templates)
        return 0.0 if self.parsed_lines == 0 else 1 - u / self.parsed_lines

    def anomalies(self) -> list[Template]:
        return [t for t in self.templates if t.is_anomaly()]


def score_templates(
    merged: dict[tuple[str, str], list], total: int, sensitivity: str = "normal"
) -> list[Template]:
    if total == 0:
        return []

    threshold = threshold_for(sensitivity)
    # Per-level totals let the policy judge "rare within this level".
    level_totals: dict[str, int] = {}
    for (_level, _tmpl), (count, _sample, lvl, _svc) in merged.items():
        level_totals[lvl] = level_totals.get(lvl, 0) + count

    out: list[Template] = []
    for (_level, tmpl), (count, sample, lvl, svc) in merged.items():
        sig = Signals(
            level=lvl,
            message=sample,
            template_count=count,
            level_total=level_totals.get(lvl, total),
            file_total=total,
        )
        res = policy_score(sig)
        out.append(
            Template(
                level=lvl,
                template=tmpl,
                count=count,
                sample=sample,
                service=svc,
                score=round(res.score, 4),
                reasons=res.reason_texts,
                threshold=threshold,
            )
        )
    out.sort(key=lambda t: (-t.score, t.level, t.service, t.template))
    return out


def scan_file(
    path: str, workers: int | None = None, sensitivity: str = "normal", **auto_kw
) -> ScanResult:
    size = os.path.getsize(path)
    w = workers or auto_workers(size, **auto_kw)
    chunks = split_chunks(path, w)
    w = len(chunks)

    merged: dict[tuple[str, str], list] = {}
    if w == 1:
        merged = _process_range((path, chunks[0][0], chunks[0][1]))
    else:
        try:
            import multiprocessing as mp

            with mp.Pool(w) as pool:
                for local in pool.imap(_process_range, [(path, s, e) for s, e in chunks]):
                    for k, v in local.items():
                        slot = merged.get(k)
                        if slot is None:
                            merged[k] = v
                        else:
                            slot[0] += v[0]
        except Exception as exc:
            # Multiprocessing can fail (spawn issues, pickling, low memory).
            # Fall back to a serial scan so the run still completes.
            logger.warning(
                "parallel scan failed (%s: %s); falling back to serial",
                type(exc).__name__,
                exc,
            )
            merged = {}
            for s, e in chunks:
                for k, v in _process_range((path, s, e)).items():
                    slot = merged.get(k)
                    if slot is None:
                        merged[k] = v
                    else:
                        slot[0] += v[0]

    parsed = sum(v[0] for v in merged.values())
    templates = score_templates(merged, parsed, sensitivity)
    return ScanResult(
        total_lines=parsed,
        parsed_lines=parsed,
        templates=templates,
        workers=w,
        threshold=threshold_for(sensitivity),
    )


def analyze(path: str, workers: int | None = None, **auto_kw) -> dict:
    res = scan_file(path, workers=workers, **auto_kw)
    anomalies = res.anomalies()
    return {
        "file": path,
        "workers": res.workers,
        "parsed_lines": res.parsed_lines,
        "unique_templates": len(res.templates),
        "redundancy": round(res.redundancy(), 4),
        "anomaly_count": len(anomalies),
        "top_anomalies": [
            {
                "score": t.score,
                "level": t.level,
                "count": t.count,
                "service": t.service,
                "sample": t.sample[:200],
            }
            for t in anomalies[:20]
        ],
    }
