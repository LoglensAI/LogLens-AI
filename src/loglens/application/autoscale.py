from __future__ import annotations

import os
from dataclasses import dataclass

from loglens.application.scheduler import detect_cores

# Above this estimated line count a single file auto-switches to the fast scan.
DEFAULT_MAX_EXACT_LINES = 500_000
_SAMPLE_BYTES = 262_144


@dataclass(slots=True)
class ScalePlan:
    strategy: str  # "exact" | "scan"
    workers: int  # worker processes the scan should use (1 for exact)
    cores: int  # cores detected on this machine
    reserved: int  # cores deliberately left free for the user
    est_lines: int
    size_bytes: int
    threshold: int  # the max-exact-lines threshold used
    reason: str

    @property
    def parallel(self) -> bool:
        return self.strategy == "scan" and self.workers > 1


def estimate_lines(path: str) -> tuple[int, int]:
    size = os.path.getsize(path)
    if size == 0:
        return 0, 0
    with open(path, "rb") as f:
        sample = f.read(_SAMPLE_BYTES)
    if not sample:
        return 0, size
    newlines = sample.count(b"\n") or 1
    avg = max(1.0, len(sample) / newlines)
    return int(size / avg), size


def _reserved_cores(cores: int, headroom: int | None) -> int:
    if cores <= 1:
        return 0
    if headroom is None:
        return max(1, round(cores * 0.25))  # ~25 %, at least one
    return min(max(0, headroom), cores - 1)


# Oversplit factor the parallel scan uses (workers * oversplit slices).
_OVERSPLIT = 4


def _mem_available_bytes() -> int | None:
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def mem_capped_workers(workers: int, size_bytes: int) -> int:
    
    if workers <= 1 or size_bytes <= 0:
        return max(1, workers)
    # Small files never pressure memory, whatever the worker count.
    if size_bytes < 64 * 1024 * 1024:
        return workers
    avail = _mem_available_bytes()
    if not avail:
        return workers
    slice_bytes = size_bytes / max(1, workers * _OVERSPLIT)
    per_worker = max(768 * 1024 * 1024, int(slice_bytes * 3))  # ≥0.75 GB headroom
    cap = max(2, int(avail * 0.60 / per_worker))
    return max(1, min(workers, cap))


def plan(
    est_lines: int,
    size_bytes: int,
    cores: int,
    *,
    headroom: int | None = None,
    max_exact_lines: int | None = None,
    force: str | None = None,
) -> ScalePlan:
    threshold = max_exact_lines or DEFAULT_MAX_EXACT_LINES
    reserved = _reserved_cores(cores, headroom)
    workers = max(1, cores - reserved)
    workers = mem_capped_workers(workers, size_bytes)

    strategy = force or ("scan" if est_lines >= threshold else "exact")
    if strategy == "exact":
        reason = (
            f"~{est_lines:,} lines ≤ {threshold:,} threshold: exact full pipeline "
            f"(serial, byte-identical)"
            if force is None
            else "exact pipeline (forced)"
        )
        return ScalePlan("exact", 1, cores, reserved, est_lines, size_bytes, threshold, reason)

    reason = (
        f"~{est_lines:,} lines ≥ {threshold:,} threshold: fast parallel scan on "
        f"{workers} worker(s), {reserved} core(s) left free"
        if force is None
        else f"fast parallel scan (forced) on {workers} worker(s)"
    )
    return ScalePlan("scan", workers, cores, reserved, est_lines, size_bytes, threshold, reason)


def worker_budget(headroom: int | None = None, cores: int | None = None) -> int:
    cores = cores or detect_cores()
    return max(1, cores - _reserved_cores(cores, headroom))


def plan_for_file(
    path: str,
    *,
    cores: int | None = None,
    headroom: int | None = None,
    max_exact_lines: int | None = None,
    force: str | None = None,
) -> ScalePlan:
    cores = cores or detect_cores()
    est, size = estimate_lines(path)
    return plan(
        est,
        size,
        cores,
        headroom=headroom,
        max_exact_lines=max_exact_lines,
        force=force,
    )


def describe_plan(plan: ScalePlan) -> str:
    mb = plan.size_bytes / 1e6
    if plan.strategy == "scan":
        return (
            f"[bold cyan][LogLens][/bold cyan] large input (~{plan.est_lines:,} lines, "
            f"{mb:,.0f} MB): auto-scaling to the fast parallel scan on "
            f"[bold]{plan.workers}[/bold] worker(s) — [bold]{plan.reserved}[/bold] core(s) "
            f"left free for your other work. "
            f"[dim](--no-auto-scale for the exact pipeline, --headroom N to change)[/dim]"
        )
    return (
        f"[bold cyan][LogLens][/bold cyan] input ~{plan.est_lines:,} lines: running the "
        f"exact full pipeline."
    )
