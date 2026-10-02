from __future__ import annotations

import os
from dataclasses import dataclass

from loglens.application.scheduler import detect_cores

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