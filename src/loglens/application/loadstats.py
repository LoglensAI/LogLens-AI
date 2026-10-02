from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SourceStat:
    source_id: str
    lines_in: int = 0
    lines_parsed: int = 0
    lines_dropped: int = 0
    dropped_by_level: dict[str, int] = field(default_factory=dict)
    queue_depth: int = 0
    queue_peak: int = 0
    lag_seconds: float = 0.0
    mode: str = "full"
    worker: int | None = None
    started_at: float | None = None
    finished_at: float | None = None
    compute_seconds: float | None = None
    error: str | None = None

    def start(self) -> None:
        self.started_at = time.monotonic()

    def finish(self, error: str | None = None) -> None:
        self.finished_at = time.monotonic()
        if error:
            self.error = error

    def record_drop(self, level: str, n: int = 1) -> None:
        self.lines_dropped += n
        key = level.upper()
        self.dropped_by_level[key] = self.dropped_by_level.get(key, 0) + n

    def observe_depth(self, depth: int) -> None:
        self.queue_depth = depth
        if depth > self.queue_peak:
            self.queue_peak = depth

    @property
    def elapsed(self) -> float:
        if self.compute_seconds is not None:
            return max(0.0, self.compute_seconds)
        if self.started_at is None:
            return 0.0
        end = self.finished_at if self.finished_at is not None else time.monotonic()
        return max(0.0, end - self.started_at)

    @property
    def lines_per_sec(self) -> float:
        e = self.elapsed
        return self.lines_parsed / e if e > 0 else 0.0

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source_id,
            "worker": self.worker,
            "lines_in": self.lines_in,
            "lines_parsed": self.lines_parsed,
            "lines_dropped": self.lines_dropped,
            "dropped_by_level": dict(sorted(self.dropped_by_level.items())),
            "queue_peak": self.queue_peak,
            "lag_seconds": round(self.lag_seconds, 3),
            "mode": self.mode,
            "lines_per_sec": round(self.lines_per_sec, 1),
            "elapsed_seconds": round(self.elapsed, 3),
            "ok": self.ok,
            "error": self.error,
        }


@dataclass(slots=True)
class LoadStats:
    sources: dict[str, SourceStat] = field(default_factory=dict)

    def get(self, source_id: str) -> SourceStat:
        st = self.sources.get(source_id)
        if st is None:
            st = SourceStat(source_id=source_id)
            self.sources[source_id] = st
        return st

    @property
    def total_parsed(self) -> int:
        return sum(s.lines_parsed for s in self.sources.values())

    @property
    def total_dropped(self) -> int:
        return sum(s.lines_dropped for s in self.sources.values())

    @property
    def any_degraded(self) -> bool:
        return any(s.mode != "full" for s in self.sources.values())

    @property
    def faulted(self) -> list[str]:
        return sorted(sid for sid, s in self.sources.items() if not s.ok)

    def to_dict(self) -> dict[str, Any]:
        # Deterministic: sources sorted by id.
        return {
            "total_parsed": self.total_parsed,
            "total_dropped": self.total_dropped,
            "degraded": self.any_degraded,
            "faulted": self.faulted,
            "by_source": [self.sources[k].to_dict() for k in sorted(self.sources)],
        }
