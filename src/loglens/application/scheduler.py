from __future__ import annotations

import os
from dataclasses import dataclass, field


def _cgroup_quota_cores() -> float | None:
    try:
        with open("/sys/fs/cgroup/cpu.max", encoding="ascii") as fh:
            quota_s, period_s = (fh.read().split() + ["100000"])[:2]
        if quota_s != "max":
            quota, period = int(quota_s), int(period_s)
            if quota > 0 and period > 0:
                return quota / period
    except (OSError, ValueError):
        pass
    # cgroup v1
    try:
        with open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us", encoding="ascii") as fh:
            quota = int(fh.read().strip())
        with open("/sys/fs/cgroup/cpu/cpu.cfs_period_us", encoding="ascii") as fh:
            period = int(fh.read().strip())
        if quota > 0 and period > 0:
            return quota / period
    except (OSError, ValueError):
        pass
    return None


def _affinity_cores() -> int | None:
    getaffinity = getattr(os, "sched_getaffinity", None)
    if getaffinity is None:
        return None
    try:
        return len(getaffinity(0))
    except OSError:
        return None


def detect_cores() -> int:
    candidates: list[int] = []
    aff = _affinity_cores()
    if aff:
        candidates.append(aff)
    cpu = os.cpu_count()
    if cpu:
        candidates.append(cpu)
    quota = _cgroup_quota_cores()
    if quota is not None:
        candidates.append(max(1, int(quota + 0.999)))
    return min(candidates) if candidates else 1


def effective_workers(
    n_sources: int,
    requested: int | None = None,
    reserve_coordinator: bool = True,
    max_cap: int = 32,
) -> int:
    cores = detect_cores()
    if cores <= 1:
        return 1
    budget = cores - 1 if reserve_coordinator else cores
    budget = max(1, budget)
    if requested is not None and requested > 0:
        budget = min(budget, requested)
    return max(1, min(budget, n_sources, max_cap))


@dataclass(slots=True)
class Assignment:
    """The computed plan for a run."""

    workers: int
    sources_by_worker: dict[int, list[str]] = field(default_factory=dict)
    worker_of: dict[str, int] = field(default_factory=dict)
    split_sources: list[str] = field(default_factory=list)
    split_width: dict[str, int] = field(default_factory=dict)

    @property
    def shared(self) -> bool:
        return any(len(v) > 1 for v in self.sources_by_worker.values())


def plan_assignment(
    specs,
    workers: int,
) -> Assignment:
    specs = list(specs)
    a = Assignment(workers=workers)
    for w in range(workers):
        a.sources_by_worker[w] = []

    if workers <= 1:
        a.sources_by_worker = {0: [s.id for s in specs]}
        a.worker_of = {s.id: 0 for s in specs}
        return a

    load = [0] * workers
    for spec in sorted(specs, key=lambda s: s.id):
        h = int.from_bytes(_stable_digest(spec.id), "big") % workers
        w = h
        if load[h] > min(load) + 0:
            w = min(range(workers), key=lambda i: (load[i], i))
        a.sources_by_worker[w].append(spec.id)
        a.worker_of[spec.id] = w
        load[w] += 1

    for w in a.sources_by_worker:
        a.sources_by_worker[w].sort()

    idle = workers - sum(1 for v in a.sources_by_worker.values() if v)
    if idle > 0:
        file_specs = sorted(
            (s for s in specs if s.is_file and s.size_bytes() > 16 * 1024 * 1024),
            key=lambda s: s.size_bytes(),
            reverse=True,
        )
        spare = idle
        for s in file_specs:
            if spare <= 0:
                break
            extra = min(spare, 7)
            a.split_sources.append(s.id)
            a.split_width[s.id] = extra + 1
            spare -= extra

    return a


def _stable_digest(text: str) -> bytes:
    import hashlib

    return hashlib.blake2b(text.encode("utf-8"), digest_size=8).digest()


@dataclass(slots=True)
class DeficitScheduler:
    quantum: float = 1.0
    deficit: dict[str, float] = field(default_factory=dict)
    weight: dict[str, float] = field(default_factory=dict)
    _order: list[str] = field(default_factory=list)
    _cursor: int = 0
    _credited: bool = False

    def add(self, source_id: str, weight: float = 1.0) -> None:
        if source_id not in self.weight:
            self.weight[source_id] = max(weight, 1e-9)
            self.deficit[source_id] = 0.0
            self._order.append(source_id)

    def select(self, ready: set[str]) -> str | None:
        if not ready or not self._order:
            return None
        n = len(self._order)
        for _ in range(4 * n + 2):
            sid = self._order[self._cursor % n]
            if sid not in ready:
                self.deficit[sid] = 0.0  # idle flow banks no credit
                self._advance()
                continue
            if not self._credited:
                self.deficit[sid] += self.quantum * self.weight[sid]
                self._credited = True
            if self.deficit[sid] >= 1.0:
                self.deficit[sid] -= 1.0
                return sid
            self._advance()
        return max(ready, key=lambda s: self.deficit.get(s, 0.0))

    def _advance(self) -> None:
        self._cursor = (self._cursor + 1) % len(self._order)
        self._credited = False
