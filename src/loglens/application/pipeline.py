from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from enum import Enum

from loglens.domain.severity import get_severity

_PROTECTED_MAX_RANK = get_severity("ERROR")  # == 3


class OverflowPolicy(str, Enum):
    BLOCK = "block"
    DROP_OLDEST = "drop-oldest"
    DROP_NEWEST = "drop-newest"
    SAMPLE = "sample"


def is_protected(level: str) -> bool:
    """True if a line of this level must never be shed."""
    return get_severity(level) <= _PROTECTED_MAX_RANK


@dataclass(slots=True)
class DropAccounting:
    dropped: int = 0
    by_level: dict[str, int] | None = None

    def add(self, level: str, n: int = 1) -> None:
        self.dropped += n
        if self.by_level is None:
            self.by_level = {}
        k = level.upper()
        self.by_level[k] = self.by_level.get(k, 0) + n


class SheddingQueue:
    def __init__(
        self,
        maxsize: int,
        policy: OverflowPolicy = OverflowPolicy.BLOCK,
        sample_rate: int = 10,
    ) -> None:
        if maxsize < 1:
            raise ValueError("maxsize must be >= 1")
        self.maxsize = maxsize
        self.policy = policy
        self.sample_rate = max(2, sample_rate)
        self._q: deque[tuple[str, object]] = deque()
        self._lock = threading.Lock()
        self._not_full = threading.Condition(self._lock)
        self._not_empty = threading.Condition(self._lock)
        self._closed = False
        self._sample_counter = 0
        self.drops = DropAccounting()

    @property
    def depth(self) -> int:
        with self._lock:
            return len(self._q)

    def put(self, level: str, item: object, timeout: float | None = None) -> bool:
        with self._not_full:
            if len(self._q) < self.maxsize:
                self._q.append((level, item))
                self._not_empty.notify()
                return True

            protected = is_protected(level)

            if self.policy is OverflowPolicy.BLOCK:
                while len(self._q) >= self.maxsize and not self._closed:
                    if not self._not_full.wait(timeout):
                        break  # timed out
                    if timeout is not None and len(self._q) >= self.maxsize:
                        break
                if len(self._q) < self.maxsize:
                    self._q.append((level, item))
                    self._not_empty.notify()
                    return True
                if protected or self._closed:
                    self._q.append((level, item))
                    self._not_empty.notify()
                    return True
                self.drops.add(level)
                return False

            if protected:
                self._q.append((level, item))
                self._not_empty.notify()
                return True

            if self.policy is OverflowPolicy.DROP_NEWEST:
                self.drops.add(level)
                return False

            if self.policy is OverflowPolicy.DROP_OLDEST:
                for i, (lvl, _it) in enumerate(self._q):
                    if not is_protected(lvl):
                        del self._q[i]
                        self.drops.add(lvl)
                        self._q.append((level, item))
                        self._not_empty.notify()
                        return True
                self.drops.add(level)
                return False

            if self.policy is OverflowPolicy.SAMPLE:
                self._sample_counter += 1
                if self._sample_counter % self.sample_rate == 0:
                    for i, (lvl, _it) in enumerate(self._q):
                        if not is_protected(lvl):
                            del self._q[i]
                            self.drops.add(lvl)
                            self._q.append((level, item))
                            self._not_empty.notify()
                            return True
                self.drops.add(level)
                return False

            return False

    def get(self, timeout: float | None = None) -> tuple[str, object] | None:
        with self._not_empty:
            while not self._q and not self._closed:
                if not self._not_empty.wait(timeout):
                    return None
            if not self._q:
                return None
            item = self._q.popleft()
            self._not_full.notify()
            return item

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._not_empty.notify_all()
            self._not_full.notify_all()


LADDER = ("full", "no_embeddings", "counts_only", "sampling")


@dataclass(slots=True)
class LadderConfig:
    capacity: int
    high: float = 0.85
    low: float = 0.5
    dwell: int = 3


class DegradationLadder:
    def __init__(self, cfg: LadderConfig, on_change=None) -> None:
        self.cfg = cfg
        self._level = 0
        self._up = 0
        self._down = 0
        self._on_change = on_change

    @property
    def mode(self) -> str:
        return LADDER[self._level]

    def observe(self, depth: int) -> str:
        frac = depth / self.cfg.capacity if self.cfg.capacity else 0.0
        if frac >= self.cfg.high:
            self._down += 1
            self._up = 0
            if self._down >= self.cfg.dwell and self._level < len(LADDER) - 1:
                self._transition(self._level + 1)
        elif frac <= self.cfg.low:
            self._up += 1
            self._down = 0
            if self._up >= self.cfg.dwell and self._level > 0:
                self._transition(self._level - 1)
        else:
            self._up = self._down = 0
        return self.mode

    def _transition(self, new_level: int) -> None:
        old = LADDER[self._level]
        self._level = new_level
        self._up = self._down = 0
        if self._on_change is not None:
            self._on_change(old, LADDER[new_level])
