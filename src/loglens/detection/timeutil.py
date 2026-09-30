from __future__ import annotations

import re
from datetime import datetime, timedelta

_TS_PATTERNS: tuple[str, ...] = (
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d-%H.%M.%S.%f",  # BGL
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",
    "%b %d %H:%M:%S.%f",
)

_ISO_TZ = re.compile(r"([+-]\d{2}:?\d{2}|Z)$")
_DUR = re.compile(r"(\d+(?:\.\d+)?)\s*([smhdw])", re.IGNORECASE)
_DUR_SECS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

_SPARK = "▁▂▃▄▅▆▇█"


def parse_ts(value: str) -> datetime | None:

    if not value:
        return None
    s = value.strip().strip("[]")
    if not s:
        return None
    if s.isdigit():
        n = int(s)
        try:
            return datetime.fromtimestamp(n / 1000 if n > 10_000_000_000 else n)
        except (OverflowError, OSError, ValueError):
            return None
    core = _ISO_TZ.sub("", s).strip()
    for fmt in _TS_PATTERNS:
        try:
            return datetime.strptime(core, fmt)
        except ValueError:
            continue
    try:
        from dateutil import parser as _p

        return _p.parse(s, fuzzy=True).replace(tzinfo=None)
    except (ValueError, OverflowError, TypeError, ImportError):
        return None


def parse_duration(value: str) -> timedelta | None:
    if not value:
        return None
    total = 0.0
    matched = False
    for num, unit in _DUR.findall(value):
        total += float(num) * _DUR_SECS[unit.lower()]
        matched = True
    if not matched:
        return None
    return timedelta(seconds=total)


def humanize_delta(delta: timedelta) -> str:
    secs = int(delta.total_seconds())
    if secs < 0:
        return "in the future"
    if secs < 5:
        return "just now"
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"


def humanize_span(start: datetime, end: datetime) -> str:
    secs = int(abs((end - start).total_seconds()))
    if secs == 0:
        return "instant"
    parts: list[str] = []
    for label, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if secs >= size:
            parts.append(f"{secs // size}{label}")
            secs %= size
        if len(parts) == 2:
            break
    return " ".join(parts)


def bucketize(times: list[datetime], start: datetime, end: datetime, n: int = 24) -> list[int]:
    n = max(1, n)
    counts = [0] * n
    span = (end - start).total_seconds()
    if span <= 0:
        for t in times:
            if start <= t <= end:
                counts[-1] += 1
        return counts
    for t in times:
        if t < start or t > end:
            continue
        idx = int((t - start).total_seconds() / span * n)
        counts[min(idx, n - 1)] += 1
    return counts


def sparkline(counts: list[int]) -> str:
    if not counts:
        return ""
    hi = max(counts)
    if hi == 0:
        return _SPARK[0] * len(counts)
    out = []
    for c in counts:
        level = 0 if c == 0 else 1 + int((c / hi) * (len(_SPARK) - 2))
        out.append(_SPARK[min(level, len(_SPARK) - 1)])
    return "".join(out)
