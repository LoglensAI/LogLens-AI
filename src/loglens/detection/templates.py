from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache

from loglens.domain.models import LogEntry

_MASKS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "<uuid>",
    ),
    (re.compile(r"\b0[xX][0-9a-fA-F]+\b"), "<hex>"),
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<hex>"),
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{2,5})?\b"), "<ip>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][\d:]{5,8}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b"), "<ts>"),
    (
        re.compile(
            r"\b\d+(\.\d+)?\s*(ms|s|sec|seconds?|min|minutes?|h|hours?"
            r"|kb|mb|gb|tb|kib|mib|gib|bytes?|%)\b",
            re.IGNORECASE,
        ),
        r"<num>\2",
    ),
    (re.compile(r"\b\d+(\.\d+)?\b"), "<num>"),
    (re.compile(r'"[^"]*"'), "<str>"),
    (re.compile(r"'[^']*'"), "<str>"),
    (re.compile(r"\S*\d\S*"), "<id>"),
]

_WS = re.compile(r"\s+")
_HAS_DIGIT = re.compile(r"\d")


def _template_key_uncached(message: str) -> str:
    t = message.strip()
    has_digit = bool(_HAS_DIGIT.search(t))

    if "-" in t:  # uuid (requires hyphens)
        t = _MASKS[0][0].sub(_MASKS[0][1], t)
    if "0x" in t or "0X" in t:  # hex 0x…
        t = _MASKS[1][0].sub(_MASKS[1][1], t)
    if len(t) >= 12:  # long hex run (needs ≥12 chars)
        t = _MASKS[2][0].sub(_MASKS[2][1], t)
    if has_digit and "." in t:  # ipv4
        t = _MASKS[3][0].sub(_MASKS[3][1], t)
    if has_digit and "-" in t and ":" in t:  # iso timestamp
        t = _MASKS[4][0].sub(_MASKS[4][1], t)
    if has_digit:  # number + unit
        t = _MASKS[5][0].sub(_MASKS[5][1], t)
    if has_digit:  # bare number
        t = _MASKS[6][0].sub(_MASKS[6][1], t)
    if '"' in t:  # double-quoted string
        t = _MASKS[7][0].sub(_MASKS[7][1], t)
    if "'" in t:  # single-quoted string
        t = _MASKS[8][0].sub(_MASKS[8][1], t)
    if has_digit:  # catch-all token containing a digit
        t = _MASKS[9][0].sub(_MASKS[9][1], t)

    return _WS.sub(" ", t).lower()


@lru_cache(maxsize=131_072)
def _template_key_cached(message: str) -> str:
    return _template_key_uncached(message)


def template_key(message: str) -> str:
    return _template_key_cached(message)


_ISO_RE = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?"
)
_SYSLOG_RE = re.compile(
    r"(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
_NGINX_RE = re.compile(
    r"(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<time>\d{2}:\d{2}:\d{2})"
)
_EPOCH_RE = re.compile(r"^(?P<sec>1\d{9})(?P<ms>\d{3})?(\.\d+)?$")

_MONTHS = {
    m: i + 1
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    )
}


def parse_timestamp(ts: str) -> float | None:
    if not ts:
        return None
    ts = ts.strip()

    m = _EPOCH_RE.match(ts)
    if m:
        sec = float(m.group("sec"))
        if m.group("ms"):
            sec += int(m.group("ms")) / 1000.0
        return sec

    m = _ISO_RE.search(ts)
    if m:
        try:
            dt = datetime.strptime(f"{m.group('date')} {m.group('time')}", "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            return None

    m = _SYSLOG_RE.search(ts)
    if m:
        try:
            now = datetime.now()
            dt = datetime(now.year, _MONTHS[m.group("mon")], int(m.group("day")))
            h, mi, s = (int(x) for x in m.group("time").split(":"))
            return dt.replace(hour=h, minute=mi, second=s, tzinfo=timezone.utc).timestamp()
        except (ValueError, KeyError):
            return None

    m = _NGINX_RE.search(ts)
    if m:
        try:
            dt = datetime(int(m.group("year")), _MONTHS[m.group("mon")], int(m.group("day")))
            h, mi, s = (int(x) for x in m.group("time").split(":"))
            return dt.replace(hour=h, minute=mi, second=s, tzinfo=timezone.utc).timestamp()
        except (ValueError, KeyError):
            return None

    return None


@dataclass
class TemplateGroup:
    key: tuple[str, str]  # (LEVEL, template)
    representative: LogEntry  # first entry seen
    indices: list[int] = field(default_factory=list)  # entry indices

    @property
    def count(self) -> int:
        return len(self.indices)

    @property
    def level(self) -> str:
        return self.key[0]

    @property
    def template(self) -> str:
        return self.key[1]


class TemplateRegistry:
    def __init__(self, entries: Sequence[LogEntry]):
        self.groups: list[TemplateGroup] = []
        self.entry_group: list[int] = [0] * len(entries)  # entry idx -> group idx
        index: dict[tuple[str, str], int] = {}
        for i, e in enumerate(entries):
            key = (e.level.upper(), template_key(e.message))
            gi = index.get(key)
            if gi is None:
                gi = len(self.groups)
                index[key] = gi
                self.groups.append(TemplateGroup(key=key, representative=e))
            self.groups[gi].indices.append(i)
            self.entry_group[i] = gi

    def __len__(self) -> int:
        return len(self.groups)

    @property
    def counts(self) -> list[int]:
        return [g.count for g in self.groups]

    def representative_indices(self) -> list[int]:
        """Index (into the original entry list) of each group's representative."""
        return [g.indices[0] for g in self.groups]
