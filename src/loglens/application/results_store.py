from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

SCHEMA = "loglens.results.v1"

SEVERITY_MENU: list[tuple[str, str]] = [
    ("CRITICAL", "Critical / Fatal"),
    ("ERROR", "Error"),
    ("WARN", "Warning"),
    ("INFO", "Info"),
    ("DEBUG", "Debug / Trace"),
]
_LEVEL_ALIASES: dict[str, set[str]] = {
    "CRITICAL": {"CRITICAL", "CRIT", "FATAL", "EMERGENCY", "EMERG", "ALERT", "PANIC", "SEVERE"},
    "ERROR": {"ERROR", "ERR"},
    "WARN": {"WARN", "WARNING"},
    "INFO": {"INFO", "NOTICE"},
    "DEBUG": {"DEBUG", "TRACE"},
}

TIME_WINDOWS: list[tuple[str, int]] = [
    ("Last 1 hour", 3600),
    ("Last 3 hours", 3 * 3600),
    ("Last 8 hours", 8 * 3600),
    ("Last 24 hours", 24 * 3600),
    ("Last 48 hours", 48 * 3600),
    ("Last 72 hours", 72 * 3600),
    ("Last 1 week", 7 * 86400),
    ("Last 2 weeks", 14 * 86400),
    ("Last 1 month", 30 * 86400),
    ("Last 3 months", 90 * 86400),
    ("Last 6 months", 180 * 86400),
    ("Last 1 year", 365 * 86400),
]

_BGL_TS = re.compile(r"(\d{4})-(\d{2})-(\d{2})-(\d{2})\.(\d{2})\.(\d{2})(?:\.(\d+))?")
_ISO_TS = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)


def to_epoch(ts: str | None) -> float | None:
    if not ts:
        return None
    m = _BGL_TS.search(ts)
    if m:
        y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
        try:
            return datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc).timestamp()
        except ValueError:
            return None
    m = _ISO_TS.search(ts)
    if m:
        y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
        try:
            return datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc).timestamp()
        except ValueError:
            return None
    return None


def hour_bucket(epoch: float) -> int:
    return int(epoch // 3600)


def canonical_bucket(level: str) -> str:
    up = (level or "").upper()
    for bucket, members in _LEVEL_ALIASES.items():
        if up in members:
            return bucket
    return up




def save_results(path: str, result: dict[str, Any]) -> str:
    result = {**result, "schema": SCHEMA}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f)
    return path


def load_results(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)




def reference_epoch(result: dict[str, Any]) -> float | None:
    span = result.get("time_span") or {}
    return span.get("last_epoch")


def severity_count(result: dict[str, Any], level_bucket: str, window_seconds: int) -> int:
    ref = reference_epoch(result)
    hist = (result.get("level_time_hist") or {}).get(canonical_bucket(level_bucket))
    if ref is None or not hist:
        return 0
    lo_bucket = hour_bucket(ref - window_seconds)
    total = 0
    for hb_str, c in hist.items():
        if int(hb_str) >= lo_bucket:
            total += c
    return total


def severity_breakdown(result: dict[str, Any], window_seconds: int) -> dict[str, int]:
    return {
        bucket: severity_count(result, bucket, window_seconds) for bucket, _label in SEVERITY_MENU
    }


def families_in_window(
    result: dict[str, Any],
    window_seconds: int | None = None,
    level_bucket: str | None = None,
    query: str = "",
    limit: int = 50,
) -> list[dict[str, Any]]:
    ref = reference_epoch(result)
    lo = (ref - window_seconds) if (ref is not None and window_seconds) else None
    q = query.strip().lower()
    out = []
    for fam in result.get("families", []):
        if level_bucket and canonical_bucket(fam.get("level", "")) != canonical_bucket(
            level_bucket
        ):
            continue
        if lo is not None:
            last = fam.get("last_epoch")
            if last is None or last < lo:
                continue
        if q and q not in (fam.get("template", "") + " " + fam.get("sample", "")).lower():
            continue
        out.append(fam)
    out.sort(key=lambda f: (-float(f.get("score", 0.0)), -int(f.get("count", 0))))
    return out[:limit]