from __future__ import annotations

import re
from dataclasses import dataclass, field

from loglens.detection.trace import Frame, extract_frames, primary_site

APPLICATION = "application"
LIBRARY = "library"
LOCATION_ONLY = "location_only"
EXCEPTION_ONLY = "exception_only"
PLAIN = "plain"

BLOCKING = "blocking"
NON_BLOCKING = "non-blocking"
UNKNOWN = "unknown"

_EXC = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*(?:Error|Exception|Fault|Overflow|Timeout))\b|\b(SIG[A-Z]+)\b"
)

_HARD_BLOCK = (
    "panic",
    "fatal",
    "segfault",
    "segmentation fault",
    "core dumped",
    "oom",
    "out of memory",
    "stack overflow",
    "kernel panic",
    "cannot start",
    "failed to start",
    "unrecoverable",
    "deadlock",
)
_BLOCK = (
    "crash",
    "crashed",
    "aborted",
    "abort",
    "terminating",
    "terminated",
    "shutting down",
    "shutdown",
    "halt",
    "halting",
    "killed",
    "killing process",
    "exit code",
    "exited with",
    "service unavailable",
    "503",
    "circuit open",
    "circuit breaker open",
    "connection refused",
    "refusing connection",
    "stopped accepting",
    "unhandled exception",
    "returning 500",
    "status 500",
)
_NON_BLOCK = (
    "retry",
    "retrying",
    "will retry",
    "retried",
    "fallback",
    "falling back",
    "degraded",
    "recovered",
    "recovery",
    "reconnect",
    "reconnecting",
    "backoff",
    "back off",
    "ignored",
    "ignoring",
    "skipped",
    "skipping",
    "continuing",
    "deprecated",
    "throttl",
    "rate limit",
    "transient",
    "temporarily",
    "slow",
)
_RECOVERY = ("recovered", "reconnected", "back to normal", "healthy again", "resolved")


@dataclass
class Diagnosis:
    trace_kind: str
    impact: str
    impact_reason: str
    exception_type: str | None = None
    site: Frame | None = None
    headline: str = ""
    where_human: str = ""
    frames: list[Frame] = field(default_factory=list)


def detect_exception_type(text: str) -> str | None:
    m = _EXC.search(text or "")
    if not m:
        return None
    for g in m.groups():
        if g:
            return g
    return None


def classify_trace(frames: list[Frame], text: str) -> tuple[str, Frame | None, str | None]:
    exc = detect_exception_type(text or "")
    structured = [f for f in frames if f.lang != "generic"]
    if frames and (len(frames) >= 2 or structured):
        if any(not f.is_library and f.file for f in frames):
            return APPLICATION, primary_site(frames), exc
        return LIBRARY, primary_site(frames), exc
    inline = frames or extract_frames(text or "")
    if inline:
        return LOCATION_ONLY, inline[0], exc
    if exc:
        return EXCEPTION_ONLY, None, exc
    return PLAIN, None, exc


def classify_blocking(level: str, text: str, *, recovery_follows: bool = False) -> tuple[str, str]:
    low = (text or "").lower()
    lvl = (level or "").upper()

    for kw in _HARD_BLOCK:
        if kw in low:
            return BLOCKING, f"hard-stop signal ('{kw}')"

    if recovery_follows:
        return NON_BLOCKING, "a recovery/normal line follows for this source"

    has_block = any(kw in low for kw in _BLOCK)
    has_soft = any(kw in low for kw in _NON_BLOCK)

    if has_soft and not has_block:
        return NON_BLOCKING, "recovery/retry language present"
    if has_block and not has_soft:
        return BLOCKING, "flow-stopping language present"
    if has_block and has_soft:
        return NON_BLOCKING, "failure followed by retry/recovery"

    if lvl == "FATAL":
        return BLOCKING, "FATAL severity"
    if lvl == "CRITICAL":
        return BLOCKING, "CRITICAL severity"
    if lvl in ("WARNING", "WARN", "NOTICE", "INFO", "DEBUG"):
        return NON_BLOCKING, f"{lvl} severity"
    return UNKNOWN, "no clear blocking/recovery signal"


def _headline(kind: str, site: Frame | None, exc: str | None, level: str, impact: str) -> str:
    who = f"{exc} " if exc else ""
    if kind == APPLICATION and site:
        loc = site.basename + (f" line {site.line}" if site.line is not None else "")
        fn = f", in {site.func}()" if site.func else ""
        return f"{who}in your code — {loc}{fn}.".strip()
    if kind == LIBRARY and site:
        return f"{who}failed inside a library ({site.basename}) — called from your code.".strip()
    if kind == LOCATION_ONLY and site:
        loc = site.basename + (f" line {site.line}" if site.line is not None else "")
        return f"{who}reported at {loc}.".strip()
    if kind == EXCEPTION_ONLY and exc:
        return f"{exc} was raised (no source file in the log)."
    verb = "stopped the flow" if impact == BLOCKING else "was logged"
    return f"{(level or 'Event').title()} {verb} — no stack trace in this line."


def _where_human(kind: str, site: Frame | None) -> str:
    if kind in (APPLICATION, LOCATION_ONLY) and site:
        loc = site.file + (f":{site.line}" if site.line is not None else "")
        return loc + (f"  (in {site.func})" if site.func else "")
    if kind == LIBRARY and site:
        loc = site.file + (f":{site.line}" if site.line is not None else "")
        return f"{loc}  (library — not your code)"
    if kind == EXCEPTION_ONLY:
        return "no source file in the log"
    return "no source location in the log"


def diagnose(
    text: str,
    frames: list[Frame] | None = None,
    *,
    level: str = "",
    recovery_follows: bool = False,
) -> Diagnosis:
    frames = frames or []
    kind, site, exc = classify_trace(frames, text)
    impact, reason = classify_blocking(level, text, recovery_follows=recovery_follows)
    if impact == UNKNOWN and kind in (APPLICATION, LIBRARY) and not recovery_follows:
        impact, reason = BLOCKING, "unhandled traceback (operation aborted)"
    return Diagnosis(
        trace_kind=kind,
        impact=impact,
        impact_reason=reason,
        exception_type=exc,
        site=site,
        headline=_headline(kind, site, exc, level, impact),
        where_human=_where_human(kind, site),
        frames=frames,
    )
