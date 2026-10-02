from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Iterator
from functools import lru_cache

from loglens.detection.cloud import map_cloud_json
from loglens.domain.models import LogEntry

logger = logging.getLogger("loglens.parser")

# JSON is detected/parsed separately (see detect_format/parse_line), so it is
# intentionally not in this regex table — keeping every value a real Pattern.
PATTERNS: dict[str, re.Pattern[str]] = {
    "NGINX": re.compile(
        r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d+) (?P<bytes>\d+)'
    ),
    "APACHE": re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d+) (?P<bytes>\d+)'
    ),
    "APP_LOG": re.compile(
        r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,\.]\d+)\s+"
        r"(?P<level>[A-Z]+)\s+\[(?P<thread>[^\]]*)\]\s+"
        r"(?P<service>[^:\s]+):\s*(?P<message>.*)"
    ),
    "ZK_LOG": re.compile(
        r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,\.]\d+)\s+-\s+"
        r"(?P<level>[A-Z]+)\s+\[(?P<thread>.+)\]\s+-\s+(?P<message>.+)"
    ),
    "SPARK_LOG": re.compile(
        r"^(?P<time>\d\d/\d\d/\d\d \d\d:\d\d:\d\d)\s+"
        r"(?P<level>[A-Z]+)\s+(?P<service>[^:]+):\s*(?P<message>.*)"
    ),
    "APACHE_ERR": re.compile(
        r"^\[(?P<time>\w{3} \w{3} \d+ [\d:]+ \d{4})\]\s+"
        r"\[(?P<level>\w+)\]\s+(?P<message>.+)"
    ),
    "WINCBS": re.compile(
        r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\s+"
        r"(?P<level>\w+)\s+(?P<service>\w+)\s+(?P<message>.+)"
    ),
    "HDFS": re.compile(
        r"^(?P<date>\d{6})\s+(?P<time>\d{6})\s+(?P<pid>\d+)\s+"
        r"(?P<level>[A-Z]+)\s+(?P<service>\S+?):\s+(?P<message>.+)"
    ),
    "HPC": re.compile(
        r"^(?P<label>-|[A-Z0-9_]+)\s+(?P<epoch>\d{9,10})\s+"
        r"(?P<date>\d{4}\.\d\d\.\d\d)\s+(?P<node>\S+)\s+(?P<message>.+)"
    ),
    "HEALTHAPP": re.compile(
        r"^(?P<time>\d{8}-\d{1,2}:\d{1,2}:\d{1,2}:\d+)\|"
        r"(?P<service>[^|]+)\|(?P<pid>[^|]+)\|(?P<message>.+)"
    ),
    "PROXIFIER": re.compile(
        r"^\[(?P<time>[\d.]+ [\d:]+)\]\s+"
        r"(?P<service>\S+?\.exe(?:\s+\*\d+)?)\s+-\s+(?P<message>.+)"
    ),
    "SYSLOG": re.compile(
        r"(?P<time>\w+\s+\d+\s+[\d:]+) (?P<host>\S+) (?P<service>\S+?):? (?P<message>.+)"
    ),
    "KUBE": re.compile(
        r"^(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
        r"(?P<stream>stdout|stderr)\s+(?P<flag>[FP])\s+(?P<message>.*)$"
    ),
    "STANDARD": re.compile(
        r"(?P<time>\d{4}-\d{2}-\d{2}T[\d:]+Z)\s+(?P<level>\w+)\s+\[(?P<service>[^\]]+)\]\s+(?P<message>.+)"
    ),
    "LOGLENS": re.compile(
        r"(?P<time>\d{4}-\d{2}-\d{2}T[\d:]+Z)\s+(?P<level>\w+)\s+(?P<service>\S+)\s+(?P<message>.+)"
    ),
}


_PRI_RE = re.compile(r"^<(\d{1,3})>\s*")
_FACILITY_SEV_RE = re.compile(
    r"\b(?:kern|user|mail|daemon|auth(?:priv)?|syslog|lpr|news|uucp|cron|ftp"
    r"|local[0-7])\.(emerg|alert|crit|err|error|warning|warn|notice|info"
    r"|debug)\b",
    re.IGNORECASE,
)
SYSLOG_SEVERITY = {
    0: "EMERGENCY",
    1: "ALERT",
    2: "CRITICAL",
    3: "ERROR",
    4: "WARN",
    5: "NOTICE",
    6: "INFO",
    7: "DEBUG",
}
_TEXT_SEVERITY = {
    "emerg": "EMERGENCY",
    "alert": "ALERT",
    "crit": "CRITICAL",
    "err": "ERROR",
    "error": "ERROR",
    "warning": "WARN",
    "warn": "WARN",
    "notice": "NOTICE",
    "info": "INFO",
    "debug": "DEBUG",
}


def _syslog_level(line: str) -> str:
    m = _PRI_RE.match(line)
    if m:
        return SYSLOG_SEVERITY[int(m.group(1)) % 8]
    m = _FACILITY_SEV_RE.search(line)
    if m:
        return _TEXT_SEVERITY[m.group(1).lower()]
    return "INFO"


_PLAINTEXT_LEVEL_RE = re.compile(
    r"\b(EMERG(?:ENCY)?|ALERT|CRIT(?:ICAL)?|FATAL|SEVERE|ERROR|ERR|EXCEPTION"
    r"|WARN(?:ING)?|FAIL(?:ED|URE)?|NOTICE|DEBUG|TRACE|INFO)\b",
    re.IGNORECASE,
)
_PLAINTEXT_LEVEL_MAP = {
    "emerg": "EMERGENCY",
    "emergency": "EMERGENCY",
    "alert": "ALERT",
    "crit": "CRITICAL",
    "critical": "CRITICAL",
    "fatal": "CRITICAL",
    "severe": "CRITICAL",
    "error": "ERROR",
    "err": "ERROR",
    "exception": "ERROR",
    "fail": "ERROR",
    "failed": "ERROR",
    "failure": "ERROR",
    "warn": "WARN",
    "warning": "WARN",
    "notice": "NOTICE",
    "debug": "DEBUG",
    "trace": "DEBUG",
    "info": "INFO",
}


def infer_level(text: str) -> str:
    m = _PLAINTEXT_LEVEL_RE.search(text)
    if m:
        return _PLAINTEXT_LEVEL_MAP.get(m.group(1).lower(), "INFO")
    return "INFO"


@lru_cache(maxsize=4096)
def _norm_level(tok: str) -> str:
    return _PLAINTEXT_LEVEL_MAP.get(tok.lower(), tok.upper())


def status_to_level(status: int) -> str:
    if status in (503, 504):
        return "CRITICAL"
    if status >= 500:
        return "ERROR"
    if status == 404:
        return "INFO"
    if status >= 400:
        return "WARN"
    return "INFO"


_GENERIC_TS = re.compile(
    r"^(?P<ts>"
    r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?"
    r"|\d{2}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2}"
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r")(?=\s)"
)

_LEVEL_TOKENS = {
    "emerg",
    "emergency",
    "alert",
    "crit",
    "critical",
    "fatal",
    "severe",
    "error",
    "err",
    "warn",
    "warning",
    "notice",
    "info",
    "debug",
    "trace",
}

_LOGFMT_PAIR = re.compile(r"(\w[\w.\-]*)=(\"(?:[^\"\\]|\\.)*\"|'[^']*'|\S+)")
_LOGFMT_KEYS = {
    "level",
    "lvl",
    "severity",
    "msg",
    "message",
    "time",
    "ts",
    "timestamp",
    "logger",
    "service",
    "caller",
}
_COMPONENT_RE = re.compile(r"^[A-Za-z][\w.\-/]*(?:\[\d+\])?:?$")


def _is_logfmt(line: str) -> bool:
    pairs = _LOGFMT_PAIR.findall(line)
    if len(pairs) < 2:
        return False
    keys = {k.lower() for k, _ in pairs}
    if not (keys & {"level", "lvl", "severity", "msg", "message"}):
        return False
    return len(keys & _LOGFMT_KEYS) >= 2


def _looks_like_component(tok: str) -> bool:
    core = tok.rstrip(":")
    if not core or len(core) > 60 or not _COMPONENT_RE.match(tok):
        return False
    return (
        any(c in core for c in "._-/")
        or core.endswith("]")
        or tok.endswith(":")
        or (core.isupper() and len(core) >= 2)
        or any(ch.isdigit() for ch in core)
    )


def detect_format(line: str) -> str:
    line = line.strip()
    if not line:
        return "UNKNOWN"
    probe = _PRI_RE.sub("", line)
    if probe.startswith(("{", "[")):
        try:
            json.loads(probe)
            return "JSON"
        except ValueError:
            pass
    for fmt, pattern in PATTERNS.items():
        if fmt == "JSON":
            continue
        if pattern and pattern.match(probe):
            return fmt
    if _is_logfmt(probe):
        return "LOGFMT"
    if _GENERIC_TS.match(probe):
        return "GENERIC"
    return "PLAINTEXT"


def _parse_kube(line: str) -> LogEntry | None:
    m = PATTERNS["KUBE"].match(line)
    if not m:
        return None
    msg = m.group("message").strip()
    return LogEntry(
        timestamp=m.group("time"),
        level=infer_level(msg),
        service="unknown",
        message=msg,
        raw=line,
        metadata={"stream": m.group("stream")},
    )


def _parse_logfmt(line: str) -> LogEntry:
    pairs: dict[str, str] = {}
    for k, v in _LOGFMT_PAIR.findall(line):
        if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
            v = v[1:-1]
        pairs[k.lower()] = v
    ts = pairs.get("time") or pairs.get("ts") or pairs.get("timestamp") or ""
    lvl_raw = pairs.get("level") or pairs.get("lvl") or pairs.get("severity") or ""
    level = _norm_level(lvl_raw) if lvl_raw else infer_level(line)
    service = (
        pairs.get("service")
        or pairs.get("logger")
        or pairs.get("component")
        or pairs.get("app")
        or "unknown"
    )
    message = pairs.get("msg") or pairs.get("message") or ""
    reserved = _LOGFMT_KEYS | {"component", "app"}
    meta = {k: v for k, v in pairs.items() if k not in reserved}
    return LogEntry(
        timestamp=ts,
        level=level,
        service=service,
        message=message or line,
        raw=line,
        metadata=meta,
    )


def _parse_generic(line: str, layout: dict | None = None) -> LogEntry | None:
    m = _GENERIC_TS.match(line)
    if not m:
        return None
    ts = m.group("ts")
    rest = line[m.end() :].strip()
    tokens = rest.split()
    if not tokens:
        return LogEntry(timestamp=ts, level="INFO", service="unknown", message="", raw=line)

    idx = 0
    level: str | None = None
    first = tokens[0].strip("[]").rstrip(":")
    if first.lower() in _LEVEL_TOKENS:
        level = _norm_level(first)
        idx = 1

    service = "unknown"
    want_service = bool(layout and layout.get("service_col"))
    if want_service and layout and layout.get("has_level") and level is None:
        # Sniff learned the column sits after a level; this line has none, so
        # don't misread the first message word as a service.
        want_service = False
    if idx < len(tokens) and (len(tokens) - idx) >= 2:
        cand = tokens[idx].rstrip(":")
        if want_service and cand:
            service = cand
            idx += 1
        elif layout is None and _looks_like_component(tokens[idx]):
            service = cand
            idx += 1

    message = " ".join(tokens[idx:]) if idx < len(tokens) else rest
    if level is None:
        level = infer_level(rest)
    return LogEntry(
        timestamp=ts,
        level=level,
        service=service or "unknown",
        message=message,
        raw=line,
    )


def parse_line(line: str, fmt: str, layout: dict | None = None) -> LogEntry | None:
    line = line.strip()
    if not line:
        return None
    try:
        if fmt == "JSON":
            data = json.loads(line)
            if not isinstance(data, dict):
                raise ValueError("not an object")
            cloud = map_cloud_json(data, line)
            if cloud is not None:
                return cloud
            return LogEntry(
                timestamp=str(data.get("timestamp", data.get("time", ""))),
                level=str(data.get("level", data.get("severity", "INFO"))).upper(),
                service=str(data.get("service", data.get("logger", "unknown"))),
                message=str(data.get("message", data.get("msg", line))),
                raw=line,
                metadata={
                    k: v
                    for k, v in data.items()
                    if k
                    not in (
                        "timestamp",
                        "time",
                        "level",
                        "severity",
                        "service",
                        "logger",
                        "message",
                        "msg",
                    )
                },
            )
        if fmt == "STANDARD":
            m = PATTERNS["STANDARD"].match(line)
            if m:
                return LogEntry(
                    timestamp=m.group("time"),
                    level=m.group("level").upper(),
                    service=m.group("service"),
                    message=m.group("message").strip(),
                    raw=line,
                )
        if fmt in ("NGINX", "APACHE"):
            m = PATTERNS[fmt].match(line)
            if m:
                status = int(m.group("status"))
                return LogEntry(
                    timestamp=m.group("time"),
                    level=status_to_level(status),
                    service=fmt.lower(),
                    message=f"{m.group('method')} {m.group('path')} {status}",
                    raw=line,
                    metadata={"ip": m.group("ip"), "status": m.group("status")},
                )
        if fmt == "HDFS":
            m = PATTERNS["HDFS"].match(line)
            if m:
                return LogEntry(
                    timestamp=f"{m.group('date')} {m.group('time')}",
                    level=_norm_level(m.group("level")),  # FATAL->CRITICAL
                    service=m.group("service").rstrip(":"),
                    message=m.group("message").strip(),
                    raw=line,
                    metadata={"pid": m.group("pid")},
                )
        if fmt == "SYSLOG":
            stripped = _PRI_RE.sub("", line)
            m = PATTERNS["SYSLOG"].match(stripped)
            if m:
                msg = m.group("message").strip()
                lvl = _syslog_level(line)
                if lvl == "INFO":
                    lvl = infer_level(msg)
                return LogEntry(
                    timestamp=m.group("time"),
                    level=lvl,
                    service=m.group("service").rstrip(":"),
                    message=msg,
                    raw=line,
                )
        if fmt == "LOGLENS":
            m = PATTERNS["LOGLENS"].match(line)
            if m:
                return LogEntry(
                    timestamp=m.group("time"),
                    level=m.group("level").upper(),
                    service=m.group("service").strip("[]"),
                    message=m.group("message").strip(),
                    raw=line,
                )
        if fmt in ("APP_LOG", "ZK_LOG", "SPARK_LOG"):
            m = PATTERNS[fmt].match(line)
            if m:
                gd = m.groupdict()
                svc = (gd.get("service") or "").strip() or "zookeeper"
                return LogEntry(
                    timestamp=m.group("time"),
                    level=_norm_level(m.group("level")),
                    service=svc,
                    message=m.group("message").strip(),
                    raw=line,
                    metadata={"thread": gd.get("thread", "")},
                )
        if fmt == "APACHE_ERR":
            m = PATTERNS["APACHE_ERR"].match(line)
            if m:
                return LogEntry(
                    timestamp=m.group("time"),
                    level=_norm_level(m.group("level")),
                    service="apache",
                    message=m.group("message").strip(),
                    raw=line,
                )
        if fmt == "WINCBS":
            m = PATTERNS["WINCBS"].match(line)
            if m:
                return LogEntry(
                    timestamp=m.group("time"),
                    level=_norm_level(m.group("level")),
                    service=m.group("service"),
                    message=m.group("message").strip(),
                    raw=line,
                )
        if fmt == "HPC":
            m = PATTERNS["HPC"].match(line)
            if m:
                msg = m.group("message").strip()
                return LogEntry(
                    timestamp=m.group("date"),
                    level=infer_level(msg),
                    service=m.group("node"),
                    message=msg,
                    raw=line,
                    metadata={"alert_label": m.group("label")},
                )
        if fmt == "HEALTHAPP":
            m = PATTERNS["HEALTHAPP"].match(line)
            if m:
                return LogEntry(
                    timestamp=m.group("time"),
                    level=infer_level(m.group("message")),
                    service=m.group("service").strip(),
                    message=m.group("message").strip(),
                    raw=line,
                )
        if fmt == "PROXIFIER":
            m = PATTERNS["PROXIFIER"].match(line)
            if m:
                return LogEntry(
                    timestamp=m.group("time"),
                    level=infer_level(m.group("message")),
                    service=m.group("service").strip(),
                    message=m.group("message").strip(),
                    raw=line,
                )
        if fmt == "KUBE":
            entry = _parse_kube(line)
            if entry is not None:
                return entry
        if fmt == "LOGFMT":
            return _parse_logfmt(line)
        if fmt == "GENERIC":
            entry = _parse_generic(line, layout)
            if entry is not None:
                return entry
        return LogEntry(
            timestamp="",
            level=infer_level(line),
            service="unknown",
            message=line,
            raw=line,
            parsed=False,
        )
    except Exception as exc:
        # Never let one malformed line abort a whole file — degrade to an
        # unparsed entry. Logged at debug since noisy logs are the norm.
        logger.debug("parse fell back to raw (%s: %s)", type(exc).__name__, exc)
        return LogEntry(
            timestamp="",
            level="INFO",
            service="unknown",
            message=line,
            raw=line,
            parsed=False,
        )


def _sniff_generic_layout(samples: list[str]) -> dict:
    with_level = 0
    cands: list[str] = []
    for s in samples:
        m = _GENERIC_TS.match(s)
        if not m:
            continue
        tokens = s[m.end() :].strip().split()
        if not tokens:
            continue
        idx = 0
        first = tokens[0].strip("[]").rstrip(":")
        if first.lower() in _LEVEL_TOKENS:
            with_level += 1
            idx = 1
        if idx < len(tokens) and (len(tokens) - idx) >= 2:
            cands.append(tokens[idx].rstrip(":"))

    has_level = bool(samples) and with_level >= 0.6 * len(samples)
    service_col = False
    if len(cands) >= 3:
        distinct = set(cands)
        id_like = sum(1 for c in cands if _COMPONENT_RE.match(c))
        low_cardinality = len(distinct) <= 40 and len(distinct) <= 0.5 * len(cands)
        mostly_id = id_like >= 0.8 * len(cands)
        service_col = low_cardinality and mostly_id
    return {"service_col": service_col, "has_level": has_level}


def sniff_format(lines: list[str], sample: int = 200) -> tuple[str, float, dict]:
    counts: dict[str, int] = {}
    seen: list[tuple[str, str]] = []
    for raw in lines:
        s = raw.strip()
        if not s:
            continue
        f = detect_format(s)
        counts[f] = counts.get(f, 0) + 1
        seen.append((s, f))
        if len(seen) >= sample:
            break
    if not seen:
        return "PLAINTEXT", 0.0, {}
    # Prefer a concrete format over the PLAINTEXT/UNKNOWN catch-alls when a real
    # one is present on a meaningful share of lines (headers/blank noise aside).
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    fmt, hits = ranked[0]
    if fmt in ("PLAINTEXT", "UNKNOWN"):
        for cand, n in ranked:
            if cand not in ("PLAINTEXT", "UNKNOWN") and n >= 0.4 * len(seen):
                fmt, hits = cand, n
                break
    confidence = round(hits / len(seen), 3)
    layout: dict = {}
    if fmt == "GENERIC":
        layout = _sniff_generic_layout([s for s, f in seen if f == "GENERIC"])
    return fmt, confidence, layout


_CONTINUATION_RE = re.compile(
    r"^[ \t]+\S"
    r"|^(?:at\s+\S"
    r"|Caused by:"
    r"|\.\.\.\s*\d+\s+more"
    r"|Traceback \(most recent call last\)"
    r"|File \")"
)

_MAX_CONTINUATION = 200


class StreamParser:
    def __init__(self, fmt: str | None = None):
        self.forced_fmt = fmt
        self.sticky: str | None = fmt
        self.first_format: str | None = None
        self._pending: LogEntry | None = None
        self._pending_continuations = 0
        self.stats = {
            "lines": 0,
            "blank": 0,
            "continuations": 0,
            "fallback": 0,
            "format_switches": 0,
        }

    def _sticky_matches(self, line: str) -> bool:
        fmt = self.sticky
        if fmt is None:
            return False
        if fmt == "JSON":
            return line.lstrip().startswith("{")
        if fmt in ("PLAINTEXT", "UNKNOWN"):
            return False
        probe = _PRI_RE.sub("", line)
        if fmt == "GENERIC":
            return bool(_GENERIC_TS.match(probe))
        if fmt == "LOGFMT":
            return _is_logfmt(probe)
        pattern = PATTERNS.get(fmt)
        return bool(pattern and pattern.match(probe))

    def _format_for(self, line: str) -> str:
        if self.forced_fmt:
            return self.forced_fmt
        if self._sticky_matches(line):
            assert self.sticky is not None  # _sticky_matches is False when sticky is None
            return self.sticky
        detected = detect_format(line)
        if detected in ("PLAINTEXT", "UNKNOWN"):
            return self.sticky or detected
        if self.sticky is not None and detected != self.sticky:
            self.stats["format_switches"] += 1
        self.sticky = detected
        return detected

    def feed(self, line: str) -> LogEntry | None:
        self.stats["lines"] += 1
        if not line.strip():
            self.stats["blank"] += 1
            return None

        if (
            self._pending is not None
            and self._pending_continuations < _MAX_CONTINUATION
            and _CONTINUATION_RE.match(line)
        ):
            self._pending.message += " | " + line.strip()
            self._pending.raw += "\n" + line.rstrip("\n")
            self._pending_continuations += 1
            self.stats["continuations"] += 1
            return None

        fmt = self._format_for(line)
        if self.first_format is None:
            self.first_format = fmt
        entry = parse_line(line, fmt)
        if entry is not None and not entry.parsed:
            self.stats["fallback"] += 1

        completed, self._pending = self._pending, entry
        self._pending_continuations = 0
        return completed

    def flush(self) -> LogEntry | None:
        completed, self._pending = self._pending, None
        return completed

    def parse_all(self, lines: Iterable[str]) -> Iterator[LogEntry]:
        for line in lines:
            entry = self.feed(line)
            if entry is not None:
                yield entry
        entry = self.flush()
        if entry is not None:
            yield entry
