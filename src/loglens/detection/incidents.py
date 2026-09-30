from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

_SEVERE = {"CRITICAL", "FATAL", "ERROR"}
_ORIGIN_RANK = {"system": 3, "upstream_service": 2, "dependency": 1, "your_code": 0, "unknown": 0}
_SEV_RANK = {"FATAL": 4, "CRITICAL": 3, "ERROR": 2, "WARNING": 1, "WARN": 1, "INFO": 0}


@dataclass
class Family:
    template_id: str
    level: str
    service: str
    count: int = 1
    first_dt: datetime | None = None
    last_dt: datetime | None = None
    origin: str = "unknown"
    origin_detail: str | None = None
    message: str = ""


@dataclass
class Incident:
    id: str
    family_ids: list[str] = field(default_factory=list)
    root_cause_id: str = ""
    root_cause_message: str = ""
    root_cause_origin: str = "unknown"
    root_cause_detail: str | None = None
    services: list[str] = field(default_factory=list)
    first_dt: datetime | None = None
    last_dt: datetime | None = None
    span_seconds: int = 0
    events: int = 0
    level: str = ""


def _incident_id(source: str, template_ids: list[str]) -> str:
    key = source + "|" + "|".join(sorted(template_ids))
    return "inc_" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:10]


def _root_cause(fams: list[Family]) -> Family:
    _min = datetime.min
    return sorted(
        fams,
        key=lambda f: (
            -_ORIGIN_RANK.get(f.origin, 0),
            (f.first_dt or _min),
            -_SEV_RANK.get(f.level.upper(), 0),
            f.template_id,
        ),
    )[0]


def _finish(source: str, fams: list[Family]) -> Incident:
    ids = [f.template_id for f in fams]
    root = _root_cause(fams)
    firsts = [f.first_dt for f in fams if f.first_dt is not None]
    lasts = [d for f in fams if (d := (f.last_dt or f.first_dt)) is not None]
    first_dt = min(firsts) if firsts else None
    last_dt = max(lasts) if lasts else None
    span = int((last_dt - first_dt).total_seconds()) if (first_dt and last_dt) else 0
    services: list[str] = []
    for f in sorted(fams, key=lambda f: (f.first_dt or datetime.min, f.template_id)):
        if f.service and f.service not in services:
            services.append(f.service)
    level = max((f.level.upper() for f in fams), key=lambda lv: _SEV_RANK.get(lv, 0))
    return Incident(
        id=_incident_id(source, ids),
        family_ids=sorted(ids),
        root_cause_id=root.template_id,
        root_cause_message=root.message,
        root_cause_origin=root.origin,
        root_cause_detail=root.origin_detail,
        services=services,
        first_dt=first_dt,
        last_dt=last_dt,
        span_seconds=span,
        events=sum(f.count for f in fams),
        level=level,
    )


def group_incidents(
    families: list[Family], *, source: str = "", gap_seconds: float = 300.0
) -> tuple[list[Incident], dict[str, str]]:
    severe = [f for f in families if f.level.upper() in _SEVERE]
    if not severe:
        return [], {}

    dated = [f for f in severe if f.first_dt is not None]
    undated = [f for f in severe if f.first_dt is None]

    incidents: list[Incident] = []
    if dated:
        dated.sort(key=lambda f: (f.first_dt or datetime.min, f.template_id))
        cur: list[Family] = [dated[0]]
        cur_last = dated[0].last_dt or dated[0].first_dt
        for f in dated[1:]:
            start = f.first_dt
            if (
                cur_last is not None
                and start is not None
                and (start - cur_last).total_seconds() <= gap_seconds
            ):
                cur.append(f)
                end = f.last_dt or f.first_dt
                if end is not None and (cur_last is None or end > cur_last):
                    cur_last = end
            else:
                incidents.append(_finish(source, cur))
                cur = [f]
                cur_last = f.last_dt or f.first_dt
        incidents.append(_finish(source, cur))

    if undated:
        incidents.append(_finish(source, undated))

    mapping: dict[str, str] = {}
    for inc in incidents:
        for tid in inc.family_ids:
            mapping[tid] = inc.id
    return incidents, mapping
