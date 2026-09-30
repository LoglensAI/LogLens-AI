from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from loglens.detection.templates import template_key
from loglens.domain.models import Anomaly, LogEntry


def template_of(message: str) -> str:
    return template_key(message)


@dataclass
class AnomalyGroup:
    level: str
    service: str
    template: str
    sample: str
    count: int = 0
    max_score: float = 0.0
    indices: list[int] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def group_anomalies(
    anomalies: Sequence[LogEntry | Anomaly],
    scores: Sequence[float] | None = None,
    reasons: Sequence[list[str]] | None = None,
) -> list[AnomalyGroup]:
    groups: dict[tuple, AnomalyGroup] = {}
    for i, a in enumerate(anomalies):
        key = (a.level.upper(), a.service, template_of(a.message))
        g = groups.get(key)
        if g is None:
            g = groups[key] = AnomalyGroup(
                level=a.level.upper(), service=a.service, template=key[2], sample=a.message
            )
        g.count += 1
        g.indices.append(i)
        if scores is not None and i < len(scores):
            g.max_score = max(g.max_score, float(scores[i]))
        else:
            g.max_score = max(g.max_score, float(getattr(a, "anomaly_score", 0.0)))
        if reasons is not None and i < len(reasons) and not g.reasons:
            g.reasons = list(reasons[i])
        elif not g.reasons:
            g.reasons = list(getattr(a, "anomaly_reasons", []) or [])
    out = list(groups.values())
    out.sort(key=lambda g: (-g.max_score, -g.count, g.level, g.service, g.template))
    return out
