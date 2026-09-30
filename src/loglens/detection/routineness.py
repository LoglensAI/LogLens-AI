from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

from loglens.detection.templates import template_key


@dataclass
class Routineness:
    r: float | None
    status: str
    features: dict[str, float] = field(default_factory=dict)
    note: str = ""
    count: int = 0

    @property
    def features_used(self) -> list[str]:
        return sorted(self.features)


def _entropy_norm(labels: list[str]) -> float | None:
    counts = Counter(x for x in labels if x)
    k = len(counts)
    if k < 2:
        return None
    total = sum(counts.values())
    h = -sum((c / total) * math.log(c / total) for c in counts.values())
    return h / math.log(k)


def _note_for(r: float | None, status: str) -> str:
    if r is None:
        return "routineness unknown (too few occurrences)"
    band = "routine" if r >= 0.66 else ("emerging/rare" if r <= 0.33 else "mixed-routineness")
    return f"{band} pattern (R={r:.2f}, {status})"


def compute_routineness(
    entries: list,
    *,
    baseline: dict | None = None,
    buckets: int = 24,
    min_count: int = 5,
) -> dict[str, Routineness]:

    n = len(entries)
    buckets = max(1, buckets)
    known: set[str] = set()
    if baseline and isinstance(baseline.get("templates"), dict):
        known = {k.split("|", 1)[-1] for k in baseline["templates"]}

    positions: dict[str, list[int]] = {}
    services: dict[str, list[str]] = {}
    for i, e in enumerate(entries):
        tk = template_key(getattr(e, "message", "") or "")
        positions.setdefault(tk, []).append(i)
        services.setdefault(tk, []).append(getattr(e, "service", "") or "")

    out: dict[str, Routineness] = {}
    for tk, pos in positions.items():
        c = len(pos)
        if c < min_count or n <= 1:
            out[tk] = Routineness(
                r=None, status="unknown", note=_note_for(None, "unknown"), count=c
            )
            continue

        feats: dict[str, float] = {}

        nb = min(buckets, n)
        seen_buckets = {min(int(p / n * nb), nb - 1) for p in pos}
        feats["stationarity"] = len(seen_buckets) / nb

        hs = _entropy_norm(services[tk])
        if hs is not None:
            feats["host_spread"] = hs

        if tk in known:
            feats["age"] = 1.0
        else:
            feats["age"] = (pos[-1] - pos[0]) / (n - 1)

        bcounts = Counter(min(int(p / n * nb), nb - 1) for p in pos)
        concentration = max(bcounts.values()) / c
        feats["independence"] = 1.0 - concentration

        r = sum(feats.values()) / len(feats)
        status = "measured" if len(feats) == 4 else f"partial({len(feats)}/4)"
        out[tk] = Routineness(
            r=r, status=status, features=feats, note=_note_for(r, status), count=c
        )
    return out


_CONF_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Unknown": 0}


def confidence_label(score: float, r: Routineness | None) -> tuple[str, float]:
    adj = float(score)
    if r is not None and r.r is not None:
        adj = max(0.0, score - 0.35 * r.r)
    if adj >= 0.85:
        label = "High"
    elif adj >= 0.65:
        label = "Medium"
    else:
        label = "Low"
    if r is None or r.r is None:
        label = f"{label} (R n/a)"
    return label, adj
