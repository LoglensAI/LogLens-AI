from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

import numpy as np

from loglens.detection.templates import template_key
from loglens.domain.models import LogEntry


def _bin_count(n: int) -> int:
    return max(8, min(80, n // 10))


def cooccurrence_boost(
    entries: Sequence[LogEntry],
    base_scores: np.ndarray,
    *,
    min_partners: int = 2,
    elevate_floor: int = 3,
    base_gate: float = 0.40,
    boost: float = 0.30,
    flag_at: float = 0.70,
    template_keys: Sequence[str] | None = None,
) -> tuple[np.ndarray, list[list[str]], str]:
    n = len(entries)
    scores = np.asarray(base_scores, dtype=np.float64).copy()
    reasons: list[list[str]] = [[] for _ in range(n)]
    if n < 2 * elevate_floor:
        return scores, reasons, ""

    n_bins = _bin_count(n)
    bin_of = [min(n_bins - 1, i * n_bins // n) for i in range(n)]

    if template_keys is not None:
        tmpl_of = list(template_keys)
    else:
        tmpl_of = [template_key(e.message or "") for e in entries]
    counts: dict[tuple[int, str], list[int]] = defaultdict(list)
    per_template_total: dict[str, int] = defaultdict(int)
    for i in range(n):
        counts[(bin_of[i], tmpl_of[i])].append(i)
        per_template_total[tmpl_of[i]] += 1

    elevated: dict[int, list[tuple[str, set[str]]]] = defaultdict(list)
    for (b, tmpl), idxs in counts.items():
        avg = per_template_total[tmpl] / n_bins
        if len(idxs) >= max(elevate_floor, 2 * avg):
            hosts = {(entries[i].service or "unknown") for i in idxs}
            elevated[b].append((tmpl, hosts))

    boosted = 0
    incident_windows = 0
    for b, tmpls in elevated.items():
        if len(tmpls) < min_partners:
            continue
        all_hosts = {h for _t, hs in tmpls for h in hs}
        hostless = all_hosts <= {"unknown"}
        overlapping: list[str] = []
        if hostless:
            overlapping = [t for t, _hs in tmpls]
        else:
            for t, hs in tmpls:
                if any(t2 != t and (hs & hs2) for t2, hs2 in tmpls):
                    overlapping.append(t)
        if len(overlapping) < min_partners:
            continue
        incident_windows += 1
        partner_set = set(overlapping)
        for t in overlapping:
            for i in counts[(b, t)]:
                if scores[i] >= base_gate and scores[i] < 1.0:
                    new = min(1.0, scores[i] + boost)
                    if new > scores[i]:
                        scores[i] = new
                        if scores[i] >= flag_at:
                            boosted += 1
                        others = len(partner_set) - 1
                        reasons[i].append(
                            f"incident: co-occurs with {others} other "
                            f"template(s) bursting in the same window"
                        )

    note = (
        f"co-occurrence: {incident_windows} incident window(s), {boosted} line(s) lifted"
        if incident_windows
        else ""
    )
    return scores, reasons, note