from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

import numpy as np

from loglens.detection.templates import template_key
from loglens.domain.models import LogEntry
from loglens.domain.severity import get_severity

_FLOOR_SCORE = 0.70
_ERROR_SEV = 3


def _tokens(template: str) -> set[str]:
    return {t for t in template.split() if t and not t.startswith("<")}


def _near_duplicate(tokens: set[str], common_tokensets: list[set[str]], thresh: float) -> bool:
    if not tokens:
        return False
    for other in common_tokensets:
        union = tokens | other
        if not union:
            continue
        if len(tokens & other) / len(union) >= thresh:
            return True
    return False


def safety_floor(
    entries: Sequence[LogEntry],
    scores: np.ndarray,
    *,
    rare_max: int = 3,
    common_min: int = 20,
    jaccard: float = 0.8,
    flag_at: float = 0.70,
) -> tuple[np.ndarray, list[list[str]], str]:
    n = len(entries)
    out = np.asarray(scores, dtype=np.float64).copy()
    reasons: list[list[str]] = [[] for _ in range(n)]
    if n == 0:
        return out, reasons, ""

    tmpl_of = [template_key(e.message or "") for e in entries]
    counts: dict[str, int] = defaultdict(int)
    for t in tmpl_of:
        counts[t] += 1
    common_tokensets = [_tokens(t) for t, c in counts.items() if c >= common_min]

    floor = max(flag_at, _FLOOR_SCORE) if flag_at > _FLOOR_SCORE else flag_at
    floored = 0
    surfaced_templates: set[str] = set()
    for i, e in enumerate(entries):
        if out[i] >= flag_at:
            continue
        if get_severity(e.level) > _ERROR_SEV:
            continue
        t = tmpl_of[i]
        if counts[t] > rare_max:
            continue
        if _near_duplicate(_tokens(t), common_tokensets, jaccard):
            continue
        out[i] = max(out[i], floor)
        reasons[i].append(
            f"safety floor: rare {e.level.upper()} template (seen {counts[t]}×), "
            "surfaced despite a low score"
        )
        floored += 1
        surfaced_templates.add(t)

    note = (
        f"safety floor: {floored} line(s) across {len(surfaced_templates)} rare severe template(s)"
        if floored
        else ""
    )
    return out, reasons, note
