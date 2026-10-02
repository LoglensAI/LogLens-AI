from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Sequence

import numpy as np

from loglens.detection.templates import template_key
from loglens.domain.models import LogEntry

_STRUCTURAL = [
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    re.compile(r"\b0[xX][0-9a-fA-F]+\b"),
    re.compile(r"\b[0-9a-fA-F]{12,}\b"),
    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{2,5})?\b"),  # ip[:port]
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][\d:]{5,8}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b"),  # ISO ts
    re.compile(r'"[^"]*"'),
    re.compile(r"'[^']*'"),
]
_NUM_TOKEN = re.compile(r"^([0-9][0-9,]*(?:\.\d+)?)([A-Za-z%]{0,4})$")


def numeric_slots(message: str) -> list[float]:
    t = message.strip()
    for pat in _STRUCTURAL:
        t = pat.sub(" ", t)
    vals: list[float] = []
    for tok in t.split():
        tok = tok.strip(",;:()[]{}<>=\"'")
        m = _NUM_TOKEN.match(tok)
        if m:
            try:
                vals.append(float(m.group(1).replace(",", "")))
            except ValueError:
                continue
    return vals


def _fmt(x: float) -> str:
    return str(int(x)) if x == int(x) else f"{x:.2f}"


def parameter_anomaly_scores(
    entries: Sequence[LogEntry],
    *,
    min_group: int = 12,
    z_cutoff: float = 5.0,
    min_ratio: float = 3.0,
    flag_at: float = 0.70,
    template_keys: Sequence[str] | None = None,
) -> tuple[np.ndarray, list[list[str]], str]:
    
    n = len(entries)
    scores = np.zeros(n, dtype=np.float64)
    reasons: list[list[str]] = [[] for _ in range(n)]
    if n == 0:
        return scores, reasons, ""

    groups: dict[str, list[int]] = defaultdict(list)
    if template_keys is not None:
        for i, k in enumerate(template_keys):
            groups[k].append(i)
    else:
        for i, e in enumerate(entries):
            groups[template_key(e.message or "")].append(i)

    flagged = 0
    for idxs in groups.values():
        if len(idxs) < min_group:
            continue
        slotlists = {i: numeric_slots(entries[i].message or "") for i in idxs}
        counts = [len(slotlists[i]) for i in idxs]
        common = Counter(counts).most_common(1)[0][0]  # the usual slot count
        if common == 0:
            continue
        members = [i for i in idxs if len(slotlists[i]) == common]
        if len(members) < min_group:
            continue
        for slot in range(common):
            vals = np.array([slotlists[i][slot] for i in members], dtype=np.float64)
            med = float(np.median(vals))
            mad = float(np.median(np.abs(vals - med)))
            if mad <= 0:  # a steady/constant slot — nothing to flag
                continue
            for i in members:
                x = slotlists[i][slot]
                z = 0.6745 * abs(x - med) / mad 
                ratio = abs(x - med) / max(abs(med), 1.0)
                if z >= z_cutoff and ratio >= min_ratio:
                    score = min(1.0, 0.7 + 0.3 * min(1.0, (z - z_cutoff) / z_cutoff))
                    if score > scores[i]:
                        scores[i] = score
                    reasons[i].append(
                        f"parameter anomaly: value {_fmt(x)} vs typical "
                        f"{_fmt(med)} for this template (robust z={z:.0f})"
                    )
                    if score >= flag_at:
                        flagged += 1

    note = f"parameters: {flagged} value outlier(s) across {len(groups)} templates"
    return scores, reasons, note