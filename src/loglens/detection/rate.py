from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

import numpy as np

from loglens.detection.templates import template_key
from loglens.domain.models import LogEntry


def _bin_count(n: int) -> int:
    return max(10, min(80, n // 10))


def rate_burst_scores(
    entries: Sequence[LogEntry],
    *,
    min_count: int = 12,
    burst_min: int = 10,
    factor: float = 6.0,
    min_active_windows: int = 4,
    flag_at: float = 0.70,
) -> tuple[np.ndarray, list[list[str]], str]:

    n = len(entries)
    scores = np.zeros(n, dtype=np.float64)
    reasons: list[list[str]] = [[] for _ in range(n)]
    if n < 2 * burst_min:
        return scores, reasons, ""

    n_bins = _bin_count(n)
    bin_of = [min(n_bins - 1, i * n_bins // n) for i in range(n)]

    by_template: dict[str, list[int]] = defaultdict(list)
    for i, e in enumerate(entries):
        by_template[template_key(e.message or "")].append(i)

    bursts = 0
    for idxs in by_template.values():
        total = len(idxs)
        if total < min_count:
            continue
        counts = np.zeros(n_bins, dtype=np.int64)
        for i in idxs:
            counts[bin_of[i]] += 1
        active = counts[counts > 0]
        if active.size < min_active_windows:
            continue
        baseline = float(np.median(active))
        threshold = max(float(burst_min), factor * baseline)
        burst_bins = {b for b in range(n_bins) if counts[b] >= threshold}
        if not burst_bins:
            continue
        bursts += 1
        for i in idxs:
            b = bin_of[i]
            if b in burst_bins:
                ratio = counts[b] / max(baseline, 1.0)
                score = min(1.0, 0.7 + 0.3 * min(1.0, (ratio - factor) / factor))
                if score > scores[i]:
                    scores[i] = score
                if not reasons[i]:
                    reasons[i].append(
                        f"rate burst: this message fired {int(counts[b])}× in one window "
                        f"vs a usual {baseline:.0f} (×{ratio:.0f} its normal rate)"
                    )

    note = f"rate: {bursts} template(s) with a burst window" if bursts else ""
    return scores, reasons, note
