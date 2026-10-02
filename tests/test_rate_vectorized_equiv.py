from __future__ import annotations

from collections import defaultdict

import numpy as np

from loglens.detection.parser import parse_line, sniff_format
from loglens.detection.rate import _bin_count, rate_burst_scores
from loglens.detection.templates import template_key
from loglens.domain.models import LogEntry


def _reference(
    entries,
    *,
    min_count: int = 12,
    burst_min: int = 10,
    factor: float = 6.0,
    min_active_windows: int = 4,
    flag_at: float = 0.70,
):
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


def _assert_identical(entries):
    s1, r1, n1 = _reference(entries)
    s2, r2, n2 = rate_burst_scores(entries)
    assert np.array_equal(s1, s2), "scores diverged"
    assert r1 == r2, "reasons diverged"
    assert n1 == n2, "note diverged"


def _mk(level, msg, i):
    return LogEntry(timestamp=f"t{i}", level=level, service="svc", message=msg, raw=msg)


def test_empty_and_tiny():
    _assert_identical([])
    _assert_identical([_mk("INFO", "hello", i) for i in range(5)])


def test_steady_no_burst():
    entries = [_mk("INFO", f"request {i} ok", i) for i in range(500)]
    _assert_identical(entries)


def test_clear_burst():
    # a template that floods one region of the log
    entries = []
    for i in range(600):
        if 200 <= i < 260:
            entries.append(_mk("ERROR", "connection reset by peer", i))
        else:
            entries.append(_mk("INFO", f"heartbeat {i}", i))
    _assert_identical(entries)


def test_recurring_with_spike():
    entries = []
    for i in range(1000):
        if i % 20 == 0:
            entries.append(_mk("WARN", "retrying upstream call", i))
        elif 500 <= i < 540:
            entries.append(_mk("WARN", "retrying upstream call", i))
        else:
            entries.append(_mk("INFO", f"served {i}", i))
    _assert_identical(entries)


def test_real_testlogs():
    import glob
    import os

    for path in sorted(glob.glob("testlogs/*.log")):
        if os.path.getsize(path) > 2_000_000:
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = [ln.rstrip("\n") for ln in fh]
        fmt, _c, layout = sniff_format(raw[:200])
        entries = [e for ln in raw if (e := parse_line(ln, fmt, layout)) is not None]
        _assert_identical(entries)


def test_synthetic_large():
    from scripts.perf_bench import _gen

    raw = _gen(20000)
    fmt, _c, layout = sniff_format(raw[:200])
    entries = [e for ln in raw if (e := parse_line(ln, fmt, layout)) is not None]
    _assert_identical(entries)