from __future__ import annotations

import glob
import os

import numpy as np
import pytest

import loglens.detection.detector as D
from loglens.detection.parser import parse_line, sniff_format
from loglens.detection.run import RunConfig, run


def _load(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = [ln.rstrip("\n") for ln in fh]
    fmt, _c, layout = sniff_format(raw[:200])
    return [e for ln in raw if (e := parse_line(ln, fmt, layout)) is not None]


def _fixtures():
    out = []
    for path in sorted(glob.glob("testlogs/*.log")):
        if os.path.getsize(path) > 2_000_000:
            continue
        entries = _load(path)
        if entries:
            out.append((os.path.basename(path), entries))
    return out


def _run_both(entries, mode="fast"):
    try:
        D._SCORE_CACHE_ENABLED = True
        on = run(entries, RunConfig(mode=mode))
        D._SCORE_CACHE_ENABLED = False
        off = run(entries, RunConfig(mode=mode))
    finally:
        D._SCORE_CACHE_ENABLED = True
    return on, off


@pytest.mark.parametrize("name,entries", _fixtures())
def test_cache_byte_identical_real_logs(name, entries):
    on, off = _run_both(entries)
    assert np.array_equal(on.scores, off.scores), f"{name}: scores differ"
    assert on.reasons == off.reasons, f"{name}: reasons differ"
    assert np.array_equal(on.flagged, off.flagged), f"{name}: flags differ"


def test_cache_byte_identical_synthetic():
    from scripts.perf_bench import _gen

    raw = _gen(20000)
    fmt, _c, layout = sniff_format(raw[:200])
    entries = [e for ln in raw if (e := parse_line(ln, fmt, layout)) is not None]
    on, off = _run_both(entries)
    assert np.array_equal(on.scores, off.scores)
    assert on.reasons == off.reasons
    assert np.array_equal(on.flagged, off.flagged)


def test_cache_default_enabled():
    assert D._SCORE_CACHE_ENABLED is True
