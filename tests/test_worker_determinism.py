"""The answer must not depend on how many workers (cores) did the work.

Regression tests for two bugs found in the Stage 1 QA audit, where the same
1M-line file gave different anomaly counts at different --workers values:

* turbo detected the log format from the first line of *each chunk*. A chunk
  starting on a stack-trace line was parsed as PLAINTEXT, which changed every
  template key in it (more workers -> more chunk boundaries -> more such chunks).
* the parallel scan cut ``workers * 4`` slices and ran the detector per slice,
  so the slice size -- and with it what counts as "rare" -- changed with workers.
"""

from __future__ import annotations

import pytest

from loglens.application.parallel_scan import (
    DEFAULT_SLICE_LINES,
    parallel_analyze_file,
    plan_slice_count,
)
from loglens.detection.turbo import scan_file

TRACE = "    at com.acme.pay.Gateway.charge(Gateway.java:142)"


@pytest.fixture
def java_style_log(tmp_path):
    """Generic app log where every other line is a stack-trace continuation, so
    chunk boundaries are very likely to land on one."""
    out = []
    for i in range(4000):
        lvl = "ERROR" if i % 97 == 0 else "INFO"
        out.append(f"2024-01-01 00:{i // 60 % 60:02d}:{i % 60:02d} {lvl} api request {i} handled")
        out.append(TRACE)
    out.append("2024-01-01 01:00:00 FATAL db kernel panic not syncing")
    p = tmp_path / "java.log"
    p.write_text("\n".join(out) + "\n", encoding="utf-8")
    return str(p)


def _turbo_signature(res):
    return [(t.level, t.template, t.count, t.score) for t in res.templates]


def test_turbo_same_result_for_any_worker_count(java_style_log):
    base = scan_file(java_style_log, workers=1)
    for w in (2, 3, 5, 7, 11):
        res = scan_file(java_style_log, workers=w)
        assert res.parsed_lines == base.parsed_lines, f"workers={w}"
        assert _turbo_signature(res) == _turbo_signature(base), f"workers={w}"
        assert len(res.anomalies()) == len(base.anomalies()), f"workers={w}"


def test_turbo_still_finds_the_fatal(java_style_log):
    res = scan_file(java_style_log, workers=5)
    assert any("kernel panic" in t.sample for t in res.anomalies())


def _scan_signature(r):
    return (
        r["slices"],
        r["lines_parsed"],
        r["anomaly_lines"],
        [(f["level"], f["template"], f["count"], f["score"]) for f in r["families"]],
    )


@pytest.mark.parametrize("log", ["rate_burst.log", "hdfs_sessions.log", "error_burst.log"])
def test_parallel_scan_same_result_for_any_worker_count(log):
    path = f"testlogs/{log}"
    base = parallel_analyze_file(path, mode="fast", workers=1, slice_lines=60)
    assert base["slices"] > 1  # the test is only meaningful with several slices
    for w in (2, 3, 5):
        r = parallel_analyze_file(path, mode="fast", workers=w, slice_lines=60)
        assert _scan_signature(r) == _scan_signature(base), f"workers={w}"


def test_slice_count_depends_on_file_not_workers():
    # 1M lines of ~55 bytes -> 40 slices of 25k lines, whatever the machine.
    assert plan_slice_count(55_000_000, 55.0, DEFAULT_SLICE_LINES) == 40
    assert plan_slice_count(1_000, 50.0, DEFAULT_SLICE_LINES) == 1
    assert plan_slice_count(0, 50.0, DEFAULT_SLICE_LINES) == 1
    assert plan_slice_count(1_000, 0.0, DEFAULT_SLICE_LINES) == 1
