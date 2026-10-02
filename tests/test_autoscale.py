from __future__ import annotations

import os

from loglens.application.autoscale import (
    DEFAULT_MAX_EXACT_LINES,
    estimate_lines,
    plan,
    plan_for_file,
)


def test_small_file_runs_exact():
    p = plan(est_lines=10_000, size_bytes=1_000_000, cores=12)
    assert p.strategy == "exact"
    assert p.workers == 1


def test_large_file_switches_to_scan():
    p = plan(est_lines=6_400_000, size_bytes=400_000_000, cores=12)
    assert p.strategy == "scan"
    assert p.parallel is True


def test_headroom_default_reserves_quarter():
    p = plan(est_lines=10_000_000, size_bytes=1, cores=12)
    assert p.reserved == 3  # ~25% of 12
    assert p.workers == 9


def test_headroom_explicit():
    p = plan(est_lines=10_000_000, size_bytes=1, cores=12, headroom=5)
    assert p.reserved == 5
    assert p.workers == 7


def test_headroom_cannot_starve_all_workers():
    p = plan(est_lines=10_000_000, size_bytes=1, cores=4, headroom=99)
    assert p.workers >= 1
    assert p.reserved == 3  # clamped so one worker remains


def test_single_core_runs_serial():
    p = plan(est_lines=10_000_000, size_bytes=1, cores=1)
    assert p.workers == 1
    assert p.reserved == 0


def test_custom_threshold():
    p = plan(est_lines=200_000, size_bytes=1, cores=8, max_exact_lines=100_000)
    assert p.strategy == "scan"
    p2 = plan(est_lines=200_000, size_bytes=1, cores=8)  # default 500k
    assert p2.strategy == "exact"


def test_force_overrides_heuristic():
    big = plan(est_lines=9_000_000, size_bytes=1, cores=8, force="exact")
    assert big.strategy == "exact"
    small = plan(est_lines=10, size_bytes=1, cores=8, force="scan")
    assert small.strategy == "scan"


def test_default_threshold_value():
    assert DEFAULT_MAX_EXACT_LINES == 500_000


def test_estimate_lines(tmp_path):
    f = tmp_path / "x.log"
    f.write_text("\n".join(f"line number {i} here" for i in range(5000)) + "\n")
    est, size = estimate_lines(str(f))
    assert size == os.path.getsize(str(f))
    # estimate within 10% of the true 5000
    assert 4500 <= est <= 5500


def test_empty_file():
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".log") as tf:
        est, size = estimate_lines(tf.name)
        assert est == 0 and size == 0
        p = plan_for_file(tf.name, cores=8)
        assert p.strategy == "exact"
