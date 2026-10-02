from __future__ import annotations

import os

from loglens.application.parallel_scan import parallel_analyze_file


def _log(name):
    return os.path.join("testlogs", name)


def test_runs_and_merges_single_worker():
    r = parallel_analyze_file(_log("error_burst.log"), mode="fast", workers=1)
    assert r["lines_parsed"] == 380
    assert r["anomaly_count"] > 0
    assert r["approximate"] is True
    assert r["faulted_slices"] == 0
    # merged top anomalies are sorted worst-first
    scores = [a["score"] for a in r["top_anomalies"]]
    assert scores == sorted(scores, reverse=True)


def test_multi_slice_completes_and_covers_all_lines():
    r = parallel_analyze_file(_log("rate_burst.log"), mode="fast", workers=4)
    # every line is covered exactly once across slices (byte-range split is a partition)
    assert r["lines_parsed"] == 410
    assert r["slices"] >= 1


def test_progress_callback_fires():
    seen = []
    parallel_analyze_file(
        _log("hdfs_sessions.log"),
        mode="fast",
        workers=3,
        on_progress=lambda done, total: seen.append((done, total)),
    )
    assert seen, "progress callback never fired"
    # completes to total
    assert seen[-1][0] == seen[-1][1]


def test_deterministic():
    a = parallel_analyze_file(_log("service_outage.log"), mode="fast", workers=2)
    b = parallel_analyze_file(_log("service_outage.log"), mode="fast", workers=2)
    assert a["anomaly_count"] == b["anomaly_count"]
    assert a["top_anomalies"] == b["top_anomalies"]
    assert a["lines_parsed"] == b["lines_parsed"]