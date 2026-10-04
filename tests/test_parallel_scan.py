from __future__ import annotations

import os

from loglens.application.parallel_scan import _THREAD_VARS, parallel_analyze_file


def _log(name):
    return os.path.join("testlogs", name)


def test_runs_and_groups_into_families_single_worker():
    r = parallel_analyze_file(_log("error_burst.log"), mode="fast", workers=1)
    assert r["lines_parsed"] == 380
    assert r["family_count"] >= 1
    assert r["anomaly_lines"] >= 1
    assert r["approximate"] is True
    assert r["faulted_slices"] == 0
    # families sorted worst-first
    scores = [f["score"] for f in r["families"]]
    assert scores == sorted(scores, reverse=True)
    # each family has the fields the explorer will need
    f = r["families"][0]
    for key in ("level", "template", "count", "score", "services", "first_ts", "last_ts"):
        assert key in f


def test_multi_slice_covers_all_lines():
    r = parallel_analyze_file(_log("rate_burst.log"), mode="fast", workers=4, oversplit=3)
    # byte-range split is a partition → every line counted once
    assert r["lines_parsed"] == 410
    assert r["slices"] >= 4


def test_progress_fires_many_steps():
    seen = []
    parallel_analyze_file(
        _log("hdfs_sessions.log"),
        mode="fast",
        workers=2,
        oversplit=4,
        on_progress=lambda done, total: seen.append((done, total)),
    )
    assert seen, "progress never fired"
    assert seen[-1][0] == seen[-1][1]  # completes to total
    # oversplit → more steps than workers, so ETA can appear early
    assert seen[-1][1] >= 4


def test_thread_caps_are_set():
    parallel_analyze_file(_log("service_outage.log"), mode="fast", workers=2)
    for v in _THREAD_VARS:
        assert os.environ.get(v) == "1"


def test_deterministic():
    a = parallel_analyze_file(_log("service_outage.log"), mode="fast", workers=2, oversplit=2)
    b = parallel_analyze_file(_log("service_outage.log"), mode="fast", workers=2, oversplit=2)
    assert a["family_count"] == b["family_count"]
    assert a["families"] == b["families"]
    assert a["lines_parsed"] == b["lines_parsed"]
