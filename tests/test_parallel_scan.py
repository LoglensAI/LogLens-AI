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


def test_supervised_head_in_parallel_path(tmp_path):
    """The supervised head must apply per-slice when a model is given — delivers
    auto-scale / --parallel for the model, not just unsupervised detection."""
    from loglens.detection.benchmark import load_labeled, train_and_save

    # Train a tiny head on a labeled fixture.
    labeled = tmp_path / "bgl.log"
    normal = "\n".join(
        f"- 2024-01-01 00:{i // 60:02d}:{i % 60:02d} INFO api ok id={i}" for i in range(80)
    )
    anom = "\n".join(f"K 2024-01-01 01:{i:02d}:00 FATAL db pool exhausted {i}" for i in range(20))
    labeled.write_text(normal + "\n" + anom + "\n", encoding="utf-8")
    model = tmp_path / "head.pkl"
    entries, labels = load_labeled(str(labeled), fmt="bgl")
    train_and_save(entries, labels, str(model))

    # Unsupervised parallel vs supervised parallel on the same file.
    base = parallel_analyze_file(_log("incident_heavy.log"), mode="fast", workers=2)
    sup = parallel_analyze_file(
        _log("incident_heavy.log"), mode="fast", workers=2, model=str(model)
    )
    assert base["supervised"] is False
    assert sup["supervised"] is True
    assert sup["model"] == str(model)
    # both cover the same lines (the split is a partition either way)
    assert sup["lines_parsed"] == base["lines_parsed"]


def test_run_parallel_total_failure_retries_then_exits(monkeypatch, tmp_path, capsys):
    """If every slice faults (workers killed), _run_parallel retries with fewer
    workers and, if it still can't parse a line, exits non-zero instead of
    printing a bogus '✓ completed'."""
    import pytest
    import typer

    from loglens.application import parallel_scan as ps
    from loglens.interface import cli

    src = tmp_path / "big.log"
    src.write_text("\n".join(f"line {i}" for i in range(100)) + "\n")

    calls = []

    def fake(path, *, mode, workers, limit, model, on_progress=None, on_event=None):
        calls.append(workers)
        if on_progress:
            on_progress(workers, workers)
        return {  # total failure: faults, zero lines parsed
            "slices": workers,
            "workers": workers,
            "lines_parsed": 0,
            "anomaly_lines": 0,
            "family_count": 0,
            "by_level": {},
            "incident": False,
            "faulted_slices": workers,
            "families": [],
            "top_lines": [],
            "supervised": False,
            "model": "",
            "format": "x",
            "display_limit": limit,
        }

    monkeypatch.setattr(ps, "parallel_analyze_file", fake)

    with pytest.raises(typer.Exit) as ei:
        cli._run_parallel(
            str(src), mode="fast", workers=8, headroom=None, limit=20, as_json=True, started=0.0
        )
    assert ei.value.exit_code == 1
    # it retried with progressively fewer workers (8 → 4 → 2 → 1)
    assert calls == [8, 4, 2, 1]
