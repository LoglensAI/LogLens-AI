from __future__ import annotations

from loglens.application.results_store import (
    SEVERITY_MENU,
    TIME_WINDOWS,
    canonical_bucket,
    families_in_window,
    hour_bucket,
    load_results,
    save_results,
    severity_breakdown,
    severity_count,
    to_epoch,
)


def test_to_epoch_bgl_and_iso():
    assert to_epoch("2005-06-04-00.24.37.928478") is not None
    assert to_epoch("2024-01-01T12:00:00Z") is not None
    assert to_epoch("2024-01-01 12:00:00") is not None
    assert to_epoch("not a timestamp") is None
    assert to_epoch("") is None
    # BGL and ISO of the same instant agree
    assert to_epoch("2005-06-04-00.24.37.000000") == to_epoch("2005-06-04 00:24:37")


def test_canonical_bucket_folds_levels():
    assert canonical_bucket("FATAL") == "CRITICAL"
    assert canonical_bucket("SEVERE") == "CRITICAL"
    assert canonical_bucket("WARNING") == "WARN"
    assert canonical_bucket("err") == "ERROR"


def _make_result():
    # Log 'ends' at hour bucket 1000 (epoch 1000*3600). Build a level×hour hist.
    last = 1000 * 3600
    hist = {
        "CRITICAL": {str(hour_bucket(last)): 5, str(hour_bucket(last - 2 * 3600)): 3},
        "INFO": {str(hour_bucket(last)): 100, str(hour_bucket(last - 100 * 3600)): 50},
    }
    fams = [
        {
            "level": "CRITICAL",
            "template": "disk fail <id>",
            "sample": "disk fail node7",
            "count": 8,
            "score": 1.0,
            "services": ["n7"],
            "first_ts": "",
            "last_ts": "",
            "first_epoch": last - 2 * 3600,
            "last_epoch": last,
        },
        {
            "level": "INFO",
            "template": "heartbeat <id>",
            "sample": "heartbeat ok",
            "count": 150,
            "score": 0.1,
            "services": ["n1"],
            "first_ts": "",
            "last_ts": "",
            "first_epoch": last - 100 * 3600,
            "last_epoch": last - 100 * 3600,
        },
    ]
    return {
        "family_count": len(fams),
        "families": fams,
        "level_time_hist": hist,
        "time_span": {"first_epoch": last - 200 * 3600, "last_epoch": last},
    }


def test_severity_count_window():
    r = _make_result()
    # last 1h: only the bucket at `last` → 5 critical
    assert severity_count(r, "CRITICAL", 3600) == 5
    # last 3h: includes bucket at last-2h → 5 + 3 = 8
    assert severity_count(r, "CRITICAL", 3 * 3600) == 8
    # INFO last 1h = 100; last-100h INFO excluded until window ≥ 100h
    assert severity_count(r, "INFO", 3600) == 100
    assert severity_count(r, "INFO", 101 * 3600) == 150


def test_severity_breakdown_keys():
    r = _make_result()
    bd = severity_breakdown(r, 3600)
    assert set(bd) == {b for b, _ in SEVERITY_MENU}
    assert bd["CRITICAL"] == 5


def test_families_filter_by_severity_and_search():
    r = _make_result()
    crit = families_in_window(r, level_bucket="CRITICAL")
    assert len(crit) == 1 and crit[0]["level"] == "CRITICAL"
    found = families_in_window(r, query="heartbeat")
    assert len(found) == 1 and "heartbeat" in found[0]["template"]
    assert families_in_window(r, query="nonexistent") == []


def test_families_filter_by_window():
    r = _make_result()
    # last 3h: only the CRITICAL family (last_epoch == last) qualifies; INFO is 100h old
    recent = families_in_window(r, window_seconds=3 * 3600)
    assert [f["level"] for f in recent] == ["CRITICAL"]


def test_save_load_roundtrip(tmp_path):
    r = _make_result()
    p = str(tmp_path / "x.loglens.json")
    save_results(p, r)
    loaded = load_results(p)
    assert loaded["family_count"] == r["family_count"]
    assert loaded["schema"].startswith("loglens.results")


def test_time_windows_menu_complete():
    labels = [lbl for lbl, _ in TIME_WINDOWS]
    assert "Last 1 hour" in labels and "Last 1 year" in labels
    assert len(TIME_WINDOWS) == 12
