from __future__ import annotations

from datetime import datetime, timedelta

from loglens.detection.incidents import Family, group_incidents

_BASE = datetime(2024, 1, 1, 0, 0, 0)


def _t(sec):
    return _BASE + timedelta(seconds=sec)


def _cascade():
    # db OOM -> api timeout -> cache refused, all within ~1 min
    return [
        Family("db1", "CRITICAL", "db", 3, _t(10), _t(40), "system", "out of memory", "db OOM"),
        Family("api1", "ERROR", "api", 5, _t(20), _t(50), "upstream_service", "db", "api timeout"),
        Family(
            "cache1",
            "ERROR",
            "cache",
            2,
            _t(30),
            _t(45),
            "upstream_service",
            "redis",
            "cache refused",
        ),
    ]


def test_single_cascade_is_one_incident():
    incs, mapping = group_incidents(_cascade(), source="app.log", gap_seconds=300)
    assert len(incs) == 1
    inc = incs[0]
    assert set(inc.family_ids) == {"db1", "api1", "cache1"}
    assert inc.services == ["db", "api", "cache"]  # first-seen order
    assert inc.events == 10
    assert all(mapping[t] == inc.id for t in ("db1", "api1", "cache1"))


def test_root_cause_is_system_origin():
    incs, _ = group_incidents(_cascade(), source="app.log")
    # the system-origin DB crash outranks the upstream symptoms it caused
    assert incs[0].root_cause_id == "db1"
    assert incs[0].root_cause_origin == "system"


def test_time_gap_splits_incidents():
    fams = _cascade() + [
        Family("web1", "ERROR", "web", 1, _t(4000), _t(4000), "your_code", "routes.py", "web 500"),
    ]
    incs, _ = group_incidents(fams, source="app.log", gap_seconds=300)
    assert len(incs) == 2  # the web error is >300s after the cascade → its own incident


def test_ids_deterministic_and_distinct():
    incs1, _ = group_incidents(_cascade(), source="app.log")
    incs2, _ = group_incidents(_cascade(), source="app.log")
    assert incs1[0].id == incs2[0].id  # stable
    # different source → different id
    incs3, _ = group_incidents(_cascade(), source="other.log")
    assert incs3[0].id != incs1[0].id


def test_non_severe_excluded():
    fams = [
        Family("info1", "INFO", "api", 9, _t(1), _t(9), "unknown", None, "ok"),
        Family("warn1", "WARNING", "api", 2, _t(2), _t(8), "unknown", None, "slow"),
    ]
    incs, mapping = group_incidents(fams, source="app.log")
    assert incs == [] and mapping == {}


def test_undated_fallback_one_incident():
    fams = [
        Family("a", "ERROR", "api", 1, None, None, "your_code", "a.py", "boom"),
        Family("b", "CRITICAL", "db", 1, None, None, "system", "oom", "crash"),
    ]
    incs, mapping = group_incidents(fams, source="app.log")
    assert len(incs) == 1  # no timestamps → single fallback incident
    assert len(mapping) == 2
