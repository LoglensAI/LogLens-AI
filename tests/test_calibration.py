from __future__ import annotations

from loglens.detection.calibration import calibrate, to_payload

_DAY = 86400


def _alerts():
    # api noisy (6), db quiet (2)
    return [
        ("api", 0.95),
        ("api", 0.9),
        ("api", 0.88),
        ("api", 0.8),
        ("api", 0.75),
        ("api", 0.7),
        ("db", 0.97),
        ("db", 0.6),
    ]


def test_measured_rate_over_full_day():
    b = {x.service: x for x in calibrate(_alerts(), budget_per_day=5, window_seconds=_DAY)}
    assert b["api"].measured_per_day == 6.0 and b["api"].basis == "measured"
    assert b["api"].within_budget is False  # 6 > 5
    assert b["db"].within_budget is True  # 2 <= 5


def test_sub_day_window_extrapolates():
    b = calibrate(_alerts(), budget_per_day=5, window_seconds=14 * 60)
    assert all(x.basis == "extrapolated" for x in b)
    assert b[0].measured_per_day is not None and b[0].measured_per_day > 5


def test_unknown_window_is_within_and_unlabeled():
    b = calibrate(_alerts(), budget_per_day=5, window_seconds=None)
    assert all(x.basis == "unknown" and x.measured_per_day is None for x in b)
    assert all(x.within_budget for x in b)


def test_suggested_cutoff_when_over():
    alerts = [("api", 1.0 - i * 0.05) for i in range(12)]
    b = calibrate(alerts, budget_per_day=5, window_seconds=_DAY)[0]
    assert b.within_budget is False
    assert b.suggested_cutoff is not None
    admitted = sum(1 for _, s in alerts if s >= b.suggested_cutoff)
    assert admitted <= 6  # ~budget (k = round(5))


def test_never_hides_nothing_dropped():
    b = calibrate(_alerts(), budget_per_day=5, window_seconds=_DAY)
    assert sum(x.alerts for x in b) == len(_alerts())


def test_payload_shape_and_wording():
    p = to_payload(calibrate(_alerts(), budget_per_day=5, window_seconds=_DAY), 5)
    assert p["budget_per_day_per_service"] == 5
    assert "guarantee" in p["wording"].lower()  # honest wording, not a promise
    assert set(p["over_budget_services"]) == {"api"}
    assert {s["service"] for s in p["by_service"]} == {"api", "db"}


def test_deterministic_service_order():
    p1 = to_payload(calibrate(_alerts(), window_seconds=_DAY), 5)
    p2 = to_payload(calibrate(_alerts(), window_seconds=_DAY), 5)
    assert p1 == p2
    assert [s["service"] for s in p1["by_service"]] == ["api", "db"]  # sorted
