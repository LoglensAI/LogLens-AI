from __future__ import annotations

from datetime import datetime, timedelta

from loglens.detection.timeutil import (
    bucketize,
    humanize_delta,
    humanize_span,
    parse_duration,
    parse_ts,
    sparkline,
)


def test_parse_ts_common_formats():
    assert parse_ts("2024-01-01 00:00:04") == datetime(2024, 1, 1, 0, 0, 4)
    assert parse_ts("2024-01-01T00:00:04.500Z") == datetime(2024, 1, 1, 0, 0, 4, 500000)
    assert parse_ts("2005-06-03-15.42.50.363779") == datetime(2005, 6, 3, 15, 42, 50, 363779)


def test_parse_ts_epoch_and_junk():
    assert parse_ts("1117838570") is not None  # epoch seconds
    assert parse_ts("not a timestamp") is None
    assert parse_ts("") is None


def test_parse_duration():
    assert parse_duration("24h") == timedelta(hours=24)
    assert parse_duration("90m") == timedelta(minutes=90)
    assert parse_duration("2d") == timedelta(days=2)
    assert parse_duration("1h30m") == timedelta(hours=1, minutes=30)
    assert parse_duration("") is None
    assert parse_duration("garbage") is None


def test_humanize_delta():
    assert humanize_delta(timedelta(seconds=2)) == "just now"
    assert humanize_delta(timedelta(seconds=42)) == "42s ago"
    assert humanize_delta(timedelta(minutes=5)) == "5m ago"
    assert humanize_delta(timedelta(hours=2)) == "2h ago"
    assert humanize_delta(timedelta(days=3)) == "3d ago"


def test_humanize_span():
    assert humanize_span(datetime(2024, 1, 1, 0, 0, 0), datetime(2024, 1, 1, 0, 0, 0)) == "instant"
    assert humanize_span(datetime(2024, 1, 1, 0, 0, 0), datetime(2024, 1, 1, 2, 14, 0)) == "2h 14m"


def test_bucketize_and_sparkline():
    s, e = datetime(2024, 1, 1, 0, 0, 0), datetime(2024, 1, 1, 0, 0, 12)
    times = [s, s, s + timedelta(seconds=6), e]
    counts = bucketize(times, s, e, 12)
    assert sum(counts) == 4
    assert counts[0] == 2  # two at the start
    spark = sparkline(counts)
    assert len(spark) == 12
    # all-zero counts render as the lowest block, never crash
    assert sparkline([0, 0, 0]) == "▁▁▁"
    assert sparkline([]) == ""


def test_bucketize_ignores_out_of_range():
    s, e = datetime(2024, 1, 1, 1, 0, 0), datetime(2024, 1, 1, 2, 0, 0)
    times = [datetime(2024, 1, 1, 0, 0, 0), datetime(2024, 1, 1, 1, 30, 0)]
    counts = bucketize(times, s, e, 4)
    assert sum(counts) == 1  # the 00:00 event is outside [01:00, 02:00]
