from __future__ import annotations

import warnings
from datetime import datetime, timedelta

from loglens.detection.timeutil import parse_ts


def test_yearless_syslog_stamps_parse_without_deprecation_warning():
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        dt = parse_ts("Jan  1 10:00:00")
    assert dt is not None and dt.month == 1 and dt.day == 1


def test_leap_day_parses():
    dt = parse_ts("Feb 29 12:00:00")
    assert dt is not None and (dt.month, dt.day) == (2, 29)


def test_yearless_stamp_is_never_in_the_future():
    for stamp in ("Dec 31 23:59:59", "Jan  1 00:00:00", "Jun 15 12:00:00"):
        dt = parse_ts(stamp)
        assert dt is not None and dt <= datetime.now() + timedelta(days=1), stamp
