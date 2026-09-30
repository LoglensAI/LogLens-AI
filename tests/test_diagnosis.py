from __future__ import annotations

from loglens.detection.diagnosis import (
    APPLICATION,
    BLOCKING,
    EXCEPTION_ONLY,
    LIBRARY,
    LOCATION_ONLY,
    NON_BLOCKING,
    PLAIN,
    UNKNOWN,
    classify_blocking,
    detect_exception_type,
    diagnose,
)
from loglens.detection.trace import extract_frames

_PY = """Traceback (most recent call last):
  File "/srv/app/api/orders.py", line 142, in checkout
    charge = gateway.charge(x)
  File "/usr/lib/python3.12/http/client.py", line 1010, in _post
RuntimeError: boom"""


def test_exception_type_detection():
    assert detect_exception_type("ERROR NullPointerException here") == "NullPointerException"
    assert detect_exception_type("segfault: received SIGSEGV") == "SIGSEGV"
    # "panic" is a state, not a named exception — not reported as an exception type
    assert detect_exception_type("panic: runtime error") is None
    assert detect_exception_type("all good") is None


def test_trace_kind_application():
    d = diagnose(_PY, extract_frames(_PY), level="ERROR")
    assert d.trace_kind == APPLICATION
    assert d.site and "orders.py" in d.site.file
    assert "your code" in d.headline
    assert d.exception_type == "RuntimeError"


def test_trace_kind_library_only():
    lib = 'File "/usr/lib/python3.12/json/decoder.py", line 337, in decode'
    d = diagnose(lib, extract_frames(lib), level="ERROR")
    assert d.trace_kind == LIBRARY


def test_trace_kind_location_only():
    d = diagnose("ERROR failed at config/loader.rb:20", [], level="ERROR")
    assert d.trace_kind == LOCATION_ONLY
    assert d.site and d.site.line == 20


def test_trace_kind_exception_only():
    d = diagnose("ERROR ValueError: bad input", [], level="ERROR")
    assert d.trace_kind == EXCEPTION_ONLY
    assert d.exception_type == "ValueError"


def test_trace_kind_plain():
    d = diagnose("disk usage at 80 percent", [], level="INFO")
    assert d.trace_kind == PLAIN


def test_blocking_hard_stop():
    imp, reason = classify_blocking("FATAL", "kernel panic not syncing")
    assert imp == BLOCKING and "hard-stop" in reason


def test_non_blocking_retry():
    imp, _ = classify_blocking("ERROR", "connection refused, retrying in 2s")
    assert imp == NON_BLOCKING


def test_recovery_follows_makes_non_blocking():
    imp, _ = classify_blocking("ERROR", "connection refused host=db", recovery_follows=True)
    assert imp == NON_BLOCKING


def test_unknown_when_no_signal():
    imp, _ = classify_blocking("ERROR", "something odd happened")
    assert imp == UNKNOWN


def test_traceback_defaults_to_blocking():
    # a real app traceback with no other signal should lean blocking
    d = diagnose(_PY, extract_frames(_PY), level="ERROR")
    assert d.impact == BLOCKING


def test_severity_fallback():
    assert classify_blocking("WARNING", "slowish")[0] == NON_BLOCKING
    assert classify_blocking("CRITICAL", "weird state")[0] == BLOCKING
