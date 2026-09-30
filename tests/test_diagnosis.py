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


from loglens.detection.diagnosis import (  # noqa: E402
    DEPENDENCY,
    SYSTEM,
    UPSTREAM,
    YOUR_CODE,
    classify_origin,
)


def test_origin_system():
    o, d = classify_origin("kernel panic: out of memory, killing process 8123")
    assert o == SYSTEM and d == "out of memory"
    assert classify_origin("worker crashed with SIGSEGV")[0] == SYSTEM


def test_origin_upstream():
    assert classify_origin("GET /pay -> 503 host=payments-svc") == (UPSTREAM, "payments-svc")
    assert classify_origin("connection refused host=redis-1") == (UPSTREAM, "redis-1")


def test_origin_dependency_from_frame():
    f = extract_frames(
        'File "/venv/lib/python3.12/site-packages/requests/adapters.py", line 5, in send'
    )
    assert classify_origin("ConnectionError", f) == (DEPENDENCY, "requests")
    fn = extract_frames("at x (/app/node_modules/axios/lib/http.js:22:5)")
    assert classify_origin("boom", fn) == (DEPENDENCY, "axios")


def test_origin_missing_module():
    assert classify_origin("ModuleNotFoundError: No module named 'numpy'") == (DEPENDENCY, "numpy")


def test_origin_your_code():
    f = extract_frames('File "/srv/app/api/orders.py", line 55, in handle')
    assert classify_origin("ValueError: bad", f) == (YOUR_CODE, "orders.py")


def test_origin_unknown():
    assert classify_origin("disk usage at 70 percent") == (UNKNOWN, None)


def test_diagnose_sets_origin():
    # no system/upstream signal; deepest frame is stdlib http/client → dependency
    d = diagnose(_PY, extract_frames(_PY), level="ERROR")
    assert d.origin == DEPENDENCY
    # a message that names an upstream wins over the frame location
    up = diagnose("api call failed: 504 gateway timeout host=payments", [], level="ERROR")
    assert up.origin == UPSTREAM and up.origin_detail == "payments"
