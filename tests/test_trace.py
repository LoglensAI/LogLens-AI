from __future__ import annotations

from loglens.detection.trace import (
    extract_frames,
    is_new_record,
    primary_site,
    reconstruct_trace,
)
from loglens.domain.models import LogEntry

_PY = """Traceback (most recent call last):
  File "/app/src/service.py", line 88, in handle
    result = process(req)
  File "/usr/lib/python3.12/json/decoder.py", line 337, in decode
    raise JSONDecodeError(msg)
ValueError: bad json"""


def test_python_frames_and_library_flag():
    frames = extract_frames(_PY)
    assert [f.basename for f in frames] == ["service.py", "decoder.py"]
    assert frames[0].line == 88 and frames[0].func == "handle"
    assert frames[1].is_library is True
    assert frames[0].is_library is False


def test_primary_site_prefers_app_frame():
    site = primary_site(extract_frames(_PY))
    assert site is not None
    assert site.file == "/app/src/service.py" and site.line == 88


def test_java_node_generic():
    assert extract_frames("at com.acme.Svc.checkout(Svc.java:142)")[0].line == 142
    assert extract_frames("at tick (/srv/app/h.js:23:11)")[0].file == "/srv/app/h.js"
    assert extract_frames("failed at src/db/pool.rs:100")[0].line == 100


def test_no_false_match_on_timestamp():
    assert extract_frames("2024-01-01 12:30:00 connection ok") == []


def test_is_new_record():
    assert is_new_record("2024-01-01 00:00:04 INFO x") is True
    assert is_new_record('  File "/a/b.py", line 3, in f') is False
    assert is_new_record("Traceback (most recent call last):") is False


def test_reconstruct_across_split_entries_indent_stripped():
    # simulate a parser that stripped leading whitespace, with a real record after
    body = [ln.lstrip() for ln in _PY.splitlines()]
    entries = (
        [LogEntry(raw="2024-01-01 00:00:01 ERROR api unhandled exception")]
        + [LogEntry(raw=ln) for ln in body]
        + [LogEntry(raw="2024-01-01 00:00:05 INFO api next request")]
    )
    frames = reconstruct_trace(entries, 0)
    assert [f.basename for f in frames] == ["service.py", "decoder.py"]
    # stops at the next real record — doesn't slurp "next request"
    assert all("next request" not in (f.raw or "") for f in frames)
    assert primary_site(frames).file == "/app/src/service.py"


def test_reconstruct_no_trace_returns_empty():
    entries = [
        LogEntry(raw="2024-01-01 00:00:01 ERROR api boom"),
        LogEntry(raw="2024-01-01 00:00:02 INFO api ok"),
    ]
    assert reconstruct_trace(entries, 0) == []
