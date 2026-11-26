from __future__ import annotations

import importlib.util
import pathlib

import pytest

_MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "ci" / "gh_analyze.py"


@pytest.fixture(scope="module")
def gh():
    spec = importlib.util.spec_from_file_location("gh_analyze", _MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


_DATA = {
    "mode": "fast",
    "lines_parsed": 2000,
    "incident": True,
    "anomaly_count": 2,
    "anomalies": [
        {
            "level": "CRITICAL",
            "service": "db",
            "score": 0.95,
            "count": 3,
            "message": "connection refused | host=db-1",
            "reasons": ["severity CRITICAL", "failure keyword"],
        },
        {
            "level": "WARNING",
            "service": "api",
            "score": 0.72,
            "count": 1,
            "message": "slow response",
            "reasons": ["flood"],
        },
    ],
}


def test_summary_has_table_and_incident(gh):
    md = gh._write_summary(_DATA)
    assert "LogLens AI" in md
    assert "INCIDENT" in md
    assert "| CRITICAL |" in md and "| WARNING |" in md
    # pipe characters in messages must be escaped so the table doesn't break
    assert "connection refused \\| host=db-1" in md


def test_summary_empty_is_clean(gh):
    md = gh._write_summary(
        {"mode": "fast", "lines_parsed": 10, "anomaly_count": 0, "anomalies": []}
    )
    assert "No anomalies detected" in md
    assert "|" not in md  # no table when there's nothing to show


def test_annotations_map_severity(gh, capsys):
    gh._emit_annotations(_DATA)
    out = capsys.readouterr().out
    # ":" in a property is escaped as %3A; GitHub shows it as ":" again.
    assert "::error title=LogLens%3A CRITICAL in db::" in out
    assert "::warning title=LogLens%3A WARNING in api::" in out


def test_emoji(gh):
    assert gh._emoji("CRITICAL") == "🔴"
    assert gh._emoji("WARNING") == "🟡"
    assert gh._emoji("INFO") == "⚪"
