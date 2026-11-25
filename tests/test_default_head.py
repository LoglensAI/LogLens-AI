from __future__ import annotations

import json

import numpy as np
from typer.testing import CliRunner

from loglens.application.api import (
    DEFAULT_HEAD_PROTECT_SCORE,
    default_head_protected,
)
from loglens.domain.models import LogEntry
from loglens.interface import cli


def _e(level: str) -> LogEntry:
    return LogEntry(timestamp="2026-01-01 10:00:00", level=level, service="api", message="m")


def test_protects_confident_errors_when_errors_are_rare():
    entries = [_e("INFO")] * 95 + [_e("ERROR")] * 4 + [_e("CRITICAL")]
    scores = np.array([0.1] * 95 + [0.95, 0.95, 0.5, 0.95, 0.97])
    mask = default_head_protected(entries, scores)
    assert mask.tolist() == [False] * 95 + [True, True, False, True, True]


def test_no_protection_when_errors_are_common():
    # BGL-like: a fifth of the log is ERROR+, so the model's veto stands.
    entries = [_e("INFO")] * 80 + [_e("ERROR")] * 20
    scores = np.full(100, 0.99)
    assert not default_head_protected(entries, scores).any()


def test_info_lines_are_never_protected():
    entries = [_e("INFO")] * 10
    scores = np.full(10, DEFAULT_HEAD_PROTECT_SCORE + 0.05)
    assert not default_head_protected(entries, scores).any()


def test_empty_input():
    assert default_head_protected([], []).shape == (0,)


def _app_log(tmp_path):
    lines = [
        f"2026-01-01 10:00:{i % 60:02d} INFO api request {i} served in 12ms" for i in range(200)
    ]
    lines.append("2026-01-01 10:04:00 ERROR api database connection pool exhausted")
    p = tmp_path / "app.log"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


def test_default_model_path_reports_the_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    log = _app_log(tmp_path)
    r = CliRunner().invoke(cli.app, ["analyze", log, "--no-learn", "--format", "json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output[r.output.index("{") :])
    templates = [a["template"] for a in data["anomalies"]]
    assert any("connection pool exhausted" in t for t in templates), templates
