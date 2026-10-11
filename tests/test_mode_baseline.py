"""Reproducible baseline contracts for the fast and turbo CLI modes.

These tests deliberately compare input accounting and repeatability, not anomaly-score
parity: fast and turbo use different detection strategies and may legitimately rank
anomalies differently.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from loglens.interface.cli import app

runner = CliRunner()


def _write_baseline_log(tmp_path):
    """Create a stable, single-format log with blank lines that must be ignored."""
    path = tmp_path / "mode-baseline.log"
    lines = [
        f"2024-01-01 12:{i // 60:02d}:{i % 60:02d} web INFO request completed id={i}"
        for i in range(31)
    ]
    # Blank lines must not be counted as parsed log entries.
    path.write_text("\n".join(lines[:10] + [""] + lines[10:20] + [""] + lines[20:]) + "\n", encoding="utf-8")
    return path, len(lines)


def _run_json(path, *, turbo: bool):
    args = [
        "analyze",
        "--source",
        str(path),
        "--format",
        "json",
        "--no-model",
        "--no-learn",
        "--seed",
        "42",
    ]
    if turbo:
        args.append("--turbo")
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_fast_and_turbo_baseline_count_all_valid_lines_once(tmp_path):
    path, expected_parsed = _write_baseline_log(tmp_path)

    fast = _run_json(path, turbo=False)
    turbo = _run_json(path, turbo=True)

    assert fast["mode"] == "fast"
    assert turbo["mode"] == "turbo"
    assert fast["lines_parsed"] == expected_parsed
    assert turbo["lines_parsed"] == expected_parsed
    assert fast["lines_parsed"] == turbo["lines_parsed"]


def test_turbo_baseline_is_repeatable(tmp_path):
    path, expected_parsed = _write_baseline_log(tmp_path)

    first = _run_json(path, turbo=True)
    second = _run_json(path, turbo=True)

    assert first == second
    assert first["lines_parsed"] == expected_parsed
