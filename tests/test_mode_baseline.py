from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from loglens.interface.cli import app

runner = CliRunner()


def _write_baseline_log(tmp_path):
    """Create a deterministic log with valid entries and blank lines."""
    path = tmp_path / "mode-baseline.log"

    lines = [f"2024-01-01 12:00:{i:02d} web INFO request ok {i}" for i in range(31)]

    # Blank lines must not count as parsed entries.
    contents = lines[:10] + [""] + lines[10:20] + [""] + lines[20:]
    path.write_text("\n".join(contents) + "\n", encoding="utf-8")

    return path, len(lines)


def _run_json(path, *, turbo):
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


def test_fast_and_turbo_parse_all_valid_lines(tmp_path):
    path, expected_lines = _write_baseline_log(tmp_path)

    fast = _run_json(path, turbo=False)
    turbo = _run_json(path, turbo=True)

    assert fast["mode"] == "fast"
    assert turbo["mode"] == "turbo"

    assert fast["lines_parsed"] == expected_lines
    assert turbo["lines_parsed"] == expected_lines
    assert fast["lines_parsed"] == turbo["lines_parsed"]


def test_turbo_output_is_repeatable(tmp_path):
    path, expected_lines = _write_baseline_log(tmp_path)

    first = _run_json(path, turbo=True)
    second = _run_json(path, turbo=True)

    assert first == second
    assert first["lines_parsed"] == expected_lines


@pytest.mark.parametrize(
    ("fixture", "expected_lines", "fast_anomalies", "turbo_anomalies"),
    [
        ("clean.log", 200, 0, 0),
        ("incident_heavy.log", 250, 34, 34),
        ("param_anomaly.log", 200, 1, 0),
        ("big.log", 50_000, 5, 29),
    ],
)
def test_real_fixture_mode_baseline(fixture, expected_lines, fast_anomalies, turbo_anomalies):
    from pathlib import Path

    testlogs = Path(__file__).resolve().parents[1] / "testlogs"
    path = testlogs / fixture

    assert path.is_file(), f"Missing baseline fixture: {path}"

    fast = _run_fixture_json(path, turbo=False)
    turbo = _run_fixture_json(path, turbo=True)

    assert fast["mode"] == "fast"
    assert turbo["mode"] == "turbo"

    assert fast["lines_parsed"] == expected_lines
    assert turbo["lines_parsed"] == expected_lines

    assert fast["anomaly_count"] == fast_anomalies
    assert turbo["anomaly_count"] == turbo_anomalies

    assert fast["lines_read"] == expected_lines
    assert turbo["lines_read"] is None


def _run_fixture_json(path, *, turbo):
    import json

    from typer.testing import CliRunner

    from loglens.interface.cli import app

    args = [
        "analyze",
        "--source",
        str(path),
        "--format",
        "json",
        "--no-model",
        "--no-learn",
        "--seed",
        "0",
    ]

    if turbo:
        args.append("--turbo")

    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output

    return json.loads(result.output)
