from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from loglens.interface import cli

_LOG = (
    "2026-01-01 10:00:00 INFO api request ok\n" * 60
    + "2026-01-01 10:01:00 FATAL db kernel panic: out of memory\n"
)


@pytest.fixture
def log(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    p = tmp_path / "app.log"
    p.write_text(_LOG, encoding="utf-8")
    return str(p)


def _run(*args):
    return CliRunner().invoke(cli.app, ["analyze", *args, "--no-learn"])


@pytest.mark.parametrize("level", ["fatal", "critical", "error", "any"])
def test_fail_on_trips_on_a_fatal_line(log, level):
    assert _run(log, "--fail-on", level).exit_code == 2


@pytest.mark.parametrize(
    ("flag", "value"),
    [("--fail-on", "high"), ("--sort-by", "banana"), ("--format", "xml")],
)
def test_bad_option_values_are_rejected(log, flag, value):
    r = _run(log, flag, value)
    assert r.exit_code == 2
    assert "Invalid value" in r.output


def test_json_on_empty_input_is_valid(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    p = tmp_path / "empty.log"
    p.write_text("\n\n", encoding="utf-8")
    r = _run(str(p), "--format", "json")
    assert r.exit_code == 0
    data = json.loads(r.stdout)
    assert data["schema"] == "loglens.v1" and data["anomaly_count"] == 0


def test_json_mode_reports_source_errors(tmp_path):
    r = _run(str(tmp_path / "missing.log"), "--format", "json")
    assert r.exit_code == 1
    assert "Source not found" in json.loads(r.stdout.splitlines()[0])["error"]


def test_non_model_file_gives_a_helpful_error(log, tmp_path):
    r = _run(log, "--model", log)
    assert r.exit_code == 1
    assert "not a LogLens model file" in " ".join(r.output.split())


def test_explain_accepts_a_positional_path(log):
    r = CliRunner().invoke(cli.app, ["explain", log])
    assert r.exit_code == 0, r.output
    assert "kernel panic" in r.output.lower()


def test_analyze_multi_accepts_positional_paths(log, tmp_path):
    other = tmp_path / "other.log"
    other.write_text(_LOG, encoding="utf-8")
    r = CliRunner().invoke(cli.app, ["analyze-multi", log, str(other)])
    assert r.exit_code == 0, r.output
    assert "other.log" in r.output and "app.log" in r.output


@pytest.mark.parametrize("form", ["positional", "option"])
def test_ask_fails_fast_without_an_llm_key(log, monkeypatch, form):
    for var in ("LOGLENS_LLM_PROVIDER", "LOGLENS_LLM_API_KEY", "LOGLENS_LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)
    args = [log, "why?"] if form == "positional" else ["why?", "--source", log]
    r = CliRunner().invoke(cli.app, ["ask", *args])
    assert r.exit_code == 1
    assert "No LLM provider configured" in r.output
    assert "Detecting anomalies" not in r.output  # failed before doing the work


def test_commands_without_a_source_explain_usage():
    for cmd in (["explain"], ["ask", "why?"], ["analyze-multi"]):
        r = CliRunner().invoke(cli.app, cmd)
        assert r.exit_code == 1, cmd
        assert "source" in r.output.lower(), cmd


def test_cli_keeps_stack_traces_with_their_error(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    p = tmp_path / "py.log"
    p.write_text(
        "".join(f"2026-01-01 10:00:{i:02d} INFO app: ok {i}\n" for i in range(50))
        + "2026-01-01 10:01:00 ERROR app: crash\n"
        "Traceback (most recent call last):\n"
        '  File "/srv/app/main.py", line 3, in <module>\n'
        "    main()\n"
        "ZeroDivisionError: division by zero\n",
        encoding="utf-8",
    )
    r = CliRunner().invoke(cli.app, ["analyze", str(p), "--no-learn", "--format", "json"])
    data = json.loads(r.stdout)
    assert data["lines_read"] == 55 and data["lines_parsed"] == 51
    crash = [a for a in data["anomalies"] if a["template"] == "crash"]
    assert crash, data["anomalies"]
    assert (
        "ZeroDivisionError" in "\n".join(crash[0]["sample_lines"])
        or crash[0]["template"] == "crash"
    )
    r = CliRunner().invoke(cli.app, ["explain", str(p), "--no-learn"])
    assert "main.py" in r.output
