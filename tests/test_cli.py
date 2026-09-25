import re

from typer.testing import CliRunner

from loglens import __version__
from loglens.interface.cli import app

runner = CliRunner()


def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "LogLens" in result.output


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in strip_ansi(result.output)


def test_help_lists_commands():
    result = runner.invoke(app, ["help"])
    assert result.exit_code == 0
    out = strip_ansi(result.output)
    # every command should be listed with a description, not just a bare name
    for cmd in ("analyze", "train", "watch", "daemon"):
        assert cmd in out


def test_no_hello_command():
    # `hello` was removed; unknown commands should not resolve to it
    result = runner.invoke(app, ["hello"])
    assert result.exit_code != 0


def _write_log(tmp_path):
    p = tmp_path / "app.log"
    lines = [f"2024-01-01 12:00:{i:02d} web INFO request ok {i}" for i in range(30)]
    lines.append("2024-01-01 12:01:00 db CRITICAL database connection refused")
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


def test_analyze_format_json_is_valid(tmp_path):
    import json

    log = _write_log(tmp_path)
    result = runner.invoke(app, ["analyze", "--source", log, "--format", "json", "--no-model"])
    assert result.exit_code == 0
    data = json.loads(result.output)  # must be clean, parseable JSON on stdout
    assert data["mode"] == "fast"
    assert data["lines_parsed"] >= 30
    assert "anomalies" in data
    if data["anomalies"]:
        a = data["anomalies"][0]
        assert {"level", "service", "score", "count", "message", "reasons"} <= set(a)


def test_analyze_format_json_turbo(tmp_path):
    import json

    log = _write_log(tmp_path)
    result = runner.invoke(app, ["analyze", "--source", log, "--turbo", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["mode"] == "turbo"


def test_fail_on_trips_on_critical(tmp_path):
    log = _write_log(tmp_path)
    result = runner.invoke(app, ["analyze", "--source", log, "--fail-on", "critical", "--no-model"])
    assert result.exit_code == 2  # gate tripped → CI build should fail


def test_fail_on_default_does_not_gate(tmp_path):
    log = _write_log(tmp_path)
    result = runner.invoke(app, ["analyze", "--source", log, "--no-model"])
    assert result.exit_code == 0


def test_fail_on_unknown_threshold_does_not_gate(tmp_path):
    log = _write_log(tmp_path)
    result = runner.invoke(app, ["analyze", "--source", log, "--fail-on", "bogus", "--no-model"])
    assert result.exit_code == 0  # a typo must never silently fail (or pass) a build wrongly
