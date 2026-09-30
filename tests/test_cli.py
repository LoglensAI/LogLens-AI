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


def test_version_json():
    import json as _json

    result = runner.invoke(app, ["version", "--json"])
    assert result.exit_code == 0
    data = _json.loads(result.output)
    assert data["version"] == __version__
    for key in ("commit", "build_date", "python"):
        assert key in data


def test_assess_incident_fires_on_critical():
    from loglens.interface.cli import _assess_incident

    items = [{"level": "CRITICAL", "count": 1, "score": 0.95}]
    incident, score, reasons = _assess_incident(items, lines_parsed=2000)
    assert incident is True
    assert 0.0 < score <= 1.0
    assert reasons  # non-empty explanation


def test_assess_incident_clean_is_false():
    from loglens.interface.cli import _assess_incident

    items = [{"level": "INFO", "count": 1, "score": 0.0}]
    incident, score, reasons = _assess_incident(items, lines_parsed=100)
    assert incident is False
    assert score == 0.0
    assert reasons == []


def test_assess_incident_burst_ratio():
    from loglens.interface.cli import _assess_incident

    # 40% of lines severe (ERROR) but no CRITICAL → still an incident via burst
    items = [{"level": "ERROR", "count": 40, "score": 0.7}]
    incident, score, reasons = _assess_incident(items, lines_parsed=100)
    assert incident is True
    assert any("severe" in r for r in reasons)


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


# --- CI/CD: --format json + --fail-on gating --------------------------------- #
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
    assert data.get("schema") == "loglens.v1"
    if data["anomalies"]:
        a = data["anomalies"][0]
        expected = {
            "id",
            "template_id",
            "template",
            "level",
            "service",
            "score",
            "count",
            "first_seen",
            "last_seen",
            "line_numbers",
            "sample_lines",
            "message",
            "calibrated_p",
            "reasons",
            "detector_votes",
        }
        assert expected <= set(a)
        assert isinstance(a["line_numbers"], list)
        # line numbers must be real 1-based positions in the file
        assert all(isinstance(n, int) and n >= 1 for n in a["line_numbers"])


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
