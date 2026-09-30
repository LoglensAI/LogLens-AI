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
        # rich loglens.v1 family schema (P1.3)
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


def test_analyze_json_d12_fields(tmp_path):
    import json

    log = _write_log(tmp_path)
    result = runner.invoke(app, ["analyze", "--source", log, "--format", "json", "--no-learn"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema"] == "loglens.v1"  # schema name unchanged by the additions
    assert data["anomalies"], "expected at least one family (the CRITICAL line)"
    a = data["anomalies"][0]
    for key in ("scores", "impact", "trace_kind", "provisional", "retracted", "incident_id"):
        assert key in a
    assert set(a["scores"]) == {"N", "B", "P", "R", "C", "S"}
    assert all(isinstance(a["scores"][k], (int, float)) for k in ("N", "B", "P", "C", "S"))
    assert isinstance(a["provisional"], bool) and a["retracted"] is False
    assert a["r_applied"] is False  # R stays descriptive
    if data["incident"]:
        ids = {x["incident_id"] for x in data["anomalies"] if x["incident_id"]}
        assert ids and all(i.startswith("inc_") for i in ids)


def test_analyze_json_d12_deterministic(tmp_path):
    import json

    log = _write_log(tmp_path)
    a1 = runner.invoke(app, ["analyze", "--source", log, "--format", "json", "--no-learn"]).output
    a2 = runner.invoke(app, ["analyze", "--source", log, "--format", "json", "--no-learn"]).output
    assert json.loads(a1) == json.loads(a2)  # incident_id + scores stable run-to-run


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


def test_analyze_is_deterministic(tmp_path):
    log = _write_log(tmp_path)
    args = [
        "analyze",
        "--source",
        log,
        "--format",
        "json",
        "--no-model",
        "--seed",
        "42",
        "--no-learn",
    ]
    first = runner.invoke(app, args)
    second = runner.invoke(app, args)
    assert first.exit_code == 0 and second.exit_code == 0
    assert first.output == second.output


def test_selflearn_writes_baseline(tmp_path):
    # analyze learns a baseline for the source by default (zero-touch memory)
    import glob
    import os

    log = _write_log(tmp_path)
    r = runner.invoke(app, ["analyze", "--source", log, "--no-model", "--seed", "1"])
    assert r.exit_code == 0
    state = os.environ["LOGLENS_STATE_DIR"]  # isolated by conftest
    files = glob.glob(os.path.join(state, "*.json"))
    assert files  # a baseline file was written
    import json as _json

    b = _json.load(open(files[0]))
    assert b["total"] >= 30 and b["learned_runs"] == 1


def test_no_learn_writes_nothing(tmp_path):
    import glob
    import os

    log = _write_log(tmp_path)
    r = runner.invoke(app, ["analyze", "--source", log, "--no-model", "--no-learn"])
    assert r.exit_code == 0
    state = os.environ["LOGLENS_STATE_DIR"]
    assert not glob.glob(os.path.join(state, "*.json"))  # nothing persisted


def test_grouping_sort_is_total_order():
    # tied-score families must land in a stable, seed-independent order
    from loglens.detection.grouping import group_anomalies
    from loglens.domain.models import LogEntry

    entries = [
        LogEntry(level="ERROR", service="zeta", message="disk full"),
        LogEntry(level="ERROR", service="alpha", message="disk full"),
        LogEntry(level="ERROR", service="mid", message="disk full"),
    ]
    scores = [0.9, 0.9, 0.9]  # all tied
    groups = group_anomalies(entries, scores, [[] for _ in entries])
    order = [g.service for g in groups]
    assert order == sorted(order)  # tiebreak sorts by service when score/count tie
