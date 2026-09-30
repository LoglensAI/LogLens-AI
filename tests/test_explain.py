from __future__ import annotations

import json

from typer.testing import CliRunner

from loglens.interface.cli import app

runner = CliRunner()


def _write_trace_log(tmp_path):
    """A log with a recurring exception carrying a real Python traceback."""

    def ts(sec):
        return f"2024-01-01 {sec // 3600:02d}:{(sec % 3600) // 60:02d}:{sec % 60:02d}"

    lines = [f"{ts(i * 20)} INFO api handling request {i} ok" for i in range(120)]
    for k in range(4):
        sec = 1000 + k * 300
        lines += [
            f"{ts(sec)} ERROR api unhandled exception while processing order {k}",
            "Traceback (most recent call last):",
            '  File "/srv/app/api/orders.py", line 142, in checkout',
            "    charge = gateway.charge(cart.total)",
            '  File "/usr/lib/python3.12/http/client.py", line 1010, in _post',
            "    raise TimeoutError(msg)",
            "TimeoutError: upstream payment gateway timed out",
        ]
    p = tmp_path / "trace.log"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


def test_explain_terminal_runs(tmp_path):
    log = _write_trace_log(tmp_path)
    result = runner.invoke(app, ["explain", "--source", log, "--no-learn"])
    assert result.exit_code == 0
    out = result.output
    assert "When" in out and "Freq" in out
    # the failure site should be surfaced from the traceback
    assert "orders.py" in out


def test_explain_json_schema_and_trace(tmp_path):
    log = _write_trace_log(tmp_path)
    result = runner.invoke(app, ["explain", "--source", log, "--no-learn", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema"] == "loglens.explain.v1"
    assert data["window"]["applied"] is True
    assert data["anomaly_families"] >= 1
    fam = data["anomalies"][0]
    for key in (
        "level",
        "service",
        "count",
        "frequency",
        "site",
        "trace",
        "confidence",
        "r_status",
    ):
        assert key in fam
    # the recurring exception is grouped and its site/trace extracted
    assert fam["count"] == 4
    assert fam["site"] and "orders.py" in fam["site"]
    assert any("orders.py" in f for f in fam["trace"])


def test_explain_window_narrowing(tmp_path):
    log = _write_trace_log(tmp_path)
    # a 30-minute window still catches the clustered exceptions
    r30 = runner.invoke(
        app, ["explain", "--source", log, "--no-learn", "--last", "30m", "--format", "json"]
    )
    assert r30.exit_code == 0
    d30 = json.loads(r30.output)
    assert d30["window"]["applied"] is True
    assert d30["events_in_window"] >= 1


def test_explain_since_absolute(tmp_path):
    log = _write_trace_log(tmp_path)
    result = runner.invoke(
        app,
        [
            "explain",
            "--source",
            log,
            "--no-learn",
            "--since",
            "2024-01-01 00:10:00",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["window"]["from"].startswith("2024-01-01T00:10:00")


def test_explain_top_limits_cards(tmp_path):
    log = _write_trace_log(tmp_path)
    result = runner.invoke(app, ["explain", "--source", log, "--no-learn", "--top", "1"])
    assert result.exit_code == 0
