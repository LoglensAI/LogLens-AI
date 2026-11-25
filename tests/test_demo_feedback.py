from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from typer.testing import CliRunner

from loglens.interface import cli


def test_demo_runs_on_the_bundled_log_and_finds_the_incident(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    out = tmp_path / "demo.html"
    r = CliRunner().invoke(cli.app, ["demo", "--html", str(out)])
    assert r.exit_code == 0, r.output
    text = " ".join(r.output.split()).lower()
    assert "kernel panic" in text and "incident" in text
    assert "loglens feedback" in text
    assert out.exists() and out.stat().st_size > 1000
    assert not (tmp_path / ".loglens" / "baselines").exists()  # demo doesn't learn


def test_feedback_prints_a_prefilled_form_link():
    r = CliRunner().invoke(cli.app, ["feedback"])
    assert r.exit_code == 0, r.output
    url = r.output.strip().splitlines()[-1]
    q = parse_qs(urlparse(url).query)
    assert q["template"] == ["beta_feedback.yml"]
    assert "LogLens" in q["environment"][0] and "Python" in q["environment"][0]
