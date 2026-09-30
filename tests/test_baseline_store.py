import os

from loglens.application import baseline_store as bs
from loglens.domain.models import LogEntry


def _e(level, msg):
    return LogEntry(level=level, service="api", message=msg)


def test_key_is_stable_and_profile_overrides():
    k1 = bs.baseline_key("/var/log/app.log")
    k2 = bs.baseline_key("/var/log/app.log")
    assert k1 == k2  # stable
    assert bs.baseline_key("/var/log/app.log", profile="prod-api") == "prod-api"


def test_update_grows_total_and_templates():
    entries = [_e("INFO", f"request {i} ok") for i in range(10)]
    flagged = [False] * 10
    b = bs.update_baseline(None, entries, flagged)
    assert b["total"] == 10
    assert b["learned_runs"] == 1
    b2 = bs.update_baseline(b, entries, flagged)
    assert b2["total"] == 20
    assert b2["learned_runs"] == 2


def test_update_excludes_flagged_lines():
    entries = [_e("INFO", "request ok")] * 5 + [_e("FATAL", "kernel panic")] * 5
    flagged = [False] * 5 + [True] * 5
    b = bs.update_baseline(None, entries, flagged)
    assert b["total"] == 5  # only the normal lines
    assert not any("kernel panic" in k for k in b["templates"])  # anomaly not memorised


def test_save_load_roundtrip(tmp_path):
    entries = [_e("INFO", "heartbeat ok") for _ in range(3)]
    b = bs.update_baseline(None, entries, [False] * 3)
    path = bs.save_baseline("k1", b, str(tmp_path))
    assert os.path.isfile(path)
    loaded = bs.load_baseline("k1", str(tmp_path))
    assert loaded is not None
    assert loaded["total"] == 3
    assert loaded["templates"] == b["templates"]


def test_load_missing_returns_none(tmp_path):
    assert bs.load_baseline("does-not-exist", str(tmp_path)) is None


def test_state_dir_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGLENS_STATE_DIR", str(tmp_path / "custom"))
    assert bs.default_state_dir() == str(tmp_path / "custom")
