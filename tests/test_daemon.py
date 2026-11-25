from __future__ import annotations

import json
import socket
import threading
import time

import pytest

from loglens.application import daemon as d
from loglens.interface import cli
from loglens.interface import daemon_server as ds

_LOG = (
    "2024-01-01 00:00:00 INFO service started\n"
    "2024-01-01 00:00:01 INFO handling request ok\n"
    "2024-01-01 00:00:02 ERROR connection refused host=db-1\n"
    "2024-01-01 00:00:03 ERROR connection refused host=db-1\n"
    "2024-01-01 00:00:04 FATAL kernel panic not syncing\n"
)


@pytest.fixture
def logfile(tmp_path):
    p = tmp_path / "app.log"
    p.write_text(_LOG, encoding="utf-8")
    return str(p)


@pytest.fixture
def daemon(tmp_path, monkeypatch):
    rt = tmp_path / "rt"
    rt.mkdir()
    monkeypatch.setattr(d, "_runtime_dir", lambda: str(rt))
    monkeypatch.setattr(ds, "_warmup", cli._load)

    t = threading.Thread(target=ds.serve, kwargs={"idle_timeout": 30.0}, daemon=True)
    t.start()
    deadline = time.time() + 20
    while time.time() < deadline and not d.is_running():
        time.sleep(0.05)
    assert d.is_running(), "daemon did not come up"
    yield
    d.stop()
    t.join(timeout=5)


def test_wire_roundtrip():
    a, b = socket.socketpair()
    try:
        payload = {"op": "run", "argv": ["analyze"], "nested": {"x": [1, 2, 3]}}
        d._send(a, payload)
        assert d._recv(b) == payload
    finally:
        a.close()
        b.close()


def test_recv_on_closed_socket_is_none():
    a, b = socket.socketpair()
    a.close()
    try:
        assert d._recv(b) is None
    finally:
        b.close()


def test_client_returns_none_when_no_daemon(tmp_path, monkeypatch):
    monkeypatch.setattr(d, "_runtime_dir", lambda: str(tmp_path))
    assert d.is_running() is False
    assert d.status() is None
    assert d.run_via_daemon(["analyze", "--source", "x"], spawn=False) is None


def test_should_forward_respects_env(monkeypatch):
    monkeypatch.setenv("LOGLENS_DAEMON", "1")
    assert cli._should_forward(["analyze", "--source", "x"]) is True
    assert cli._should_forward(["train", "--source", "x"]) is False
    assert cli._should_forward(["analyze", "--help"]) is False
    monkeypatch.setenv("LOGLENS_DAEMON", "0")
    assert cli._should_forward(["analyze", "--source", "x"]) is False


def test_ping_reports_current_version(daemon):
    st = d.status()
    assert st and st["ok"] and st["version"] == cli.__version__


def test_served_json_matches_in_process(daemon, logfile, capsys):
    try:
        cli.app(
            ["analyze", "--source", logfile, "--format", "json", "--no-learn"],
            standalone_mode=False,
        )
    except SystemExit:
        pass
    local = capsys.readouterr().out

    code = d.run_via_daemon(
        ["analyze", "--source", logfile, "--format", "json", "--no-learn"], spawn=False
    )
    served = capsys.readouterr().out

    assert code == 0
    assert json.loads(served) == json.loads(local)


def test_served_fail_on_propagates_exit_code(daemon, logfile):
    code = d.run_via_daemon(
        ["analyze", "--source", logfile, "--format", "json", "--fail-on", "error"],
        spawn=False,
    )
    assert code == 2


def test_wsl_skips_daemon_fast(monkeypatch):
    """On WSL (where the IPC socket can't come up), the daemon is skipped
    instantly — no spawn, no wait — so an installed binary never stalls and
    never needs LOGLENS_DAEMON=0."""
    import time

    d._viable_cache = None
    monkeypatch.setattr(d, "_is_wsl", lambda: True)
    assert d.local_ipc_viable() is False
    t0 = time.perf_counter()
    assert d.ensure_running(spawn=True) is False
    assert time.perf_counter() - t0 < 1.0  # instant, no 3s spawn wait
    d._viable_cache = None


def test_local_ipc_viable_here():
    """A normal Linux environment can host the daemon."""
    d._viable_cache = None
    assert d.local_ipc_viable() is True
    d._viable_cache = None


def test_handle_run_clean_error_no_traceback(tmp_path):
    """A bad-input command served in-process must come back as a clean one-line
    error with exit 1 — never a raw Python traceback."""
    bgl = tmp_path / "bgl.log"
    bgl.write_text("- INFO ok\nPANIC FATAL boom\n", encoding="utf-8")
    req = {
        "token": "",
        "op": "run",
        # wrong --format on purpose → LogLensError inside the loader
        "argv": ["benchmark", str(bgl), "--format", "jsonl"],
        "cwd": str(tmp_path),
        "env": {"LOGLENS_DAEMON": "0"},
        "tty": False,
        "width": 100,
    }
    resp = ds._handle_run(req)
    assert resp["exit_code"] == 1
    combined = resp["stdout"] + resp["stderr"]
    assert "Traceback (most recent call last)" not in combined
    assert "[LogLens]" in combined


def test_bad_token_is_rejected(daemon):
    state = d._read_state()
    assert state is not None
    sock = d._open_client(state)
    assert sock is not None
    try:
        d._send(sock, {"token": "wrong", "op": "ping"})
        resp = d._recv(sock)
    finally:
        sock.close()
    assert resp == {"ok": False, "error": "unauthorized"}


# --- health / repair (issue #16) --------------------------------------------


def test_health_running_reports_latency(daemon):
    h = d.health()
    assert h["status"] == "running"
    assert h["version"] == d.__version__
    assert h["latency_ms"] >= 0


def test_health_stopped_without_state(tmp_path, monkeypatch):
    monkeypatch.setattr(d, "_runtime_dir", lambda: str(tmp_path))
    assert d.health() == {"status": "stopped"}


def _write_dead_state(tmp_path, monkeypatch, pid: int) -> None:
    monkeypatch.setattr(d, "_runtime_dir", lambda: str(tmp_path))
    d._write_state(
        {
            "transport": "unix" if d._USE_UNIX else "tcp",
            "path": str(tmp_path / "gone.sock"),
            "port": 1,  # nothing listens on port 1
            "pid": pid,
            "token": "x",
            "version": d.__version__,
            "started": time.time(),
        }
    )


def test_health_stale_when_socket_is_dead(tmp_path, monkeypatch):
    import os

    # Our own pid is alive but nothing answers on the recorded socket.
    _write_dead_state(tmp_path, monkeypatch, pid=os.getpid())
    h = d.health()
    assert h["status"] == "stale"
    assert h["pid_alive"] is True


def test_health_outdated_version(daemon, monkeypatch):
    monkeypatch.setattr(d, "__version__", "0.0.0-other")
    h = d.health()
    assert h["status"] == "outdated"
    assert h["expected_version"] == "0.0.0-other"


def test_repair_discards_stale_state_and_respawns(tmp_path, monkeypatch):
    import os

    _write_dead_state(tmp_path, monkeypatch, pid=os.getpid())
    d._set_cooldown()  # an earlier failed start must not block an explicit repair
    calls = []
    monkeypatch.setattr(d, "local_ipc_viable", lambda: True)
    monkeypatch.setattr(
        d, "ensure_running", lambda spawn=True, wait=3.0: calls.append(spawn) or True
    )
    assert d.repair() is True
    assert calls == [True]
    assert d._read_state() is None
    assert not d._in_cooldown()


def test_repair_not_attempted_where_ipc_unavailable(tmp_path, monkeypatch):
    import os

    _write_dead_state(tmp_path, monkeypatch, pid=os.getpid())
    monkeypatch.setattr(d, "local_ipc_viable", lambda: False)
    assert d.repair() is False


def test_status_cli_respawns_stale_daemon(tmp_path, monkeypatch):
    import os

    from typer.testing import CliRunner

    _write_dead_state(tmp_path, monkeypatch, pid=os.getpid())
    monkeypatch.setattr(d, "repair", lambda wait=5.0: True)
    healthy = {
        "status": "running",
        "pid": 1,
        "version": "x",
        "transport": "unix",
        "started": time.time(),
        "latency_ms": 0.4,
    }
    seq = iter([d.health(), healthy])
    monkeypatch.setattr(d, "health", lambda: next(seq))
    r = CliRunner().invoke(cli.app, ["daemon", "status"])
    assert r.exit_code == 0, r.output
    assert "stale" in r.output and "running" in r.output


def test_status_cli_no_repair_only_reports(tmp_path, monkeypatch):
    import os

    from typer.testing import CliRunner

    _write_dead_state(tmp_path, monkeypatch, pid=os.getpid())
    monkeypatch.setattr(d, "repair", lambda wait=5.0: pytest.fail("must not repair"))
    r = CliRunner().invoke(cli.app, ["daemon", "status", "--no-repair"])
    assert r.exit_code == 1
    assert "stale" in r.output
