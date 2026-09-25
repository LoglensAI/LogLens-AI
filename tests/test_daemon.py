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
        cli.app(["analyze", "--source", logfile, "--format", "json"], standalone_mode=False)
    except SystemExit:
        pass
    local = capsys.readouterr().out

    code = d.run_via_daemon(["analyze", "--source", logfile, "--format", "json"], spawn=False)
    served = capsys.readouterr().out

    assert code == 0
    assert json.loads(served) == json.loads(local)


def test_served_fail_on_propagates_exit_code(daemon, logfile):
    code = d.run_via_daemon(
        ["analyze", "--source", logfile, "--format", "json", "--fail-on", "error"],
        spawn=False,
    )
    assert code == 2


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
