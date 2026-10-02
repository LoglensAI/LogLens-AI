from __future__ import annotations

import pytest

from loglens.application.sources import SourceSpec, parse_sources


def test_bare_path():
    (s,) = parse_sources(["/var/log/app.log"])
    assert s.kind == "file"
    assert s.path == "/var/log/app.log"
    assert s.id == "app.log"


def test_named_path():
    (s,) = parse_sources(["api=/var/log/api.log"])
    assert s.id == "api"
    assert s.path == "/var/log/api.log"


def test_cmd_and_url():
    cmd, url = parse_sources(["db=cmd:journalctl -u db", "edge=https://host/log"])
    assert cmd.kind == "cmd" and cmd.cmd == "journalctl -u db"
    assert url.kind == "url" and url.url == "https://host/log"


def test_bare_cmd_and_url_ids():
    cmd, url = parse_sources(["cmd:journalctl -u db", "https://host/path/stream"])
    assert cmd.kind == "cmd" and cmd.id == "journalctl"
    assert url.kind == "url" and url.id == "stream"


def test_duplicate_ids_made_unique():
    a, b = parse_sources(["/a/app.log", "/b/app.log"])
    assert a.id == "app.log"
    assert b.id == "app.log-2"


def test_fmt_applied_to_all():
    specs = parse_sources(["a=/x.log", "b=/y.log"], fmt="JSON")
    assert all(s.fmt == "JSON" for s in specs)


def test_exactly_one_input_required():
    with pytest.raises(ValueError):
        SourceSpec(id="bad")
    with pytest.raises(ValueError):
        SourceSpec(id="bad", path="/x", url="https://y")


def test_state_key_isolation():
    a = SourceSpec(id="api", path="/x.log")
    b = SourceSpec(id="db", path="/y.log")
    assert a.state_key() != b.state_key()
    assert a.state_key("autotrain").startswith("autotrain:")


def test_weight_must_be_positive():
    with pytest.raises(ValueError):
        SourceSpec(id="x", path="/a", weight=0)
