from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import traceback
from typing import Any

import click
from rich.console import Console

from loglens import __version__
from loglens.application import daemon as d
from loglens.interface import cli


def _warmup() -> None:
    cli._load()
    try:
        sample = (
            "2024-01-01 00:00:00 INFO service started\n"
            "2024-01-01 00:00:01 INFO handling request\n"
            "2024-01-01 00:00:02 ERROR connection refused host=db\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as fh:
            fh.write(sample)
            warm_path = fh.name
        cli.app(
            ["analyze", "--source", warm_path, "--format", "json", "--no-model"],
            standalone_mode=False,
        )
        os.remove(warm_path)
    except Exception:  # noqa: BLE001 — warmup is best-effort only
        pass


def _handle_run(req: dict[str, Any]) -> dict[str, Any]:
    argv = list(req.get("argv", []))
    cwd = req.get("cwd") or os.getcwd()
    env = req.get("env") or {}
    tty = bool(req.get("tty", False))
    width = int(req.get("width", 100)) or 100

    buf_out, buf_err = io.StringIO(), io.StringIO()
    cap = Console(
        file=buf_out,
        force_terminal=tty,
        color_system="truecolor" if tty else None,
        width=width,
        soft_wrap=False,
    )

    old_console = cli.console
    old_cwd = os.getcwd()
    old_env = os.environ.copy()
    code = 0
    try:
        cli.console = cap
        try:
            os.chdir(cwd)
        except OSError:
            pass
        os.environ.clear()
        os.environ.update({str(k): str(v) for k, v in env.items()})
        os.environ["LOGLENS_DAEMON"] = "0"
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            try:
                ret = cli.app(argv, standalone_mode=False)
                code = ret if isinstance(ret, int) else 0
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
            except click.exceptions.Exit as exc:
                code = int(getattr(exc, "exit_code", 0))
            except click.exceptions.Abort:
                buf_err.write("Aborted!\n")
                code = 1
            except click.exceptions.ClickException as exc:
                exc.show()
                code = int(getattr(exc, "exit_code", 1))
            except Exception:  # noqa: BLE001 — a bad run must not kill the daemon
                traceback.print_exc()
                code = 1
    finally:
        cli.console = old_console
        try:
            os.chdir(old_cwd)
        except OSError:
            pass
        os.environ.clear()
        os.environ.update(old_env)

    return {
        "ok": True,
        "exit_code": int(code),
        "stdout": buf_out.getvalue(),
        "stderr": buf_err.getvalue(),
    }


def serve(idle_timeout: float = 1800.0) -> int:
    os.environ["LOGLENS_DAEMON"] = "0"

    if d.is_running():  # a healthy current-version daemon already owns the socket
        return 0

    d._remove_state()
    sock, state = d._bind_listener()
    d._write_state(state)
    token = state["token"]

    sys.stderr.write(
        f"[loglens] daemon {__version__} up (pid {os.getpid()}, "
        f"{state['transport']}); idle-timeout {int(idle_timeout)}s\n"
    )
    sys.stderr.flush()

    _warmup()  # warm before accepting, so request one is fast too

    sock.settimeout(idle_timeout)
    stopping = False
    try:
        while not stopping:
            try:
                conn, _ = sock.accept()
            except TimeoutError:
                sys.stderr.write("[loglens] daemon idle timeout — shutting down\n")
                break
            except OSError:
                break
            with conn:
                try:
                    req = d._recv(conn)
                except OSError:
                    continue
                if not req or req.get("token") != token:
                    try:
                        d._send(conn, {"ok": False, "error": "unauthorized"})
                    except OSError:
                        pass
                    continue
                op = req.get("op")
                if op == "ping":
                    d._send(
                        conn,
                        {
                            "ok": True,
                            "version": __version__,
                            "pid": os.getpid(),
                            "started": state["started"],
                            "transport": state["transport"],
                        },
                    )
                elif op == "shutdown":
                    d._send(conn, {"ok": True})
                    stopping = True
                elif op == "run":
                    try:
                        d._send(conn, _handle_run(req))
                    except OSError:
                        pass
                else:
                    d._send(conn, {"ok": False, "error": f"unknown op {op!r}"})
    finally:
        try:
            sock.close()
        finally:
            d._remove_state()
    return 0
