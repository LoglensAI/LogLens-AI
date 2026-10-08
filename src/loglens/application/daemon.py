from __future__ import annotations

import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any

import platformdirs

from loglens import __version__

_STATE_NAME = "daemon.json"
_SOCK_NAME = "daemon.sock"
_IS_WINDOWS = os.name == "nt"
_USE_UNIX = hasattr(socket, "AF_UNIX") and not _IS_WINDOWS

_viable_cache: bool | None = None


def _is_wsl() -> bool:
    try:
        with open("/proc/version", encoding="utf-8", errors="ignore") as fh:
            return "microsoft" in fh.read().lower()
    except OSError:
        return False


def local_ipc_viable() -> bool:
    global _viable_cache
    if _viable_cache is not None:
        return _viable_cache
    _viable_cache = _probe_bind()
    return _viable_cache


def _probe_bind() -> bool:
    if _is_wsl():
        return False
    try:
        if _USE_UNIX:
            probe = os.path.join(_runtime_dir(), f".probe.{os.getpid()}.sock")
            try:
                os.remove(probe)
            except OSError:
                pass
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.bind(probe)
                return True
            except OSError:
                return False
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
                try:
                    os.remove(probe)
                except OSError:
                    pass
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(("127.0.0.1", 0))
                return True
            except OSError:
                return False
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
    except OSError:
        return False


def _runtime_dir() -> str:

    for path in (
        platformdirs.user_runtime_dir("loglens", "loglens"),
        platformdirs.user_cache_dir("loglens", "loglens"),
    ):
        try:
            os.makedirs(path, exist_ok=True)
            return path
        except OSError:
            continue
    # Last resort: temp dir (still per-user on typical setups).
    path = os.path.join(tempfile.gettempdir(), "loglens")
    os.makedirs(path, exist_ok=True)
    return path


def _state_path() -> str:
    return os.path.join(_runtime_dir(), _STATE_NAME)


def _read_state() -> dict[str, Any] | None:
    try:
        with open(_state_path(), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_state(state: dict[str, Any]) -> None:
    path = _state_path()
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _remove_state() -> None:
    for p in (_state_path(), os.path.join(_runtime_dir(), _SOCK_NAME)):
        try:
            os.remove(p)
        except OSError:
            pass


# --- cooldown: if the daemon can't start in this environment (e.g. WSL where
# the loopback socket is filtered), remember that for a few minutes so every
# subsequent command runs in-process immediately instead of re-waiting. --------
_COOLDOWN_NAME = "daemon.nodaemon"
_COOLDOWN_SECS = 300.0


def _cooldown_path() -> str:
    return os.path.join(_runtime_dir(), _COOLDOWN_NAME)


def _in_cooldown() -> bool:
    try:
        age = time.time() - os.path.getmtime(_cooldown_path())
        return age < _COOLDOWN_SECS
    except OSError:
        return False


def _set_cooldown() -> None:
    try:
        with open(_cooldown_path(), "w", encoding="utf-8") as fh:
            fh.write(str(time.time()))
    except OSError:
        pass


def _clear_cooldown() -> None:
    try:
        os.remove(_cooldown_path())
    except OSError:
        pass


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if _IS_WINDOWS:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _send(conn: socket.socket, obj: dict[str, Any]) -> None:
    body = json.dumps(obj).encode("utf-8")
    conn.sendall(struct.pack(">I", len(body)) + body)


def _recv(conn: socket.socket) -> dict[str, Any] | None:
    header = _recv_exactly(conn, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > 512 * 1024 * 1024:  # guard against garbage
        return None
    body = _recv_exactly(conn, length)
    if body is None:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError:
        return None


def _recv_exactly(conn: socket.socket, n: int) -> bytes | None:
    chunks: list[bytes] = []
    got = 0
    while got < n:
        chunk = conn.recv(min(n - got, 1 << 20))
        if not chunk:
            return None
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def _open_client(state: dict[str, Any], timeout: float = 5.0) -> socket.socket | None:
    try:
        if state.get("transport") == "unix":
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(state["path"])
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(("127.0.0.1", int(state["port"])))
        return sock
    except (OSError, KeyError, ValueError):
        return None


def _request(op: str, timeout: float = 300.0, **payload: Any) -> dict[str, Any] | None:
    state = _read_state()
    if not state or not _pid_alive(int(state.get("pid", 0))):
        return None
    sock = _open_client(state, timeout=timeout)
    if sock is None:
        return None
    try:
        req = {"token": state.get("token", ""), "op": op, **payload}
        _send(sock, req)
        return _recv(sock)
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def is_running() -> bool:
    resp = _request("ping", timeout=3.0)
    return bool(resp and resp.get("ok") and resp.get("version") == __version__)


def status() -> dict[str, Any] | None:
    resp = _request("ping", timeout=3.0)
    if not resp or not resp.get("ok"):
        return None
    return resp


def stop() -> bool:
    resp = _request("shutdown", timeout=3.0)
    ok = bool(resp and resp.get("ok"))
    if ok:
        for _ in range(20):
            if not is_running():
                break
            time.sleep(0.05)
    return ok


def ensure_running(spawn: bool = True, wait: float = 3.0) -> bool:
    if is_running():
        _clear_cooldown()
        return True
    # Environment can't host the daemon (e.g. WSL) → don't even try; no stall.
    if not local_ipc_viable():
        return False
    # A recent failed start → don't pay the wait again; run in-process now.
    if _in_cooldown():
        return False
    stale = _read_state()
    if stale is not None:
        if stale.get("version") != __version__:
            stop()
        _remove_state()
    if not spawn:
        return False
    _spawn_detached()
    deadline = time.time() + wait
    try:
        while time.time() < deadline:
            if is_running():
                _clear_cooldown()
                return True
            time.sleep(0.1)
    except KeyboardInterrupt:
        _set_cooldown()
        return False
    # Gave the daemon its chance and it didn't answer — remember that.
    _set_cooldown()
    return False


def _spawn_detached() -> None:
    if getattr(sys, "frozen", False):
        cmd = [sys.executable, "daemon", "start", "--foreground"]
    else:
        cmd = [sys.executable, "-m", "loglens.interface.cli", "daemon", "start", "--foreground"]

    log_path = os.path.join(_runtime_dir(), "daemon.log")
    try:
        logf = open(log_path, "a", encoding="utf-8")  # noqa: SIM115 (kept open for child)
    except OSError:
        logf = subprocess.DEVNULL  # type: ignore[assignment]

    kwargs: dict[str, Any] = {"stdout": logf, "stderr": logf, "stdin": subprocess.DEVNULL}
    if _IS_WINDOWS:
        kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    try:
        subprocess.Popen(cmd, **kwargs)  # noqa: S603
    except OSError:
        pass


def run_via_daemon(argv: list[str], spawn: bool = True) -> int | None:
    if not ensure_running(spawn=spawn):
        return None
    resp = _request(
        "run",
        argv=argv,
        cwd=os.getcwd(),
        env=dict(os.environ),
        tty=sys.stdout.isatty(),
        width=_term_width(),
    )
    if not resp or not resp.get("ok"):
        return None
    sys.stdout.write(resp.get("stdout", ""))
    sys.stdout.flush()
    sys.stderr.write(resp.get("stderr", ""))
    sys.stderr.flush()
    return int(resp.get("exit_code", 0))


def _term_width() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return int(os.environ.get("COLUMNS", "100") or "100")


def _bind_listener() -> tuple[socket.socket, dict[str, Any]]:
    token = secrets.token_hex(16)
    if _USE_UNIX:
        path = os.path.join(_runtime_dir(), _SOCK_NAME)
        try:
            os.remove(path)
        except OSError:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        state = {"transport": "unix", "path": path, "port": 0}
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        state = {"transport": "tcp", "path": "", "port": sock.getsockname()[1]}
    sock.listen(16)
    state.update(
        {
            "pid": os.getpid(),
            "token": token,
            "version": __version__,
            "started": time.time(),
        }
    )
    return sock, state
