import asyncio
import logging
import os
import subprocess
import sys

import pytest

import loglens.infrastructure.llm.rca as rca_mod
from loglens import LiveDetector, LogLensHandler, analyze, analyze_async
from loglens.detection.ingestion import AsyncCommandReader, CommandError
from loglens.infrastructure.llm import LLMResponse, TokenUsage

LINES = (
    [f"2024-01-01T00:00:{i:02d}Z INFO api request completed {i % 7}ms" for i in range(40)]
    + ["2024-01-01T00:01:00Z FATAL db disk failure raid degraded"]
    + [f"2024-01-01T00:01:{i:02d}Z ERROR db connection refused host=db-1" for i in range(1, 11)]
)


def test_analyze_lines_basic():
    r = analyze(lines=LINES)
    assert r.total == 51
    assert len(r.anomalies) >= 11  # FATAL + the ERROR storm
    assert r.anomalies[0].score >= r.anomalies[-1].score  # sorted
    levels = {a.level for a in r.anomalies}
    assert "FATAL" in levels and "ERROR" in levels
    assert all(a.reasons for a in r.anomalies)
    assert r.summary()["entries"] == 51


def test_analyze_requires_exactly_one_input(tmp_path):
    with pytest.raises(ValueError):
        analyze()
    with pytest.raises(ValueError):
        analyze("x.log", lines=["a"])


def test_analyze_file(tmp_path):
    p = tmp_path / "app.log"
    p.write_text("\n".join(LINES))
    r = analyze(str(p))
    assert r.total == 51 and len(r.anomalies) >= 11


def test_analyze_bounded_command():
    r = analyze(cmd="printf 'INFO ok\\nERROR payment gateway timeout\\n'")
    assert r.total == 2
    assert any(a.level == "ERROR" for a in r.anomalies)


def test_analyze_cmd_failure_raises():
    with pytest.raises(CommandError):
        analyze(cmd="definitely-not-a-real-command-xyz 2>/dev/null")


def test_analyze_async_inside_loop():
    async def go():
        return await analyze_async(lines=LINES)

    r = asyncio.run(go())
    assert len(r.anomalies) >= 11


def test_analyze_config_threshold_passthrough():
    lo = analyze(lines=LINES, threshold=0.60)
    hi = analyze(lines=LINES, threshold=0.95)
    assert len(hi.anomalies) <= len(lo.anomalies)


def test_live_detector_stream():
    det = LiveDetector(window=200, rescore_every=20, min_window=5)
    hits = []
    for i in range(60):
        hits += det.feed(f"2024-01-01T00:00:{i % 60:02d}Z INFO api request ok {i % 5}")
    hits += det.feed("2024-01-01T00:01:00Z FATAL db split-brain detected")
    for i in range(20):
        hits += det.feed(f"2024-01-01T00:01:{i + 1:02d}Z ERROR db connection refused")
    hits += det.flush()

    assert det.total == 81
    levels = [h.level for h in hits]
    assert "FATAL" in levels, "hard-flag level must surface"
    assert levels.count("ERROR") == 20, "whole error storm reported once each"
    assert "INFO" not in levels, "benign INFO must not spam the live feed"
    # exactly-once: no duplicate indices
    idxs = [h.index for h in hits]
    assert len(idxs) == len(set(idxs))


def test_live_detector_fatal_is_instant():
    det = LiveDetector(min_window=1000)  # windowed scoring effectively off
    hits = det.feed("2024-01-01T00:00:00Z FATAL kernel panic")
    hits += det.flush()  # parser buffers the first line (multiline logs)
    assert [h.level for h in hits] in (["FATAL"], ["CRITICAL"])
    assert "surfaced immediately" in hits[0].reasons[0]


def test_live_detector_window_eviction():
    det = LiveDetector(window=50, rescore_every=10, min_window=5)
    for i in range(300):
        det.feed(f"2024-01-01T00:00:00Z INFO ok {i % 3}")
    assert det.summary()["window"] <= 50


def test_logging_handler_callback_and_isolation():
    got, boom = [], []

    def cb(a):
        got.append(a)
        boom.append(1)
        raise RuntimeError("callback exploded")  # must never propagate

    h = LogLensHandler(on_anomaly=cb, min_window=5, rescore_every=10)
    lg = logging.getLogger("test.svc.iso")
    lg.addHandler(h)
    lg.setLevel(logging.DEBUG)
    lg.propagate = False
    try:
        for i in range(30):
            lg.info("heartbeat ok %d", i % 3)
        lg.critical("kernel panic null pointer")  # -> anomaly, cb raises
        for i in range(10):
            lg.info("heartbeat ok %d", i % 3)
        h.flush()
    finally:
        lg.removeHandler(h)

    assert len(got) >= 1
    assert got[0].level == "CRITICAL"
    assert h.summary()["entries"] == 41
    assert h.anomalies == got


def test_logging_handler_no_recursion_when_callback_logs():
    lg = logging.getLogger("test.svc.rec")

    def cb(a):
        lg.error("alerting about %s", a.message)  # logs to same logger

    h = LogLensHandler(on_anomaly=cb, min_window=5)
    lg.addHandler(h)
    lg.setLevel(logging.DEBUG)
    lg.propagate = False
    try:
        lg.critical("segfault in worker")  # would recurse if unguarded
    finally:
        lg.removeHandler(h)
    assert len(h.anomalies) == 1


def test_command_reader_bounded():
    async def go():
        return [ln async for ln in AsyncCommandReader("printf 'a\\nb\\nc\\n'")]

    assert asyncio.run(go()) == ["a", "b", "c"]


def test_command_reader_merges_stderr():
    async def go():
        r = AsyncCommandReader("echo out; echo err 1>&2")
        return sorted([ln async for ln in r])

    assert asyncio.run(go()) == ["err", "out"]


def test_command_reader_streaming_early_stop_kills_child():
    async def go():
        r = AsyncCommandReader("i=0; while true; do echo line $i; i=$((i+1)); sleep 0.02; done")
        seen = []
        async for ln in r:
            seen.append(ln)
            if len(seen) >= 5:
                break
        return seen

    seen = asyncio.run(go())
    assert len(seen) == 5


def test_command_reader_missing_binary():
    async def go():
        async for _ in AsyncCommandReader(["no-such-binary-xyz"]):
            pass

    with pytest.raises(CommandError):
        asyncio.run(go())


@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell watch smoke test runs on Windows")
def test_command_reader_windows_powershell_streams_and_stops(tmp_path):
    log = tmp_path / "app log.log"
    log.write_text("INFO startup complete\n", encoding="utf-8")
    escaped_path = str(log).replace("'", "''")
    reader = AsyncCommandReader(f"Get-Content -LiteralPath '{escaped_path}' -Wait")

    async def go():
        iterator = reader.__aiter__()
        try:
            return await anext(iterator)
        finally:
            await iterator.aclose()

    assert asyncio.run(go()) == "INFO startup complete"
    assert reader.returncode is not None


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only process-tree test")
def test_command_reader_terminate_kills_process_tree():
    async def go():
        reader = AsyncCommandReader(
            "Start-Process -FilePath 'ping.exe' "
            "-ArgumentList @('-t', '127.0.0.1'); "
            "Start-Sleep -Seconds 60"
        )

        proc = await reader._spawn()

        # Find the child PID created by PowerShell.
        child_pid = None
        try:
            output = await asyncio.create_subprocess_exec(
                "powershell.exe",
                "-NoProfile",
                "-Command",
                f"(Get-CimInstance Win32_Process -Filter "
                f"'ParentProcessId = {proc.pid}').ProcessId",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await output.communicate()
            child_pid = int(stdout.decode().strip().splitlines()[0])

            await reader._terminate(proc)

            check = await asyncio.create_subprocess_exec(
                "tasklist",
                "/FI", f"PID eq {child_pid}",
                "/FO", "CSV",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            result, _ = await check.communicate()

            assert str(child_pid).encode() not in result
        finally:
            if proc.returncode is None:
                await reader._terminate(proc)

    asyncio.run(go())

class _FakeLLMClient:
    def __init__(self, config):
        self.config = config

    def chat(self, messages):
        return LLMResponse(
            content="## Root cause\nThe database ran out of connections.",
            usage=TokenUsage(),
        )


@pytest.fixture
def fake_llm(monkeypatch):

    monkeypatch.setattr(rca_mod, "LLMClient", _FakeLLMClient)
    monkeypatch.setenv("LOGLENS_LLM_PROVIDER", "openai")
    monkeypatch.setenv("LOGLENS_LLM_MODEL", "test-model")
    monkeypatch.setenv("LOGLENS_LLM_API_KEY", "test-key")


def test_analysisresult_rca_ask_and_reports(fake_llm, tmp_path):
    r = analyze(lines=LINES)
    rca = r.rca()
    assert "Root cause" in rca.report and rca.anomalies_sent > 0
    ans = r.ask("what broke?")
    assert ans.report

    html = tmp_path / "report.html"
    r.save_html(str(html), rca=rca)
    text = html.read_text()
    assert "<html" in text.lower() and "Root cause" in text

    md = tmp_path / "rca.md"
    r.save_rca(str(md), rca=rca)
    assert "Root cause" in md.read_text()


def test_livedetector_rca_and_html(fake_llm, tmp_path):
    det = LiveDetector(window=200, rescore_every=20, min_window=5)
    for ln in LINES:
        det.feed(ln)
    det.flush()
    # retained-for-post-processing contract: everything counted is kept
    assert len(det.anomalies) == det.anomaly_count >= 11
    rca = det.rca(source_name="docker logs -f api")
    assert rca.anomalies_sent == len(det.anomalies)
    p = det.save_html(str(tmp_path / "live.html"), rca=rca)
    assert "Root cause" in open(p).read()


def test_watch_cli_html_report(fake_llm, tmp_path):

    env = dict(os.environ)
    out_html = tmp_path / "watch.html"
    out_md = tmp_path / "watch_rca.md"
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            # patch the LLM inside the subprocess, then invoke the CLI
            "import loglens.infrastructure.llm.rca as m;\n"
            "from loglens.infrastructure.llm import TokenUsage, LLMResponse\n"
            "class F:\n"
            "  def __init__(s,c): pass\n"
            "  def chat(s,msgs): return LLMResponse(content='Root cause: db pool exhausted.', usage=TokenUsage())\n"
            "m.LLMClient=F\n"
            "import sys; from loglens.interface.cli import app\n"
            f"sys.argv=['loglens','watch',"
            f"\"printf 'INFO ok\\\\nFATAL db split-brain detected\\\\n"
            f"ERROR db connection refused\\\\n'\","
            f"'--quiet','--rca','--rca-out',{str(out_md)!r},"
            f"'--html-report',{str(out_html)!r}]\n"
            "app()",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert "WATCH SUMMARY" in proc.stdout, proc.stdout + proc.stderr
    assert "Root cause" in proc.stdout
    assert out_html.exists() and "Root cause" in out_html.read_text()
    assert out_md.exists()
