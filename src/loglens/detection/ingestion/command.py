from __future__ import annotations

import asyncio
import logging
import shlex
import sys
from collections.abc import AsyncIterator, Sequence

logger = logging.getLogger("loglens.ingestion.command")

CmdType = str | Sequence[str]

_EOF = object()


class CommandError(RuntimeError):
    def __init__(self, cmd: str, returncode: int | None, stderr_tail: str = ""):
        self.cmd = cmd
        self.returncode = returncode
        self.stderr_tail = stderr_tail
        msg = f"command exited with code {returncode}: {cmd}"
        if stderr_tail:
            msg += f"\n{stderr_tail}"
        super().__init__(msg)


class AsyncCommandReader:
    def __init__(self, cmd: CmdType, *, include_stderr: bool = True, kill_timeout: float = 3.0):
        self.cmd = cmd
        self.include_stderr = include_stderr
        self.kill_timeout = kill_timeout
        self.returncode: int | None = None
        self._stderr_tail: list[str] = []

    @property
    def display(self) -> str:
        if isinstance(self.cmd, str):
            return self.cmd
        return " ".join(shlex.quote(p) for p in self.cmd)

    async def _spawn(self) -> asyncio.subprocess.Process:
        stderr = asyncio.subprocess.PIPE if self.include_stderr else asyncio.subprocess.DEVNULL
        if isinstance(self.cmd, str):
            if sys.platform == "win32":
                command = (
                    "[Console]::OutputEncoding = "
                    "[System.Text.UTF8Encoding]::new(); "
                    f"{self.cmd}"
                )
                return await asyncio.create_subprocess_exec(
                    "powershell.exe",
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=stderr,
                )
            return await asyncio.create_subprocess_shell(
                self.cmd, stdout=asyncio.subprocess.PIPE, stderr=stderr
            )
        return await asyncio.create_subprocess_exec(
            *self.cmd, stdout=asyncio.subprocess.PIPE, stderr=stderr
        )

    async def __aiter__(self) -> AsyncIterator[str]:
        try:
            proc = await self._spawn()
        except FileNotFoundError as exc:
            raise CommandError(self.display, 127, str(exc)) from exc

        queue: asyncio.Queue = asyncio.Queue()
        produced_any = False

        async def pump(stream, is_stderr: bool):
            try:
                if stream is not None:
                    async for raw in stream:
                        line = raw.decode("utf-8", "replace").rstrip("\r\n")
                        if is_stderr:
                            self._stderr_tail.append(line)
                            if len(self._stderr_tail) > 20:
                                self._stderr_tail.pop(0)
                        await queue.put(line)
            finally:
                await queue.put(_EOF)

        n_streams = 2 if self.include_stderr else 1
        tasks = [asyncio.ensure_future(pump(proc.stdout, False))]
        if self.include_stderr:
            tasks.append(asyncio.ensure_future(pump(proc.stderr, True)))

        eof_seen = 0
        try:
            while eof_seen < n_streams:
                item = await queue.get()
                if item is _EOF:
                    eof_seen += 1
                    continue
                produced_any = True
                yield item
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self._terminate(proc)
            self.returncode = proc.returncode

        if self.returncode not in (0, None) and not produced_any:
            raise CommandError(self.display, self.returncode, "\n".join(self._stderr_tail[-5:]))

    async def _terminate(self, proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        if sys.platform == "win32":
            try:
                killer = await asyncio.create_subprocess_exec(
                    "taskkill",
                    "/PID", str(proc.pid),
                    "/T",
                    "/F",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await killer.wait()
            except ProcessLookupError:
                pass

            await proc.wait()
            return
        try:
            proc.terminate()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(proc.wait(), timeout=self.kill_timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except Exception as exc:
                logger.debug("proc.wait() after kill failed: %s", exc)


async def stream_command(cmd: CmdType, *, include_stderr: bool = True) -> AsyncIterator[str]:
    reader = AsyncCommandReader(cmd, include_stderr=include_stderr)
    async for line in reader:
        yield line
