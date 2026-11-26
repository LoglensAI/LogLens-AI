"""AsyncFileReader: same lines as before, read in batches (not one thread hop per line).

Reading line by line through an async file wrapper cost ~100 µs per line and was
~38% of an exact-mode run on 100k lines (Stage 1 QA audit). These tests pin the
line semantics and guard against per-line hops coming back.
"""

from __future__ import annotations

import asyncio
import gzip

import pytest

from loglens.detection.ingestion.file import AsyncFileReader


def _read(path) -> list[str]:
    async def go():
        return [line async for line in AsyncFileReader(str(path))]

    return asyncio.run(go())


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"", []),
        (b"only line, no newline", ["only line, no newline"]),
        (b"a 1\r\nb 2\r\nc 3\r\n", ["a 1", "b 2", "c 3"]),
        (b"x\ry\rz\n", ["x", "y", "z"]),  # lone CR is a line break (universal newlines)
        (b"\n\n a \n\n", ["", "", " a ", ""]),
        (b"ok\n\xff broken \xc3\x28\nend\n", ["ok", "� broken �(", "end"]),
        ("2024 INFO 用户 ✅ done\n".encode(), ["2024 INFO 用户 ✅ done"]),
        (b"\xef\xbb\xbfstart\nnext\n", ["﻿start", "next"]),  # BOM kept, as before
    ],
)
def test_lines_match_previous_semantics(tmp_path, raw, expected):
    p = tmp_path / "in.log"
    p.write_bytes(raw)
    assert _read(p) == expected


def test_gzip_is_decompressed(tmp_path):
    p = tmp_path / "in.log.gz"
    with gzip.open(p, "wb") as g:
        g.write(b"g1\ng2\r\ng3\n")
    assert _read(p) == ["g1", "g2", "g3"]


def test_reads_in_batches_not_per_line(tmp_path, monkeypatch):
    n = 50_000
    p = tmp_path / "big.log"
    p.write_text("".join(f"2024-01-01 00:00:00 INFO line {i}\n" for i in range(n)))

    hops = 0
    real = asyncio.BaseEventLoop.run_in_executor

    def counting(self, executor, func, *args):
        nonlocal hops
        hops += 1
        return real(self, executor, func, *args)

    monkeypatch.setattr(asyncio.BaseEventLoop, "run_in_executor", counting)
    lines = _read(p)
    assert len(lines) == n
    assert lines[-1] == f"2024-01-01 00:00:00 INFO line {n - 1}"
    # ~1.7 MB file in 1 MiB batches: open + a few reads, never one hop per line.
    assert hops < 10, hops
