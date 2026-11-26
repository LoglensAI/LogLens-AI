from __future__ import annotations

import pytest

from loglens.application.parallel_scan import parallel_analyze_file
from loglens.detection.turbo import scan_file

N = 3000


@pytest.fixture
def crlf_log(tmp_path):
    lines = [f"2026-01-01 10:00:{i % 60:02d} INFO 用户 request {i} ok" for i in range(N)]
    lines.append("2026-01-01 10:59:00 FATAL db kernel panic: out of memory")
    p = tmp_path / "win.log"
    p.write_bytes(("\r\n".join(lines) + "\r\n").encode("utf-8"))
    return str(p)


@pytest.mark.parametrize("workers", [1, 3, 7])
def test_turbo_counts_every_crlf_line_once(crlf_log, workers):
    res = scan_file(crlf_log, workers=workers)
    assert res.parsed_lines == N + 1


def test_parallel_counts_every_crlf_line_once(crlf_log):
    res = parallel_analyze_file(crlf_log, workers=2, slice_lines=500)
    assert res["lines_parsed"] == N + 1
