from __future__ import annotations

import importlib
import re
import time

import pytest

from loglens.detection.parser import MAX_LINE_CHARS, clip_line, detect_format, parse_line

# Every module-level regex in the code that runs over raw log text.
_MODULES = [
    "loglens.detection.parser",
    "loglens.detection.templates",
    "loglens.detection.trace",
    "loglens.detection.diagnosis",
    "loglens.domain.scoring",
    "loglens.infrastructure.alerts",
]

# Shapes that trigger catastrophic backtracking in common log regexes: long runs
# of word chars, path chars, digits, quotes, '=' and separators.
_N = 20_000
_ADVERSARIAL = [
    "x" * _N,
    "a1" * (_N // 2),
    "1" * _N,
    "a/" * (_N // 2),
    "a." * (_N // 2),
    "a-" * (_N // 2),
    "\\" * _N,
    '"' * _N,
    "'" * _N,
    "=" * _N,
    "a=" * (_N // 2),
    " " * _N + "x",
    "at " + "x" * _N,
    'File "' + "x" * _N,
    "0x" + "f" * _N + "g",
    "2026-01-01 " * (_N // 11),
]


def _patterns():
    for name in _MODULES:
        mod = importlib.import_module(name)
        for attr, val in vars(mod).items():
            if isinstance(val, re.Pattern):
                yield f"{name}.{attr}", val
            elif isinstance(val, (list, tuple)):
                for i, item in enumerate(val):
                    pat = item[0] if isinstance(item, tuple) and item else item
                    if isinstance(pat, re.Pattern):
                        yield f"{name}.{attr}[{i}]", pat


_ALL = list(_patterns())


def test_patterns_were_collected():
    assert len(_ALL) > 30


@pytest.mark.parametrize(("name", "pat"), _ALL, ids=[n for n, _ in _ALL])
def test_regex_is_linear_on_adversarial_input(name, pat):
    worst = 0.0
    for s in _ADVERSARIAL:
        t0 = time.perf_counter()
        pat.search(s)
        pat.sub("", s)
        worst = max(worst, time.perf_counter() - t0)
    # Linear regexes take a few ms on 20k chars; quadratic ones take seconds.
    assert worst < 0.5, f"{name} took {worst:.2f}s on a {_N}-char line (catastrophic backtracking)"


def test_long_line_parses_quickly_and_is_clipped():
    line = "2026-01-01 10:00:00 ERROR " + "x" * 2_000_000
    t0 = time.perf_counter()
    fmt = detect_format(line)
    entry = parse_line(line, fmt)
    assert time.perf_counter() - t0 < 2.0
    assert entry is not None
    assert len(entry.raw) <= MAX_LINE_CHARS + 40
    assert entry.raw.endswith("chars]")


def test_clip_line_leaves_normal_lines_alone():
    assert clip_line("short") == "short"
    long = "y" * (MAX_LINE_CHARS + 10)
    assert clip_line(long).endswith("…[+10 chars]")
