from __future__ import annotations

import re
import sys

from typer.testing import CliRunner

from loglens import __version__
from loglens.interface.cli import app

runner = CliRunner()


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "LogLens" in result.output


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in strip_ansi(result.output)


def main() -> int:
    checks = [test_help, test_version]
    for check in checks:
        check()
        print(f"[ci-smoke] {check.__name__}: ok")
    print(f"[ci-smoke] all {len(checks)} CLI smoke checks passed (version {__version__})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
