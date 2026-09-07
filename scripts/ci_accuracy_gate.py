import re
from typer.testing import CliRunner
from loglens.cli import app
from loglens import __version__
runner = CliRunner()

def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "LogLens" in result.output


def strip_ansi(text: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in strip_ansi(result.output)

def test_hello():
    result = runner.invoke(app, ["hello"])
    assert result.exit_code == 0
    assert "alive" in result.output