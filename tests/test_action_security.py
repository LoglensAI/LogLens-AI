"""The GitHub Action must not let untrusted inputs or log text run commands.

Regression tests for the Stage 1 QA finding that action.yml pasted
``${{ inputs.* }}`` straight into bash ``run:`` scripts. Inputs now reach the
scripts only through environment variables, are quoted, and are validated.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ACTION = ROOT / "action.yml"

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def _run_scripts() -> dict[str, str]:
    """Map step name -> its `run: |` script, read without a YAML library."""
    lines = ACTION.read_text(encoding="utf-8").splitlines()
    scripts: dict[str, str] = {}
    name = ""
    i = 0
    while i < len(lines):
        m = re.match(r"\s*- name:\s*(.+)$", lines[i])
        if m:
            name = m.group(1).strip()
        m = re.match(r"^(\s*)run:\s*\|\s*$", lines[i])
        if m:
            indent = len(m.group(1))
            body = []
            i += 1
            while i < len(lines) and (
                not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent
            ):
                body.append(lines[i])
                i += 1
            pad = min((len(b) - len(b.lstrip()) for b in body if b.strip()), default=0)
            scripts[name] = "\n".join(b[pad:] for b in body) + "\n"
            continue
        i += 1
    return scripts


def test_no_expressions_inside_run_scripts():
    scripts = _run_scripts()
    assert {"Validate inputs", "Install LogLens AI", "Analyze logs"} <= set(scripts)
    offenders = {n: s for n, s in scripts.items() if "${{" in s}
    assert not offenders, f"expressions pasted into shell source: {sorted(offenders)}"


VALID = {
    "INPUT_SOURCE": "logs/*.log",
    "INPUT_MODE": "fast",
    "INPUT_FAIL_ON": "error",
    "INPUT_MIN_SCORE": "0",
    "INPUT_LIMIT": "25",
    "INPUT_VERSION": "",
}


def _bash(script: str, env: dict[str, str], cwd: pathlib.Path) -> subprocess.CompletedProcess:
    full = {"PATH": os.environ.get("PATH", ""), "HOME": str(cwd), **env}
    return subprocess.run(
        ["bash", "-e", "-c", script], env=full, cwd=cwd, capture_output=True, text=True
    )


@needs_bash
def test_validation_accepts_normal_inputs(tmp_path):
    r = _bash(_run_scripts()["Validate inputs"], VALID, tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    for extra in (
        {"INPUT_MODE": "TURBO", "INPUT_FAIL_ON": "Critical"},
        {"INPUT_MIN_SCORE": "0.7"},
        {"INPUT_MIN_SCORE": ".5"},
        {"INPUT_MIN_SCORE": "1.0"},
        {"INPUT_FAIL_ON": ""},
        {"INPUT_VERSION": "0.13.1"},
        {"INPUT_VERSION": "1.0.0rc1"},
    ):
        r = _bash(_run_scripts()["Validate inputs"], {**VALID, **extra}, tmp_path)
        assert r.returncode == 0, (extra, r.stdout + r.stderr)


PAYLOAD = '"; touch PWNED; echo "'


@needs_bash
@pytest.mark.parametrize(
    "field", ["INPUT_MODE", "INPUT_FAIL_ON", "INPUT_MIN_SCORE", "INPUT_LIMIT", "INPUT_VERSION"]
)
def test_validation_rejects_injection_without_running_it(tmp_path, field):
    r = _bash(_run_scripts()["Validate inputs"], {**VALID, field: PAYLOAD}, tmp_path)
    assert r.returncode != 0
    assert not (tmp_path / "PWNED").exists()
    # the error names the input but never echoes the untrusted value back
    assert "PWNED" not in r.stdout + r.stderr


@needs_bash
@pytest.mark.parametrize("field", ["INPUT_MIN_SCORE", "INPUT_LIMIT"])
@pytest.mark.parametrize("bad", ["1.5", "-1", "abc", "", "1e3"])
def test_validation_rejects_bad_numbers(tmp_path, field, bad):
    r = _bash(_run_scripts()["Validate inputs"], {**VALID, field: bad}, tmp_path)
    assert r.returncode != 0, (field, bad)


@needs_bash
def test_analyze_step_passes_source_verbatim_and_runs_nothing(tmp_path):
    """`source` is free text (paths/globs), so it can't be allow-listed. It must
    reach gh_analyze.py as one plain argument and never be executed."""
    stub_dir = tmp_path / "action" / "ci"
    stub_dir.mkdir(parents=True)
    argv_file = tmp_path / "argv.txt"
    (stub_dir / "gh_analyze.py").write_text(
        "import sys, pathlib\n"
        f"pathlib.Path({str(argv_file)!r}).write_text('\\x00'.join(sys.argv[1:]))\n"
    )
    out = tmp_path / "gh_output"
    out.write_text("")
    # `python` must be a real interpreter for the step; point it at this one.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "python").symlink_to(sys.executable)
    evil_source = "logs/$(touch PWNED).log\n`touch PWNED2`; touch PWNED3"
    env = {
        **VALID,
        "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
        "ACTION_PATH": str(tmp_path / "action"),
        "INPUT_SOURCE": evil_source,
        "INPUT_SARIF": "true",
        "INPUT_COMMENT_ON_PR": "false",
        "INPUT_UPLOAD_REPORT": "true; touch PWNED4",
        "GITHUB_OUTPUT": str(out),
    }
    r = subprocess.run(
        ["bash", "-c", _run_scripts()["Analyze logs"]],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert not list(tmp_path.glob("PWNED*")), "an injected command ran"
    args = argv_file.read_text().split("\x00")
    assert args[args.index("--source") + 1] == evil_source
    assert "--sarif" in args  # exact "true" still enables a flag
    assert "--report-json" not in args  # "true; touch ..." is not "true"
    assert "exit-code=0" in out.read_text()


@pytest.fixture(scope="module")
def gh():
    spec = importlib.util.spec_from_file_location("gh_analyze", ROOT / "ci" / "gh_analyze.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_annotations_cannot_inject_workflow_commands(gh, capsys):
    """A JSON log's message can contain real newlines. Unescaped, the text after
    one would be read by the runner as a new workflow command."""
    gh._emit_annotations(
        {
            "anomalies": [
                {
                    "level": "ERROR",
                    "service": "api,evil::x",
                    "message": "boom\n::add-mask::secret\r\n::stop-commands::tok 100%",
                    "reasons": [],
                }
            ]
        }
    )
    out = capsys.readouterr().out
    assert out.count("\n") == 1  # exactly one command line was printed
    assert "\n::add-mask::" not in out and "\r" not in out
    assert "%0A::add-mask::secret%0D%0A::stop-commands::tok 100%25" in out
    assert "title=LogLens%3A ERROR in api%2Cevil%3A%3Ax::" in out
