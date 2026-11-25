from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]


def _load_prune():
    spec = importlib.util.spec_from_file_location(
        "loglens_prune", _ROOT / "packaging" / "pyinstaller" / "prune.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


prune = _load_prune()


@pytest.mark.parametrize(
    "path",
    [
        "torch/test/scalar_test",
        "torch/bin/test_api",
        "torch/bin/protoc",
        "torch/bin/protoc-3.21.12.0",
        "torch/include/ATen/ATen.h",
        "torch/share/cmake/Torch/TorchConfig.cmake",
        "torch/lib/libtorchbind_test.so",
        "torch/lib/libjitbackend_test.so",
        "torch/lib/libbackend_with_compiler.so",
        "torch/lib/libaoti_custom_ops.so",
        "torch/lib/libshm/socket.h",
        "torch\\lib\\torch_cpu.lib",  # Windows import library, backslash path
        "torch/utils/benchmark/utils/valgrind_wrapper/callgrind.h",
    ],
)
def test_build_only_files_are_dropped(path):
    assert prune.is_build_only(path)


@pytest.mark.parametrize(
    "path",
    [
        "torch/lib/libtorch_cpu.so",
        "torch/lib/libtorch_python.so",
        "torch/lib/libc10.so",
        "torch/lib/libshm.so",
        "torch/lib/libgomp.so.1",
        "torch\\lib\\torch_cpu.dll",
        "torch/lib/libtorch_cpu.dylib",
        "torch/bin/torch_shm_manager",
        "torch/_C.cpython-312-x86_64-linux-gnu.so",
        "torch/_inductor/codegen/cpp_prefix.h",  # read by torch.compile at runtime
        "torch/testing/_comparison.py",
        "loglens_models/all-MiniLM-L6-v2/model.safetensors",
        "transformers/models/bert/modeling_bert.py",
        "sklearn/tree/_tree.cpython-312-x86_64-linux-gnu.so",
        "loglens/assets/default_model.pkl",
    ],
)
def test_runtime_files_are_kept(path):
    assert not prune.is_build_only(path)


def test_prune_filters_toc_entries():
    toc = [
        ("torch/lib/libtorch_cpu.so", "/src/a", "BINARY"),
        ("torch/bin/test_jit", "/src/b", "DATA"),
        ("loglens/py.typed", "/src/c", "DATA"),
    ]
    kept, dropped = prune.prune(toc)
    assert dropped == 1
    assert [e[0] for e in kept] == ["torch/lib/libtorch_cpu.so", "loglens/py.typed"]


_NEURAL = ("torch", "sentence_transformers", "transformers", "tokenizers")

_PROBE = textwrap.dedent(
    """
    import sys
    NEURAL = {neural!r}
    attempts = []

    class Recorder:
        # Records (and blocks) any attempt to import a neural package, so the
        # test is meaningful whether or not torch is installed.
        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] in NEURAL:
                attempts.append(name)
                raise ImportError("blocked by test: " + name)
            return None

    sys.meta_path.insert(0, Recorder())
    from loglens.interface import cli
    for argv in {argvs!r}:
        try:
            cli.app(argv, standalone_mode=False)
        except BaseException:  # e.g. deep mode's "install sentence-transformers"
            pass
    print("ATTEMPTS=" + ",".join(attempts))
    """
)


def _neural_import_attempts(argvs: list[list[str]], tmp_path: Path) -> list[str]:
    script = _PROBE.format(neural=_NEURAL, argvs=argvs)
    env = {"LOGLENS_DAEMON": "0", "NO_COLOR": "1", "HOME": str(tmp_path), "PATH": ""}
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=180,
        env={**__import__("os").environ, **env},
        cwd=tmp_path,
    )
    line = [ln for ln in out.stdout.splitlines() if ln.startswith("ATTEMPTS=")]
    assert line, out.stdout + out.stderr
    return [a for a in line[-1].removeprefix("ATTEMPTS=").split(",") if a]


def test_non_deep_cli_never_imports_neural_stack(tmp_path):
    log = tmp_path / "app.log"
    log.write_text(
        "2024-01-01 00:00:00 INFO service started\n"
        "2024-01-01 00:00:01 ERROR connection refused host=db-1\n"
        "2024-01-01 00:00:02 FATAL kernel panic not syncing\n",
        encoding="utf-8",
    )
    attempts = _neural_import_attempts(
        [["version"], ["analyze", str(log), "--no-learn"], ["analyze", str(log), "--turbo"]],
        tmp_path,
    )
    assert attempts == [], f"non-deep run tried to import: {attempts}"


def test_deep_mode_does_reach_for_neural_stack(tmp_path):
    # Positive control: proves the recorder would catch an import.
    log = tmp_path / "app.log"
    log.write_text("2024-01-01 00:00:00 INFO service started\n", encoding="utf-8")
    attempts = _neural_import_attempts([["analyze", str(log), "--deep", "--no-learn"]], tmp_path)
    assert any(a.split(".")[0] == "sentence_transformers" for a in attempts), attempts
