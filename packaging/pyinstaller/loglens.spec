# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the LogLens standalone binary.

Produces a self-contained `loglens` (onedir) that needs no system Python. The
same spec builds on Linux, macOS and Windows in CI.

Neural (deep) mode is bundled when LOGLENS_BUNDLE_DEEP=1, so a system-wide
install has `--deep` working out of the box with no extra `pip install`. When a
model directory is provided via LOGLENS_BUNDLED_MODEL_DIR it is bundled too, so
deep mode works fully offline on first run (no HuggingFace download).

Build:
    pip install pyinstaller
    # core only:
    pyinstaller packaging/pyinstaller/loglens.spec --noconfirm
    # with neural bundled:
    LOGLENS_BUNDLE_DEEP=1 LOGLENS_BUNDLED_MODEL_DIR=./_models \
        pyinstaller packaging/pyinstaller/loglens.spec --noconfirm

Output: dist/loglens/  (contains the `loglens` executable + everything it needs)
"""

import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

_here = os.path.dirname(os.path.abspath(SPEC))  # noqa: F821 (SPEC injected by PyInstaller)

# --- always bundled: the app + its ML core -------------------------------- #
hiddenimports = []
for pkg in ("loglens", "sklearn", "scipy", "joblib", "numpy"):
    # loglens uses lazy imports (_load); sklearn pulls submodules dynamically —
    # PyInstaller's static analysis misses both, so collect them explicitly.
    hiddenimports += collect_submodules(pkg)

datas = collect_data_files("loglens")  # includes assets/default_model.pkl, py.typed

# --- optional: neural / deep mode ----------------------------------------- #
_bundle_deep = os.environ.get("LOGLENS_BUNDLE_DEEP", "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
if _bundle_deep:
    for pkg in ("sentence_transformers", "transformers", "tokenizers", "torch", "huggingface_hub"):
        try:
            hiddenimports += collect_submodules(pkg)
            datas += collect_data_files(pkg)
        except Exception as exc:  # a missing optional dep shouldn't kill the build
            print(f"[loglens.spec] skipping {pkg}: {exc}")
    _model_dir = os.environ.get("LOGLENS_BUNDLED_MODEL_DIR", "").strip()
    if _model_dir:
        # PyInstaller resolves relative `datas` sources against the spec file's
        # directory, but the model is downloaded to the CWD (repo root) in CI, so
        # make it absolute to avoid a "not found" mismatch.
        _model_dir = os.path.abspath(_model_dir)
        if os.path.isdir(_model_dir):
            # Shipped alongside the binary; deep mode points here so it works offline.
            datas += [(_model_dir, "loglens_models")]
        else:
            print(f"[loglens.spec] LOGLENS_BUNDLED_MODEL_DIR={_model_dir} not found; "
                  "neural model not bundled (deep mode will download on first use).")

# torch is heavy and platform-specific; let PyInstaller's hooks handle it when
# present, but never try to bundle it when deep isn't requested.
excludes = [] if _bundle_deep else ["torch", "transformers", "sentence_transformers", "tokenizers"]

block_cipher = None

a = Analysis(
    [os.path.join(_here, "entry.py")],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="loglens",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="loglens",
)
