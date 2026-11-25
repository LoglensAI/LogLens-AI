from __future__ import annotations

import fnmatch

# Directories inside the bundle that are never needed at runtime.
_DROP_DIRS = (
    "torch/include/",  # C/C++ headers for building extensions
    "torch/share/",  # CMake package config
    "torch/test/",  # C++ gtest executables
)

# torch/bin holds protoc and C++ test executables; only the shared-memory
# manager is used at runtime (torch.multiprocessing tensor sharing).
_KEEP_IN_TORCH_BIN = {"torch_shm_manager", "torch_shm_manager.exe"}

# Test fixtures and import/static libraries shipped inside torch/lib.
_DROP_TORCH_LIB_GLOBS = (
    "*test*.so",
    "*test*.dll",
    "*test*.dylib",
    "libbackend_with_compiler.*",
    "backend_with_compiler.*",
    "libaoti_custom_ops.*",
    "aoti_custom_ops.*",
    "*.lib",  # Windows import libraries (link-time only)
    "*.a",  # static libraries
)

# File types that are only useful when compiling against torch.
_DROP_SUFFIXES = (".h", ".hpp", ".cuh", ".cmake")


def is_build_only(dest: str) -> bool:
    """True if a bundle path is a build-time-only torch file safe to drop."""
    p = dest.replace("\\", "/")
    if not p.startswith("torch/"):
        return False
    if p.startswith(_DROP_DIRS):
        return True
    # torch.compile's C++ codegen reads headers under _inductor at runtime.
    if p.endswith(_DROP_SUFFIXES) and not p.startswith("torch/_inductor/"):
        return True
    if p.startswith("torch/bin/"):
        return p.rsplit("/", 1)[-1] not in _KEEP_IN_TORCH_BIN
    if p.startswith("torch/lib/") and p.count("/") == 2:
        name = p.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(name, g) for g in _DROP_TORCH_LIB_GLOBS)
    return False


def prune(toc: list) -> tuple[list, int]:
    """Filter a PyInstaller TOC list; returns (kept entries, number dropped)."""
    kept = [entry for entry in toc if not is_build_only(entry[0])]
    return kept, len(toc) - len(kept)
