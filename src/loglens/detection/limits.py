from __future__ import annotations

import math
import os

ENV_MAX_SYNONYM_VOCAB = "LOGLENS_MAX_SYNONYM_VOCAB"
ENV_MAX_CLUSTER_GROUPS = "LOGLENS_MAX_CLUSTER_GROUPS"

DEFAULT_MAX_SYNONYM_VOCAB = 2_000
DEFAULT_MAX_CLUSTER_GROUPS = 40_000

_REFERENCE_RAM_BYTES = 8 * 1024**3
_AUTO_MIN_FACTOR = 0.25
_AUTO_MAX_FACTOR = 4.0


def _available_ram_bytes() -> int | None:
    try:
        import psutil

        return int(psutil.virtual_memory().available)
    except Exception:  # noqa: BLE001 - no psutil or unsupported platform: use default
        return None


def auto_cluster_groups(available_bytes: int | None = None) -> int:
    """Cluster-group cap scaled from available RAM (see module docstring)."""
    avail = _available_ram_bytes() if available_bytes is None else available_bytes
    if not avail or avail <= 0:
        return DEFAULT_MAX_CLUSTER_GROUPS
    factor = math.sqrt(avail / _REFERENCE_RAM_BYTES)
    factor = min(_AUTO_MAX_FACTOR, max(_AUTO_MIN_FACTOR, factor))
    return int(DEFAULT_MAX_CLUSTER_GROUPS * factor)


def parse_cap(raw: str | None) -> int | str | None:
    """Parse a cap value: a positive int, ``"auto"``, or ``None`` if invalid/unset."""
    if raw is None:
        return None
    raw = raw.strip().lower()
    if raw == "auto":
        return "auto"
    try:
        value = int(raw.replace("_", "").replace(",", ""))
    except ValueError:
        return None
    return value if value > 0 else None


def max_cluster_groups() -> int:
    value = parse_cap(os.environ.get(ENV_MAX_CLUSTER_GROUPS))
    if value == "auto":
        return auto_cluster_groups()
    if isinstance(value, int):
        return value
    return DEFAULT_MAX_CLUSTER_GROUPS


def max_synonym_vocab() -> int:
    value = parse_cap(os.environ.get(ENV_MAX_SYNONYM_VOCAB))
    if isinstance(value, int):
        return value
    return DEFAULT_MAX_SYNONYM_VOCAB
