from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Sequence

from loglens.detection.templates import template_key
from loglens.domain.models import LogEntry

SCHEMA = "loglens.baseline.v1"
_MAX_TEMPLATES = 200_000


def default_state_dir() -> str:
    env = os.environ.get("LOGLENS_STATE_DIR")
    if env:
        return env
    return os.path.join(os.path.expanduser("~"), ".loglens", "baselines")


def baseline_key(source: str, profile: str = "") -> str:
    if profile:
        return re.sub(r"[^\w.-]+", "_", profile)[:80] or "profile"
    ident = os.path.abspath(source) if os.path.exists(source) else source
    h = hashlib.sha1(ident.encode("utf-8")).hexdigest()[:8]
    base = os.path.basename(source.rstrip("/\\")) or "source"
    slug = re.sub(r"[^\w.-]+", "_", base)[:60]
    return f"{slug}-{h}"


def load_baseline(key: str, state_dir: str | None = None) -> dict | None:
    path = os.path.join(state_dir or default_state_dir(), f"{key}.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and "templates" in data and "total" in data:
            return data
    except (OSError, ValueError):
        return None
    return None


def save_baseline(key: str, baseline: dict, state_dir: str | None = None) -> str:
    directory = state_dir or default_state_dir()
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"{key}.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh)
    os.replace(tmp, path)  # atomic
    return path


def update_baseline(
    baseline: dict | None,
    entries: Sequence[LogEntry],
    flagged: Sequence[bool],
    *,
    decay: float = 1.0,
) -> dict:

    templates: dict[str, float] = {}
    total = 0.0
    learned_runs = 0
    if baseline:
        templates = {k: float(v) for k, v in baseline.get("templates", {}).items()}
        total = float(baseline.get("total", 0) or 0)
        learned_runs = int(baseline.get("learned_runs", 0) or 0)
    if decay < 1.0:
        templates = {k: v * decay for k, v in templates.items()}
        total *= decay

    for i, e in enumerate(entries):
        if i < len(flagged) and flagged[i]:
            continue  # never learn from an anomaly
        key = f"{e.level.upper()}|{template_key(e.message or '')}"
        templates[key] = templates.get(key, 0.0) + 1.0
        total += 1.0

    if len(templates) > _MAX_TEMPLATES:
        kept = sorted(templates.items(), key=lambda kv: kv[1], reverse=True)[:_MAX_TEMPLATES]
        templates = dict(kept)

    return {
        "schema": SCHEMA,
        "templates": {k: int(round(v)) for k, v in templates.items()},
        "total": int(round(total)),
        "learned_runs": learned_runs + 1,
        "updated": int(time.time()),
    }
