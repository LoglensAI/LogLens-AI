from __future__ import annotations

import glob
import os

import numpy as np

from loglens.detection.detector import DetectorConfig, detect
from loglens.detection.embeddings import EmbeddingEngine
from loglens.detection.parser import parse_line, sniff_format
from loglens.detection.templates import TemplateRegistry


def _load(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = [ln.rstrip("\n") for ln in fh]
    fmt, _c, layout = sniff_format(raw[:200])
    return [e for ln in raw if (e := parse_line(ln, fmt, layout)) is not None]


def _fixtures():
    out = []
    for path in sorted(glob.glob("testlogs/*.log")):
        if os.path.getsize(path) > 2_000_000:
            continue
        entries = _load(path)
        if entries:
            out.append((os.path.basename(path), entries))
    return out


def _both(entries):
    reg = TemplateRegistry(entries)
    eng = EmbeddingEngine()
    eng.fit(entries)
    group = eng.embed_group_templates(entries, reg)  # (n_groups, dim)
    expanded = eng.embed_templates(entries, reg)  # (n_lines, dim)
    cfg = DetectorConfig.from_sensitivity("normal")
    lean = detect(entries, cfg=cfg, group_embeddings=group)
    classic = detect(entries, expanded, cfg)
    return lean, classic


def _assert_identical(name, lean, classic):
    assert np.array_equal(lean.scores, classic.scores), f"{name}: scores"
    assert lean.reasons == classic.reasons, f"{name}: reasons"
    assert np.array_equal(lean.flagged, classic.flagged), f"{name}: flags"
    assert np.array_equal(lean.labels, classic.labels), f"{name}: cluster labels"


def test_lean_cluster_byte_identical_real_logs():
    for name, entries in _fixtures():
        lean, classic = _both(entries)
        _assert_identical(name, lean, classic)


def test_lean_cluster_byte_identical_synthetic():
    from scripts.perf_bench import _gen

    raw = _gen(30000)
    fmt, _c, layout = sniff_format(raw[:200])
    entries = [e for ln in raw if (e := parse_line(ln, fmt, layout)) is not None]
    lean, classic = _both(entries)
    _assert_identical("synthetic", lean, classic)


def test_expanded_equals_group_vectors():
    """embed_templates must be exactly embed_group_templates expanded per group."""
    for _name, entries in _fixtures()[:3]:
        reg = TemplateRegistry(entries)
        eng = EmbeddingEngine()
        eng.fit(entries)
        group = eng.embed_group_templates(entries, reg)
        expanded = eng.embed_templates(entries, reg)
        for gi, g in enumerate(reg.groups):
            assert np.array_equal(expanded[g.indices[0]], group[gi])