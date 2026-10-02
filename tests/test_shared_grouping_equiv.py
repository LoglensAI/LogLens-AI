from __future__ import annotations

import glob
import os

import numpy as np

from loglens.detection.cooccurrence import cooccurrence_boost
from loglens.detection.parameters import parameter_anomaly_scores
from loglens.detection.parser import parse_line, sniff_format
from loglens.detection.rate import rate_burst_scores
from loglens.detection.sequence import sequence_anomaly_scores
from loglens.detection.templates import TemplateRegistry, template_key


def _load(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = [ln.rstrip("\n") for ln in fh]
    fmt, _c, layout = sniff_format(raw[:200])
    return [e for ln in raw if (e := parse_line(ln, fmt, layout)) is not None]


def _keys(entries):
    return [template_key(e.message or "") for e in entries]


def _logs():
    out = []
    for path in sorted(glob.glob("testlogs/*.log")):
        if os.path.getsize(path) > 2_000_000:
            continue
        entries = _load(path)
        if entries:
            out.append((os.path.basename(path), entries))
    return out


def test_rate_keys_identical():
    for name, entries in _logs():
        keys = _keys(entries)
        s1, r1, n1 = rate_burst_scores(entries)
        s2, r2, n2 = rate_burst_scores(entries, template_keys=keys)
        assert np.array_equal(s1, s2) and r1 == r2 and n1 == n2, name


def test_parameter_keys_identical():
    for name, entries in _logs():
        keys = _keys(entries)
        s1, r1, n1 = parameter_anomaly_scores(entries)
        s2, r2, n2 = parameter_anomaly_scores(entries, template_keys=keys)
        assert np.array_equal(s1, s2) and r1 == r2 and n1 == n2, name


def test_sequence_keys_identical():
    for name, entries in _logs():
        keys = _keys(entries)
        s1, r1, n1 = sequence_anomaly_scores(entries)
        s2, r2, n2 = sequence_anomaly_scores(entries, template_keys=keys)
        assert np.array_equal(s1, s2) and r1 == r2 and n1 == n2, name


def test_cooccurrence_keys_identical():
    for name, entries in _logs():
        keys = _keys(entries)
        base = np.linspace(0.0, 1.0, len(entries))
        s1, r1, n1 = cooccurrence_boost(entries, base)
        s2, r2, n2 = cooccurrence_boost(entries, base, template_keys=keys)
        assert np.array_equal(s1, s2) and r1 == r2 and n1 == n2, name


def test_registry_derived_keys_match_template_key():
    """The exact list detect() passes (from the registry) must equal template_key."""
    for name, entries in _logs():
        reg = TemplateRegistry(entries)
        derived = [reg.groups[gi].template for gi in reg.entry_group]
        assert derived == _keys(entries), name