from __future__ import annotations

import random

from loglens.detection.routineness import compute_routineness, confidence_label
from loglens.detection.templates import template_key
from loglens.domain.models import LogEntry


def _mixed_entries():
    random.seed(0)
    ents = [
        LogEntry(
            level="INFO",
            service=random.choice(["api", "db", "auth", "worker"]),
            message=f"handling request {i} ok",
        )
        for i in range(200)
    ]
    for i in range(8):
        ents.insert(
            190 + i, LogEntry(level="CRITICAL", service="db", message="kernel panic not syncing")
        )
    return ents


def test_routine_chatter_scores_high():
    r = compute_routineness(_mixed_entries())
    routine = r[template_key("handling request 5 ok")]
    assert routine.status == "measured"
    assert routine.r is not None and routine.r >= 0.7
    assert "routine" in routine.note


def test_concentrated_burst_scores_low():
    r = compute_routineness(_mixed_entries())
    burst = r[template_key("kernel panic not syncing")]
    assert burst.r is not None and burst.r <= 0.4
    assert "emerging" in burst.note or "mixed" in burst.note


def test_unknown_below_min_count():
    ents = [LogEntry(message="rare thing")] * 3
    r = compute_routineness(ents)
    rr = r[template_key("rare thing")]
    assert rr.status == "unknown"
    assert rr.r is None


def test_baseline_known_boosts_age():
    ents = [LogEntry(level="INFO", service="api", message=f"known line {i}") for i in range(6)]
    key = f"INFO|{template_key('known line 0')}"
    r = compute_routineness(ents, baseline={"templates": {key: 500}, "total": 500})
    rr = r[template_key("known line 0")]
    assert rr.features.get("age") == 1.0


def test_confidence_label_respects_routineness():
    r = compute_routineness(_mixed_entries())
    routine = r[template_key("handling request 5 ok")]
    burst = r[template_key("kernel panic not syncing")]
    lbl_routine, adj_routine = confidence_label(0.9, routine)
    lbl_burst, adj_burst = confidence_label(0.9, burst)
    assert adj_routine < adj_burst
    assert lbl_routine == "Low"


def test_confidence_unknown_tagged():
    label, _ = confidence_label(0.95, None)
    assert "R n/a" in label
