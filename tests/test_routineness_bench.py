from __future__ import annotations

from loglens.application.routineness_bench import _auc, best_variant, evaluate
from loglens.domain.models import LogEntry


def test_auc_perfect_and_inverse_and_tie():
    assert _auc([0.9, 0.8, 0.7], [0.3, 0.2, 0.1]) == 1.0  # benign all above
    assert _auc([0.1, 0.2], [0.8, 0.9]) == 0.0  # benign all below
    assert _auc([0.5, 0.5], [0.5, 0.5]) == 0.5  # all ties
    assert _auc([], [0.1]) is None


def _separable():
    """6 benign routine templates spread over hosts/time + 4 concentrated fault
    bursts near the end → R should separate them."""
    lines = []
    anom = set()
    words = [
        "heartbeat ok",
        "cache warm",
        "config reloaded",
        "healthcheck pass",
        "session opened",
        "metrics flushed",
    ]
    hosts = ["a", "b", "c", "d"]
    for i in range(300):
        lines.append(LogEntry(level="INFO", service=hosts[i % 4], message=words[i % len(words)]))
    for f in ("disk reset", "memory parity", "watchdog trip", "bus fault"):
        for _ in range(10):
            lines.append(LogEntry(level="ERROR", service="node7", message=f))
            anom.add(len(lines))  # 1-based ordinal
    return lines, anom


def test_evaluate_separable_is_promotable():
    entries, anom = _separable()
    res = evaluate(entries, anom, n_boot=200)
    best = best_variant(res)
    assert best.auc is not None and best.auc >= 0.65
    assert best.promotable  # clean synthetic → R clearly separates
    assert best.n_benign >= 2 and best.n_anomalous >= 2


def test_evaluate_non_separable_not_promotable():
    # benign and anomalous templates behave identically (same spread) → AUC ~0.5
    lines = []
    anom = set()
    hosts = ["a", "b", "c", "d"]
    for i in range(200):
        lines.append(LogEntry(level="INFO", service=hosts[i % 4], message=f"alpha op{i % 5}"))
    for i in range(200):
        lines.append(LogEntry(level="ERROR", service=hosts[i % 4], message=f"beta op{i % 5}"))
        anom.add(len(lines))
    res = evaluate(lines, anom, n_boot=200)
    best = best_variant(res)
    # both classes equally spread → R can't tell them apart → stays badge-only
    assert not best.promotable


def test_variants_present_and_deterministic():
    entries, anom = _separable()
    r1 = evaluate(entries, anom, n_boot=200, seed=7)
    r2 = evaluate(entries, anom, n_boot=200, seed=7)
    assert set(r1) == {"normal", "drop", "invert"}
    assert {m: v.ci_low for m, v in r1.items()} == {m: v.ci_low for m, v in r2.items()}
