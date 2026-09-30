import numpy as np

from loglens.detection.cooccurrence import cooccurrence_boost
from loglens.domain.models import LogEntry


def _entry(service, msg):
    return LogEntry(level="ERROR", service=service, message=msg)


def test_cooccurring_cluster_is_lifted_over_threshold():
    entries = [_entry("api", f"request {i} ok") for i in range(40)]
    base = [0.0] * 40
    start = len(entries)
    for _ in range(15):
        entries.append(_entry("db", "connection pool exhausted"))
        base.append(0.5)
        entries.append(_entry("db", "query timeout after 30s"))
        base.append(0.5)
    end = len(entries)
    entries += [_entry("api", f"request {i} ok") for i in range(40)]
    base += [0.0] * 40

    scores, reasons, note = cooccurrence_boost(entries, np.array(base), flag_at=0.70)
    lifted = list(range(start, end))
    assert all(scores[i] >= 0.70 for i in lifted)  # incident members cross threshold
    assert any("incident" in r for i in lifted for r in reasons[i])
    assert "incident window" in note


def test_isolated_spike_not_boosted():
    entries = [_entry("api", f"request {i} ok") for i in range(80)]
    base = [0.0] * 80
    start = len(entries)
    for _ in range(6):
        entries.append(_entry("db", "connection pool exhausted"))
        base.append(0.5)
    entries += [_entry("api", f"request {i} ok") for i in range(80)]
    base += [0.0] * 80

    scores, _r, _n = cooccurrence_boost(entries, np.array(base), flag_at=0.70)
    assert all(scores[i] < 0.70 for i in range(start, start + 6))  # stays below alone


def test_below_gate_never_boosted():
    entries = []
    base = []
    for _ in range(6):
        entries.append(_entry("db", "connection pool exhausted"))
        base.append(0.2)
    for _ in range(6):
        entries.append(_entry("db", "query timeout after 30s"))
        base.append(0.2)
    scores, _r, _n = cooccurrence_boost(entries, np.array(base), flag_at=0.70)
    assert (scores < 0.70).all()


def test_scores_unchanged_when_no_cooccurrence():
    entries = [_entry("api", f"request {i} ok") for i in range(60)]
    base = np.linspace(0, 0.6, 60)
    scores, _r, note = cooccurrence_boost(entries, base, flag_at=0.70)
    assert np.allclose(scores, base)
    assert note == ""
