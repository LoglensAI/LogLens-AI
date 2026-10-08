import numpy as np

from loglens.detection.detector import (
    DetectorConfig,
    cluster_summary,
    detect,
    detect_anomalies,
    get_severity,
    otsu_threshold,
)
from loglens.domain.models import LogEntry

# --- helpers ---


def make_entry(msg: str, level: str = "INFO", service: str = "svc") -> LogEntry:
    return LogEntry(
        timestamp="2024-01-15T10:00:00Z",
        level=level,
        service=service,
        message=msg,
        raw=msg,
    )


def dummy_vectors(n: int, dim: int = 16, seed: int = 0) -> np.ndarray:
    """Deterministic pseudo-embeddings; detector normalizes internally."""
    rng = np.random.default_rng(seed)
    return rng.random((n, dim)).astype(np.float32)


# --- basic contracts ---


def test_empty_input():
    res = detect([], np.zeros((0, 16)))
    assert res.summary()["entries"] == 0
    assert len(res.groups) == 0


def test_severity_mapping():
    assert get_severity("FATAL") < get_severity("ERROR")
    assert get_severity("ERROR") < get_severity("WARN")
    assert get_severity("WARN") < get_severity("INFO")
    assert get_severity("SOMETHING_UNKNOWN") == 6  # default


# --- flagging behaviour ---


def test_critical_always_flagged():
    """FATAL / CRITICAL must always be flagged regardless of clustering."""
    entries = [make_entry(f"routine heartbeat {i}", "INFO") for i in range(30)]
    entries.append(make_entry("kernel panic unrecoverable", "FATAL"))
    vecs = dummy_vectors(len(entries))
    res = detect(entries, vecs)
    assert res.flagged[-1], "FATAL entry should be flagged"
    # De-saturated scoring: guaranteed-flag levels stay above threshold but
    # are no longer pinned to exactly 1.0 (evidence differentiates them).
    assert res.scores[-1] >= 0.85
    assert res.scores[-1] < 1.0


def test_routine_info_not_flooding_anomalies():
    """A corpus of pure routine INFO should produce few/no anomalies."""
    entries = [make_entry(f"request served ok {i % 5}", "INFO") for i in range(50)]
    vecs = dummy_vectors(len(entries))
    res = detect(entries, vecs)
    assert int(res.flagged.sum()) < len(entries) // 2


def test_error_keyword_boosts_score():
    """ERROR with a failure keyword should outscore a plain INFO."""
    entries = [make_entry(f"user login ok {i}", "INFO") for i in range(20)]
    err = make_entry("database connection refused timeout", "ERROR")
    entries.append(err)
    vecs = dummy_vectors(len(entries))
    res = detect(entries, vecs)
    assert res.scores[-1] > res.scores[0]


# --- grouping & summary ---


def test_anomaly_groups_have_templates():
    entries = [make_entry(f"disk read ok {i}", "INFO") for i in range(20)]
    for _ in range(6):
        entries.append(make_entry("payment failed: card declined", "ERROR"))
    vecs = dummy_vectors(len(entries))
    res = detect(entries, vecs)
    assert res.groups, "should produce at least one anomaly group"
    top = res.groups[0]
    assert top.template
    assert top.count >= 1
    assert isinstance(top.reasons, list) and top.reasons


def test_incident_mode_triggers_on_high_severe_share():
    """If >=30% of entries are ERROR+, incident_mode should be True."""
    entries = [make_entry("service crash error", "ERROR") for _ in range(6)] + [
        make_entry("ok", "INFO") for _ in range(4)
    ]
    vecs = dummy_vectors(len(entries))
    res = detect(entries, vecs)
    assert res.incident_mode is True
    assert res.incident_note


def test_detect_anomalies_wrapper():
    entries = [make_entry(f"ok {i}", "INFO") for i in range(15)]
    entries.append(make_entry("fatal segfault", "FATAL"))
    vecs = dummy_vectors(len(entries))
    normal, anomalies, labels = detect_anomalies(entries, vecs)
    assert len(anomalies) >= 1
    assert len(normal) + len(anomalies) <= len(entries) + 1  # sanity
    assert len(labels) == len(entries)


def test_cluster_summary_shape():
    labels = np.array([0, 0, 1, -1, -1, 1])
    flagged = np.array([False, False, True, True, True, False])
    s = cluster_summary(labels, flagged)
    assert s["clusters"] == 2
    assert s["noise_points"] == 2
    assert s["anomalies"] == 3


def test_config_from_sensitivity():
    low = DetectorConfig.from_sensitivity("low")
    high = DetectorConfig.from_sensitivity("high")
    assert low.flag_threshold > high.flag_threshold


def test_otsu_threshold_returns_none_on_tiny_input():
    assert otsu_threshold(np.array([0.4, 0.6])) is None


def test_otsu_threshold_finds_valley():
    # bimodal: cluster near 0.2 and near 0.85 -> cut should sit between
    lo = np.full(200, 0.2)
    hi = np.full(200, 0.85)
    t = otsu_threshold(np.concatenate([lo, hi]))
    assert t is not None
    assert 0.35 <= t <= 0.9


def test_auto_threshold_config_toggle():
    entries = [make_entry(f"disk ok {i}", "INFO") for i in range(40)] + [
        make_entry("payment failed declined", "ERROR") for _ in range(8)
    ]
    vecs = dummy_vectors(len(entries))
    cfg = DetectorConfig(auto_threshold=True)
    res = detect(entries, vecs, cfg)
    assert "threshold_used" in res.meta
    assert res.meta["auto_threshold"] is True


def test_scores_never_saturate_to_identical_ones():
    entries = [make_entry(f"routine ok {i % 3}", "INFO") for i in range(40)]
    entries.append(make_entry("disk failure detected raid degraded", "FATAL"))
    entries.append(make_entry("oom killer invoked pid 4242", "FATAL"))
    for _ in range(20):  # repetitive FATAL drone vs the two novel ones
        entries.append(make_entry("watchdog heartbeat missed", "FATAL"))
    res = detect(entries, dummy_vectors(len(entries)))
    fatal_scores = [float(res.scores[i]) for i, e in enumerate(entries) if e.level == "FATAL"]
    assert all(s < 1.0 for s in fatal_scores), "no score may saturate at 1.0"
    assert all(res.flagged[i] for i, e in enumerate(entries) if e.level == "FATAL"), (
        "hard-flag levels stay flagged"
    )


def test_history_damp_never_hits_tight_bursts():
    entries = []
    for _ in range(30):  # early tight ERROR burst = early incident
        entries.append(make_entry("raid controller failure disk offline", "ERROR"))
    for i in range(400):
        entries.append(make_entry(f"request ok {i % 7}", "INFO"))
    res = detect(entries, dummy_vectors(len(entries)))
    err_flags = [bool(res.flagged[i]) for i, e in enumerate(entries) if e.level == "ERROR"]
    assert all(err_flags), "early burst must stay flagged"
    assert not any("routine by own history" in r for i in range(30) for r in res.reasons[i])


def test_clustering_capped_on_high_cardinality():
    import time

    import numpy as np

    from loglens.detection import detector as det

    n = det.MAX_CLUSTER_GROUPS + 5000
    rng = np.random.default_rng(0)
    gv = rng.standard_normal((n, 64)).astype(np.float32)
    gc = np.ones(n, dtype=np.float64)

    t0 = time.perf_counter()
    vecs, counts, labels, sizes, eps = det._cluster_from_group_vectors(
        gv, gc, registry=None, cfg=det.DetectorConfig()
    )
    assert time.perf_counter() - t0 < 10  # no quadratic DBSCAN
    assert labels.shape[0] == n
    assert (labels == -1).all()  # all treated as noise
    assert eps == 0.0