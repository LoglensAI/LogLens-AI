from loglens.detection.parameters import numeric_slots, parameter_anomaly_scores
from loglens.domain.models import LogEntry


def test_numeric_slots_basic_with_unit():
    assert numeric_slots("request 42 completed in 9800ms") == [42.0, 9800.0]


def test_numeric_slots_ignores_ids_ips_timestamps():
    slots = numeric_slots("2024-01-01T00:00:00Z connection to db-1 at 10.0.0.5 took 15ms")
    assert slots == [15.0]


def test_numeric_slots_strips_commas():
    assert numeric_slots("latency was 9,800 ms") == [9800.0]


def _latency_corpus(normal_ms, spike_ms):
    entries = [
        LogEntry(level="INFO", service="api", message=f"request {i} completed in {ms}ms")
        for i, ms in enumerate(normal_ms)
    ]
    start = len(entries)
    entries += [
        LogEntry(level="WARNING", service="api", message=f"request {900 + j} completed in {ms}ms")
        for j, ms in enumerate(spike_ms)
    ]
    return entries, range(start, len(entries))


def test_flags_value_outlier():
    normal = [20, 22, 19, 25, 18, 24, 21, 23, 20, 26, 19, 22]
    entries, spike_idx = _latency_corpus(normal, [9800, 11000])
    scores, reasons, note = parameter_anomaly_scores(entries, flag_at=0.70)
    assert all(scores[i] >= 0.70 for i in spike_idx)
    assert any("parameter anomaly" in r for i in spike_idx for r in reasons[i])
    # the normal lines stay quiet
    assert all(scores[i] < 0.70 for i in range(12))


def test_pools_across_levels():
    normal = [20, 22, 19, 25, 18, 24, 21, 23, 20, 26, 19, 23, 21, 22]
    entries, spike_idx = _latency_corpus(normal, [9999])
    scores, _r, _n = parameter_anomaly_scores(entries)
    assert all(scores[i] >= 0.70 for i in spike_idx)


def test_steady_slot_not_flagged():
    entries = [
        LogEntry(level="INFO", service="api", message=f"request {i} completed in 20ms")
        for i in range(20)
    ]
    scores, _r, _n = parameter_anomaly_scores(entries)
    assert (scores == 0).all()


def test_small_group_skipped():
    entries = [
        LogEntry(level="INFO", service="api", message=f"request {i} completed in {ms}ms")
        for i, ms in enumerate([20, 9000, 21])
    ]
    scores, _r, _n = parameter_anomaly_scores(entries, min_group=8)
    assert (scores == 0).all()


def test_detector_integration_flags_parameter_spike():
    import numpy as np  # noqa: F401

    from loglens.detection.detector import DetectorConfig, detect
    from loglens.detection.embeddings import EmbeddingEngine
    from loglens.detection.templates import TemplateRegistry

    normal = [20, 22, 19, 25, 18, 24, 21, 23, 20, 26, 19, 22]
    entries, spike_idx = _latency_corpus(normal, [9800])
    eng = EmbeddingEngine()
    eng.fit(entries)
    reg = TemplateRegistry(entries)
    emb = eng.embed_templates(entries, reg)
    result = detect(entries, emb, DetectorConfig.from_sensitivity("normal"))
    flagged = {i for i, f in enumerate(result.flagged) if f}
    assert all(i in flagged for i in spike_idx)
    assert "parameter_note" in result.meta


# --- Real-log false positives (Stage 1 QA audit, Loghub BGL) -------------------
# The detector was added in 0a071fe and dropped unsupervised BGL_2k F1 from 0.501
# to 0.356: every one of its flags on BGL was a false positive, all on kernel
# counters such as "<N> floating point alignment exceptions".


def _counter_corpus(values):
    return [
        LogEntry(
            level="INFO",
            service="kernel",
            message=f"{v} floating point alignment exceptions",
        )
        for v in values
    ]


def test_heavy_tailed_counter_not_flagged():
    """Counters spread over many orders of magnitude are normal; their long
    right tail is not an outlier (BGL: 5 ... 1.4e9 on normal lines)."""
    import numpy as np

    rng = np.random.default_rng(7)
    values = [int(10 ** rng.uniform(0.7, 9.1)) for _ in range(120)]
    scores, _r, _n = parameter_anomaly_scores(_counter_corpus(values))
    assert (scores < 0.70).all()


def test_bimodal_counter_not_flagged():
    """Usually 5-15 but 2.35M on a third of the lines: two normal modes, not
    a 1-in-3 anomaly rate (BGL flagged 39 such lines)."""
    small = [5, 8, 15, 8, 5, 8, 15, 8, 5, 8] * 8  # 80 lines
    big = [2354412, 640404, 2354412, 1005, 2354412] * 8  # 40 lines
    scores, _r, _n = parameter_anomaly_scores(_counter_corpus(small + big))
    assert (scores < 0.70).all()


def test_rare_spike_still_flagged_among_many():
    """The fix keeps the real case: a few huge latencies in a large group."""
    normal = [8, 16, 38, 39, 22, 31, 12, 27, 19, 35] * 19  # 190 lines, 8-39ms
    entries, spike_idx = _latency_corpus(normal, [8764, 8884, 9522, 10336, 10858])
    scores, _r, _n = parameter_anomaly_scores(entries)
    assert all(scores[i] >= 0.70 for i in spike_idx)
    assert all(scores[i] < 0.70 for i in range(len(normal)))
