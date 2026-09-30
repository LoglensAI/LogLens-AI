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
    normal = [20, 22, 19, 25, 18, 24, 21, 23, 20, 26]
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