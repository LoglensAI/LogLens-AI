from loglens.detection.rate import rate_burst_scores
from loglens.domain.models import LogEntry


def _bg(i):
    return LogEntry(level="INFO", service="api", message=f"handling GET /health ok {i}")


def test_flags_a_burst_window():
    entries = []
    for i in range(120):
        entries.append(_bg(i))
    start = len(entries)
    for _ in range(40):
        entries.append(LogEntry(level="INFO", service="db", message="reconnecting to database"))
    burst_idx = range(start, len(entries))
    for i in range(120):
        entries.append(_bg(1000 + i))

    scores, reasons, note = rate_burst_scores(entries, flag_at=0.70)
    assert all(scores[i] >= 0.70 for i in burst_idx)
    assert any("rate burst" in r for i in burst_idx for r in reasons[i])
    assert "burst window" in note


def test_steady_template_not_flagged():
    entries = []
    for i in range(300):
        if i % 10 == 0:
            entries.append(LogEntry(level="INFO", service="db", message="heartbeat ok"))
        else:
            entries.append(_bg(i))
    scores, _r, _n = rate_burst_scores(entries)
    assert (scores < 0.70).all()


def test_rare_template_not_flagged():
    entries = [_bg(i) for i in range(200)]
    for k in (20, 90, 150):
        entries[k] = LogEntry(level="INFO", service="db", message="config reloaded")
    scores, _r, _n = rate_burst_scores(entries)
    assert (scores == 0).all()


def test_detector_integration_flags_burst():
    from loglens.detection.detector import DetectorConfig, detect
    from loglens.detection.embeddings import EmbeddingEngine
    from loglens.detection.templates import TemplateRegistry

    entries = [_bg(i) for i in range(120)]
    start = len(entries)
    for _ in range(40):
        entries.append(LogEntry(level="INFO", service="db", message="reconnecting to database"))
    entries += [_bg(1000 + i) for i in range(120)]

    eng = EmbeddingEngine()
    eng.fit(entries)
    reg = TemplateRegistry(entries)
    emb = eng.embed_templates(entries, reg)
    result = detect(entries, emb, DetectorConfig.from_sensitivity("normal"))
    flagged = {i for i, f in enumerate(result.flagged) if f}
    assert all(i in flagged for i in range(start, start + 40))
    assert "rate_note" in result.meta