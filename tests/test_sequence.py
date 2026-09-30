from loglens.detection.sequence import extract_session_key, sequence_anomaly_scores
from loglens.domain.models import LogEntry

NORMAL = ["allocate", "write", "replicate", "confirm", "close"]


def _session(blk, steps):
    return [LogEntry(level="INFO", service="hdfs", message=f"{s} for block {blk}") for s in steps]


def test_extract_block_id():
    assert extract_session_key("Receiving block blk_-8391 from /10.0.0.1") == "blk_-8391"


def test_extract_uuid():
    key = extract_session_key("start req 2f1c9e0a-4b3d-11ee-be56-0242ac120002 done")
    assert key == "2f1c9e0a-4b3d-11ee-be56-0242ac120002"


def test_extract_named_id():
    assert extract_session_key("handled request_id=abc123 ok") == "abc123"


def test_no_key_for_plain_numbers():
    # a bare "job 5" / "process 42" must NOT be treated as a session key
    assert extract_session_key("background job 5 finished") is None
    assert extract_session_key("out of memory: killing process 42") is None


def _corpus(n_normal=30):
    entries = []
    for k in range(n_normal):
        entries += _session(f"blk_{k}", NORMAL)
    return entries


def test_normal_sessions_not_flagged():
    entries = _corpus()
    scores, reasons, note = sequence_anomaly_scores(entries, flag_at=0.70)
    assert (scores < 0.70).all()
    assert "0 with an anomalous order" in note


def test_reordered_session_flagged_whole():
    entries = _corpus()
    start = len(entries)
    entries += _session(
        "blk_9990001", ["allocate", "confirm", "write", "close"]
    )  
    scores, reasons, note = sequence_anomaly_scores(entries, flag_at=0.70)
    bad_idx = range(start, len(entries))
    assert all(scores[i] >= 0.70 for i in bad_idx)
    assert any("anomalous session blk_9990001" in r for i in bad_idx for r in reasons[i])


def test_truncated_session_flagged():
    entries = _corpus()
    start = len(entries)
    entries += _session("blk_9990002", ["allocate", "write"])  # never finished
    scores, _reasons, _note = sequence_anomaly_scores(entries, flag_at=0.70)
    assert any(scores[i] >= 0.70 for i in range(start, len(entries)))


def test_skips_when_not_session_structured():
    entries = [LogEntry(level="INFO", service="api", message=f"request {i} ok") for i in range(50)]
    scores, reasons, note = sequence_anomaly_scores(entries)
    assert (scores == 0).all()
    assert "skipped" in note


def test_detector_integration_flags_broken_session():

    from loglens.detection.detector import DetectorConfig, detect
    from loglens.detection.embeddings import EmbeddingEngine
    from loglens.detection.templates import TemplateRegistry

    entries = _corpus(40)
    start = len(entries)
    entries += _session("blk_9990003", ["allocate", "close", "write", "replicate", "confirm"])

    eng = EmbeddingEngine()
    eng.fit(entries)
    reg = TemplateRegistry(entries)
    emb = eng.embed_templates(entries, reg)

    cfg = DetectorConfig.from_sensitivity("normal")
    result = detect(entries, emb, cfg)
    flagged = {i for i, f in enumerate(result.flagged) if f}
    assert any(i in flagged for i in range(start, len(entries)))
    assert "sequence_note" in result.meta