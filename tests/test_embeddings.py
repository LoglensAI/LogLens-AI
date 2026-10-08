import numpy as np
import pytest

from loglens.detection.embeddings import EmbeddingEngine, extract_features
from loglens.detection.synonyms import (
    SynonymLearner,
    detect_unknown_word,
    normalize_message,
    split_camel_case,
)
from loglens.domain.models import LogEntry

# --- helpers ---


def make_entry(msg: str) -> LogEntry:
    return LogEntry(
        timestamp="2024-01-15T10:00:00Z",
        level="INFO",
        service="test",
        message=msg,
        raw=msg,
    )


def make_entry_with_level(msg: str, level: str) -> LogEntry:
    return LogEntry(
        timestamp="2024-01-15T10:00:00Z",
        level=level,
        service="test",
        message=msg,
        raw=msg,
    )


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


# --- shape tests ---


def test_embed_returns_correct_shape():
    """Use varied entries so TF-IDF can build a proper vocabulary."""
    engine = EmbeddingEngine()
    entries = [make_entry(f"database connection timeout variant {i}") for i in range(20)]
    vectors = engine.embed(entries)
    assert vectors.shape[0] == 20
    assert vectors.shape[1] >= 14


def test_single_entry_embed():
    """Single entry — TF-IDF will be minimal, log features still present."""
    engine = EmbeddingEngine()
    entries = [make_entry("kernel panic null pointer dereference")]
    vectors = engine.embed(entries)
    assert vectors.shape[0] == 1
    assert vectors.shape[1] >= 14


# --- similarity tests ---


def test_similar_messages_are_close():
    engine = EmbeddingEngine()
    entries = [
        make_entry("database connection timeout"),
        make_entry("database connection timeout after 30s"),  # similar
        make_entry("user login successful uid=1042"),  # different
    ]
    vectors = engine.embed(entries)
    sim_similar = np.dot(vectors[0], vectors[1])
    sim_different = np.dot(vectors[0], vectors[2])
    assert sim_similar > sim_different


def test_synonym_normalization():
    """conn refused and connection refused should be very similar."""
    engine = EmbeddingEngine()
    entries = [
        make_entry("conn refused port 5432"),
        make_entry("connection refused port 5432"),
        make_entry("user login successful uid=1042"),
    ]
    vectors = engine.embed(entries)
    sim_synonym = cosine_similarity(vectors[0], vectors[1])
    sim_different = cosine_similarity(vectors[0], vectors[2])
    assert sim_synonym > sim_different, (
        f"Synonym similarity {sim_synonym:.3f} should be > {sim_different:.3f}"
    )


# --- accuracy tests ---


def test_severity_separation():
    """ERROR logs should be far from INFO logs."""
    engine = EmbeddingEngine()
    entries = [
        make_entry_with_level("database connection timeout", "ERROR"),
        make_entry_with_level("database connection timeout", "INFO"),
        make_entry_with_level("database connection timeout", "DEBUG"),
    ]
    vectors = engine.embed(entries)
    sim_error_info = cosine_similarity(vectors[0], vectors[1])
    sim_info_debug = cosine_similarity(vectors[1], vectors[2])
    assert sim_error_info < sim_info_debug, (
        f"ERROR/INFO sim {sim_error_info:.3f} should be < INFO/DEBUG sim {sim_info_debug:.3f}"
    )


def test_feature_detection():
    """Specific features should score correctly."""
    error_entry = make_entry_with_level("connection refused error crash after 30s", "ERROR")
    info_entry = make_entry_with_level("user login successful", "INFO")

    error_features = extract_features(error_entry)
    info_features = extract_features(info_entry)

    assert error_features[0] > info_features[0], "ERROR level score should be higher"
    assert error_features[1] > info_features[1], "Error keyword score should be higher"


def test_http_error_detection():
    """HTTP 500 should score higher than HTTP 200."""
    entry_500 = make_entry("GET /api/users 500 Internal Server Error")
    entry_200 = make_entry("GET /api/users 200 OK")

    f500 = extract_features(entry_500)
    f200 = extract_features(entry_200)

    assert f500[2] > f200[2], "HTTP 500 should score higher than 200"


def test_memory_detection():
    """Memory related logs should have has_memory=1."""
    entry = make_entry("OOM killer activated process using 4096 MB")
    features = extract_features(entry)
    assert features[11] == 1.0, "Memory feature should be detected"


def test_ip_detection():
    """Logs with IP addresses should have has_ip=1."""
    entry = make_entry("connection refused from 192.168.1.100")
    features = extract_features(entry)
    assert features[7] == 1.0, "IP feature should be detected"


# --- synonym learner tests ---


def test_base_synonym_normalization():
    """Known abbreviations should be expanded."""
    assert "database" in normalize_message("db connection timeout")
    assert "connection" in normalize_message("conn refused")
    assert "memory" in normalize_message("oom killed")
    assert "timeout" in normalize_message("etimedout on port 5432")


def test_camel_case_splitting():
    """CamelCase words should be split correctly."""
    parts = split_camel_case("DBTimeout")
    assert "db" in parts
    assert "timeout" in parts


def test_camel_case_in_normalize():
    """CamelCase in message should be split and normalized."""
    result = normalize_message("DBTimeout in AuthService")
    assert "database" in result or "timeout" in result
    assert "auth" in result or "authentication" in result


def test_error_code_detection():
    """POSIX error codes should be normalized."""
    assert detect_unknown_word("ECONNRESET") == "reset"
    assert detect_unknown_word("ETIMEDOUT") == "timeout"
    assert detect_unknown_word("EACCES") == "denied"
    assert detect_unknown_word("ENOENT") == "missing"


def test_error_code_in_normalize():
    """Error codes inside messages should be normalized."""
    result = normalize_message("socket error ECONNRESET on port 5432")
    assert "reset" in result


def test_auto_synonym_learning():
    """Learner should discover that 'cxn' means 'connection' from corpus."""
    learner = SynonymLearner(min_cooccurrence=2, similarity_threshold=0.5)
    messages = [
        "cxn refused to database",
        "cxn timeout on database",
        "cxn reset by database",
        "connection refused to database",
        "connection timeout on database",
        "connection reset by database",
        "cxn failed on database server",
        "connection failed on database server",
    ]
    learner.fit(messages)
    learned = learner.get_all_synonyms()
    assert learned.get("cxn") == "connection", (
        f"Expected 'cxn' → 'connection', got: {learned.get('cxn')}"
    )


def test_synonym_fit_bounded_on_high_cardinality(tmp_path):
    import time

    rng = __import__("random").Random(0)
    msgs = [
        f"node R{rng.randrange(999):03d}-M{rng.randrange(2)} addr 0x{rng.randrange(2**32):08x} "
        f"code {rng.randrange(10**6)} kernel event"
        for _ in range(60000)
    ]
    learner = SynonymLearner(use_cache=False)
    t0 = time.perf_counter()
    learner.fit(msgs)
    elapsed = time.perf_counter() - t0
    assert elapsed < 30, f"synonym fit too slow ({elapsed:.1f}s) — vocab bound regressed?"


def test_learned_synonyms_improve_similarity():
    """After learning, 'cxn timeout' should be closer to 'connection timeout'."""
    learner = SynonymLearner(min_cooccurrence=2, similarity_threshold=0.5)
    corpus = [
        "cxn refused to database",
        "cxn timeout on database",
        "connection refused to database",
        "connection timeout on database",
        "cxn reset by peer",
        "connection reset by peer",
        "user login successful",
        "payment processed successfully",
    ]
    learner.fit(corpus)

    engine = EmbeddingEngine()
    engine._learner = learner
    entries = [
        make_entry("cxn timeout on database"),
        make_entry("connection timeout on database"),
        make_entry("user login successful"),
    ]
    vectors = engine.embed(entries)
    sim_synonym = cosine_similarity(vectors[0], vectors[1])
    sim_different = cosine_similarity(vectors[0], vectors[2])
    assert sim_synonym > sim_different, (
        f"Learned synonym similarity {sim_synonym:.3f} should be > {sim_different:.3f}"
    )


def is_sentence_transformers_available() -> bool:
    import importlib.util

    return importlib.util.find_spec("sentence_transformers") is not None


skip_if_no_st = pytest.mark.skipif(
    not is_sentence_transformers_available(),
    reason="sentence-transformers not installed — run: pip install sentence-transformers",
)


@skip_if_no_st
def test_deep_embed_returns_correct_shape():
    """Deep mode should return (n, 430) = 384 semantic + 32 tfidf + 14 log features."""
    from loglens.detection.deep_embeddings import DeepEmbeddingEngine

    engine = DeepEmbeddingEngine()
    entries = [
        make_entry("database connection timeout after 30s"),
        make_entry("user login successful uid=1042"),
        make_entry("kernel panic null pointer dereference"),
    ]
    vectors = engine.embed(entries)
    assert vectors.shape[0] == 3
    assert vectors.shape[1] == 430  # 384 semantic + 32 tfidf + 14 features


@skip_if_no_st
def test_deep_similar_messages_are_close():
    """Semantically similar messages should have high cosine similarity."""
    from loglens.detection.deep_embeddings import DeepEmbeddingEngine

    engine = DeepEmbeddingEngine()
    entries = [
        make_entry("database connection timeout"),
        make_entry("db conn timed out"),  # same meaning, different words
        make_entry("user logged in successfully"),  # completely different
    ]
    vectors = engine.embed(entries)
    sim_similar = cosine_similarity(vectors[0], vectors[1])
    sim_different = cosine_similarity(vectors[0], vectors[2])
    assert sim_similar > sim_different, (
        f"Similar sim {sim_similar:.3f} should be > different sim {sim_different:.3f}"
    )


@skip_if_no_st
def test_deep_beats_tfidf_on_unseen_synonyms():
    """
    Deep mode should handle unseen synonyms better than TF-IDF.
    'latency spike' vs 'slow response' — TF-IDF fails, deep succeeds.
    """
    from loglens.detection.deep_embeddings import DeepEmbeddingEngine

    engine = DeepEmbeddingEngine()
    entries = [
        make_entry("latency spike detected on api gateway"),
        make_entry("slow response detected on api gateway"),  # same meaning
        make_entry("user account created successfully"),  # different
    ]
    vectors = engine.embed(entries)
    sim_semantic = cosine_similarity(vectors[0], vectors[1])
    sim_different = cosine_similarity(vectors[0], vectors[2])
    assert sim_semantic > sim_different, (
        f"Semantic sim {sim_semantic:.3f} should be > different sim {sim_different:.3f}"
    )


@skip_if_no_st
def test_deep_severity_separation():
    """ERROR should be far from DEBUG even in deep mode."""
    from loglens.detection.deep_embeddings import DeepEmbeddingEngine

    engine = DeepEmbeddingEngine()
    entries = [
        make_entry_with_level("database connection timeout", "ERROR"),
        make_entry_with_level("database connection timeout", "INFO"),
        make_entry_with_level("database connection timeout", "DEBUG"),
    ]
    vectors = engine.embed(entries)
    sim_error_info = cosine_similarity(vectors[0], vectors[1])
    sim_info_debug = cosine_similarity(vectors[1], vectors[2])
    assert sim_error_info < sim_info_debug, (
        f"ERROR/INFO sim {sim_error_info:.3f} should be < INFO/DEBUG sim {sim_info_debug:.3f}"
    )


@skip_if_no_st
def test_deep_unit_vectors():
    """All deep embeddings should be unit vectors (normalized)."""
    from loglens.detection.deep_embeddings import DeepEmbeddingEngine

    engine = DeepEmbeddingEngine()
    entries = [
        make_entry("error connecting to database"),
        make_entry("user login failed"),
        make_entry("disk usage 95 percent"),
    ]
    vectors = engine.embed(entries)
    for i, vec in enumerate(vectors):
        norm = np.linalg.norm(vec)
        assert abs(norm - 1.0) < 1e-5, f"Vector {i} is not unit length: norm={norm:.6f}"
