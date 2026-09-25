from __future__ import annotations

import os
import sys
import threading

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from loglens.detection.embeddings import (
    N_LOG_FEATURES,
    _row_normalize,
    extract_features,
)
from loglens.detection.synonyms import STOPWORDS, SynonymLearner, normalize_message
from loglens.domain.models import LogEntry

_model = None
_model_lock = threading.Lock()

_MODEL_NAME = "all-MiniLM-L6-v2"


def _bundled_model_dir() -> str | None:
    candidates = []
    env = os.environ.get("LOGLENS_MODEL_DIR", "").strip()
    if env:
        candidates += [os.path.join(env, _MODEL_NAME), env]
    base = getattr(sys, "_MEIPASS", None)
    if base:
        candidates += [
            os.path.join(base, "loglens_models", _MODEL_NAME),
            os.path.join(base, "loglens_models"),
        ]
    for c in candidates:
        if c and os.path.isdir(c):
            return c
    return None


def _load_model():
    global _model
    with _model_lock:
        if _model is not None:
            return _model
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "Deep mode requires sentence-transformers.\n"
                "Install it with: pip install sentence-transformers"
            ) from exc
        try:
            bundled = _bundled_model_dir()
            if bundled:
                os.environ.setdefault("HF_HUB_OFFLINE", "1")
                os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
                _model = SentenceTransformer(bundled)
            else:
                _model = SentenceTransformer(_MODEL_NAME)
        except Exception as e:
            raise RuntimeError(
                "Could not load the sentence-transformers model "
                f"'all-MiniLM-L6-v2' ({type(e).__name__}: {e}).\n"
                "This usually means no internet access for the first "
                "download. Re-run without --deep to use fast TF-IDF mode."
            ) from e
        return _model


class DeepEmbeddingEngine:
    def __init__(
        self,
        batch_size: int = 256,
        tfidf_dims: int = 32,
        feature_weight: float = 0.25,
        tfidf_weight: float = 0.15,
        use_synonym_cache: bool = True,
    ):
        self.batch_size = batch_size
        self.tfidf_dims = tfidf_dims
        self.feature_weight = feature_weight
        self.tfidf_weight = tfidf_weight
        self._learner: SynonymLearner | None = None
        self._use_synonym_cache = use_synonym_cache

    def fit(self, entries: list[LogEntry]) -> DeepEmbeddingEngine:
        self._learner = SynonymLearner(use_cache=self._use_synonym_cache)
        self._learner.fit([e.message for e in entries])
        return self

    def embed(self, entries: list[LogEntry]) -> np.ndarray:
        if not entries:
            return np.zeros((0, 384 + self.tfidf_dims + N_LOG_FEATURES), dtype=np.float32)
        model = _load_model()

        if self._learner is None:
            self.fit(entries)
        assert self._learner is not None  # set by fit()
        synonyms = self._learner.get_all_synonyms()
        messages = [normalize_message(e.message, synonyms) for e in entries]

        semantic = model.encode(
            messages,
            batch_size=self.batch_size,
            show_progress_bar=False,
        ).astype(np.float32)
        semantic = _row_normalize(semantic)

        if self.tfidf_dims > 0:
            vec = TfidfVectorizer(
                max_features=self.tfidf_dims,
                sublinear_tf=True,
                min_df=2 if len(messages) >= 10 else 1,
                token_pattern=r"(?u)\b[a-zA-Z0-9_]{2,}\b",
                stop_words=sorted(STOPWORDS),
            )
            tfidf = vec.fit_transform(messages).toarray().astype(np.float32)
            if tfidf.shape[1] < self.tfidf_dims:
                pad = np.zeros((len(messages), self.tfidf_dims - tfidf.shape[1]), dtype=np.float32)
                tfidf = np.hstack([tfidf, pad])
            tfidf = _row_normalize(tfidf)
            w = self.tfidf_weight
            text_block = np.hstack([(1.0 - w) * semantic, w * tfidf])
        else:
            text_block = semantic

        feats = np.array(
            [
                e.metadata.get("_features")
                if isinstance(e.metadata.get("_features"), np.ndarray)
                else extract_features(e)
                for e in entries
            ],
            dtype=np.float32,
        )
        feats = _row_normalize(feats)

        wf = self.feature_weight
        combined = np.hstack([(1.0 - wf) * _row_normalize(text_block), wf * feats])
        return _row_normalize(combined)

    def embed_templates(self, entries: list[LogEntry], registry) -> np.ndarray:
        if not entries:
            return np.zeros((0, 384 + self.tfidf_dims + N_LOG_FEATURES), dtype=np.float32)
        reps = [entries[i] for i in registry.representative_indices()]
        group_vecs = self.embed(reps)  # (n_groups, dim)
        out = np.empty((len(entries), group_vecs.shape[1]), dtype=np.float32)
        for gi, g in enumerate(registry.groups):
            out[g.indices] = group_vecs[gi]
        return out
