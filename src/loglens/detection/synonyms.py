from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
from collections import defaultdict
from collections.abc import Iterable

import platformdirs

logger = logging.getLogger("loglens.synonyms")

BASE_SYNONYMS: dict[str, str] = {
    "db": "database",
    "conn": "connection",
    "auth": "authentication",
    "req": "request",
    "resp": "response",
    "err": "error",
    "msg": "message",
    "svc": "service",
    "k8s": "kubernetes",
    "cfg": "config",
    "env": "environment",
    "infra": "infrastructure",
    "perf": "performance",
    "proc": "process",
    "mem": "memory",
    "cpu": "processor",
    "net": "network",
    "cxn": "connection",
    "cnx": "connection",
    "svr": "server",
    "usr": "user",
    "pwd": "password",
    "cert": "certificate",
    "creds": "credentials",
    "oom": "memory",
    "terminated": "killed",
    "segfault": "crash",
    "sigkill": "killed",
    "sigterm": "terminated",
    "nullpointer": "crash",
    "npe": "crash",
    "econnrefused": "refused",
    "econnreset": "reset",
    "etimedout": "timeout",
    "heap": "memory",
    "gc": "memory",
    "ioexception": "error",
    "nullpointerexception": "crash",
    "outofmemoryerror": "memory",
    "down": "unavailable",
    "unresponsive": "unresponsive",
    "hung": "unresponsive",
    "stuck": "unresponsive",
    "overloaded": "overloaded",
}

STOPWORDS = frozenset(
    {
        "the",
        "for",
        "and",
        "not",
        "was",
        "were",
        "are",
        "has",
        "had",
        "have",
        "with",
        "from",
        "this",
        "that",
        "then",
        "than",
        "when",
        "will",
        "been",
        "being",
        "after",
        "before",
        "into",
        "over",
        "under",
        "while",
        "where",
        "which",
        "because",
        "could",
        "should",
        "would",
        "did",
        "does",
        "done",
        "due",
        "via",
        "per",
        "all",
        "any",
        "but",
        "its",
        "you",
        "your",
        "out",
        "off",
        "our",
        "their",
        "them",
        "they",
        "these",
        "those",
        "there",
        "here",
        "what",
        "who",
        "how",
        "why",
        "can",
        "cannot",
        "may",
        "might",
        "must",
        "shall",
        "upon",
        "also",
        "only",
        "just",
        "very",
        "some",
        "such",
        "each",
        "both",
        "few",
        "more",
        "most",
        "other",
        "same",
        "own",
        "too",
        "now",
        "get",
        "got",
        "set",
        "yet",
        "still",
        "about",
        "above",
        "below",
    }
)

ERROR_CODE_PATTERNS = [
    (re.compile(r"^ECONN(\w+)$"), lambda m: m.group(1).lower()),
    (re.compile(r"^ETIMED?OUT$"), lambda m: "timeout"),
    (re.compile(r"^ENOENT$"), lambda m: "missing"),
    (re.compile(r"^EPERM$"), lambda m: "denied"),
    (re.compile(r"^EACCES$"), lambda m: "denied"),
    (re.compile(r"^ESRCH$"), lambda m: "missing"),
    (re.compile(r"^E[A-Z]{2,10}$"), lambda m: m.group(0)[1:].lower()),
]

CAMEL_CASE_PATTERN = re.compile(r"([a-z])([A-Z])|([A-Z]+)([A-Z][a-z])")
WORD_NUM_PATTERN = re.compile(r"([a-zA-Z]+)(\d+)$")
NUM_WORD_PATTERN = re.compile(r"(\d+)([a-zA-Z]+)$")


_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*|\d+")


def split_camel_case(word: str) -> list[str]:
    split = re.sub(r"([a-z])([A-Z])", r"\1 \2", word)
    split = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", split)
    return split.lower().split()


def split_word_number(word: str) -> list[str]:
    m = WORD_NUM_PATTERN.match(word)
    if m:
        return [m.group(1), m.group(2)]
    m = NUM_WORD_PATTERN.match(word)
    if m:
        return [m.group(1), m.group(2)]
    return [word]


def detect_unknown_word(word: str, synonyms: dict[str, str] | None = None) -> str:
    syn = synonyms if synonyms is not None else BASE_SYNONYMS
    upper = word.upper()

    for pattern, handler in ERROR_CODE_PATTERNS:
        m = pattern.match(upper)
        if m:
            return handler(m)

    if CAMEL_CASE_PATTERN.search(word):
        parts = split_camel_case(word)
        return " ".join(syn.get(p, p) for p in parts)

    parts = split_word_number(word.lower())
    if len(parts) > 1:
        return " ".join(syn.get(p, p) for p in parts)

    return word.lower()


def normalize_message(msg: str, synonyms: dict[str, str] | None = None) -> str:

    syn = synonyms if synonyms is not None else BASE_SYNONYMS
    result: list[str] = []
    for tok in _TOKEN_RE.findall(msg):
        low = tok.lower()
        if low.isdigit():
            result.append(tok)
        elif low in syn:
            result.append(syn[low])
        else:
            result.append(detect_unknown_word(tok, syn))
    return " ".join(result)


def _corpus_fingerprint(messages: list[str]) -> str:
    h = hashlib.sha1()
    h.update(str(len(messages)).encode())
    for m in messages[:500]:
        h.update(m.encode("utf-8", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()


_MAX_SYNONYM_VOCAB = 2000


class SynonymLearner:
    CACHE_VERSION = 2

    def __init__(
        self,
        min_cooccurrence: int | None = None,
        similarity_threshold: float = 0.7,
        cache_dir: str | None = None,
        use_cache: bool = True,
    ):
        self.min_cooccurrence = min_cooccurrence
        self.similarity_threshold = similarity_threshold
        self.use_cache = use_cache
        self.learned: dict[str, str] = {}
        self.word_freq: dict[str, int] = defaultdict(int)
        self.cooccurrence: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        base = cache_dir or platformdirs.user_cache_dir("loglens")
        self._cache_path = os.path.join(base, "synonyms.json")

    def _load_cache(self, fingerprint: str) -> bool:
        """Return True (and populate ``learned``) only when the cached
        fingerprint matches the current corpus."""
        if not self.use_cache:
            return False
        try:
            with open(self._cache_path, encoding="utf-8") as f:
                data = json.load(f)
            if data.get("version") == self.CACHE_VERSION and data.get("corpus_hash") == fingerprint:
                self.learned = dict(data.get("learned", {}))
                return True
        except (OSError, ValueError, TypeError) as e:
            # Corrupt/unreadable cache — relearn from scratch, but leave a trace.
            logger.debug("synonym cache read skipped (%s): %s", type(e).__name__, e)
        return False

    def _save_cache(self, fingerprint: str) -> None:
        if not self.use_cache:
            return
        try:
            os.makedirs(os.path.dirname(self._cache_path), exist_ok=True)
            payload = {
                "version": self.CACHE_VERSION,
                "corpus_hash": fingerprint,
                "learned": self.learned,
            }
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self._cache_path), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp, self._cache_path)
        except OSError as e:
            logger.debug("synonym cache write skipped: %s", e)

    def _tokenize(self, msg: str) -> list[str]:
        toks = []
        for t in _TOKEN_RE.findall(msg.lower()):
            if len(t) < 3 or t.isdigit() or t in STOPWORDS:
                continue
            toks.append(t)
        return toks

    def fit(self, messages: Iterable[str]) -> None:
        messages = list(messages)
        fingerprint = _corpus_fingerprint(messages)
        if self._load_cache(fingerprint):
            return

        self.learned = {}
        self.word_freq = defaultdict(int)
        self.cooccurrence = defaultdict(lambda: defaultdict(int))

        min_cooc = self.min_cooccurrence
        if min_cooc is None:
            min_cooc = max(2, len(messages) // 500)

        for msg in messages:
            tokens = self._tokenize(msg)
            for token in tokens:
                self.word_freq[token] += 1
            for i, t1 in enumerate(tokens):
                for t2 in tokens[max(0, i - 3) : i + 4]:
                    if t1 != t2:
                        self.cooccurrence[t1][t2] += 1

        known = set(BASE_SYNONYMS)
        # Synonym search is O(vocab^2). On high-cardinality logs (unique node ids,
        # hex addresses, numbers) the vocabulary explodes into the hundreds of
        # thousands and this would run for minutes and exhaust memory. When the
        # vocabulary is that large, restrict the search to the most frequent
        # tokens — rare, near-unique tokens are never good synonym targets anyway.
        # Small corpora keep the exact previous behaviour (iteration order and all).
        if len(self.word_freq) <= _MAX_SYNONYM_VOCAB:
            rare_candidates: list[str] = sorted(self.cooccurrence)
            common_candidates: list[str] = sorted(self.word_freq)
        else:
            top = sorted(self.word_freq, key=lambda t: (-self.word_freq[t], t))[:_MAX_SYNONYM_VOCAB]
            rare_candidates = top
            common_candidates = top
        for rare in rare_candidates:
            if rare in known or rare in STOPWORDS:
                continue
            rare_freq = self.word_freq[rare]
            rare_ctx = self.cooccurrence[rare]
            rare_chars = set(rare)
            best: str | None = None
            best_sim = 0.0
            for common in common_candidates:
                if (
                    common == rare
                    or common in STOPWORDS
                    or len(common) <= len(rare)
                    or self.word_freq[common] < rare_freq
                ):
                    continue
                overlap = len(rare_chars & set(common)) / len(rare_chars)
                if overlap < 0.6:
                    continue
                common_ctx = self.cooccurrence[common]
                shared = sum(min(c, common_ctx.get(w, 0)) for w, c in rare_ctx.items())
                if shared < min_cooc:
                    continue
                total = sum(rare_ctx.values()) or 1
                sim = shared / total
                if sim >= self.similarity_threshold and sim > best_sim:
                    best, best_sim = common, sim
            if best:
                self.learned[rare] = best

        self._save_cache(fingerprint)

    def get_all_synonyms(self) -> dict[str, str]:
        merged = dict(BASE_SYNONYMS)
        merged.update(self.learned)
        return merged
