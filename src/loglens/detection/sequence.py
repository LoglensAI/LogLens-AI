from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence

import numpy as np

from loglens.detection.templates import template_key
from loglens.domain.models import LogEntry

_BLK_RE = re.compile(r"\bblk_-?\d+\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_IDKEY_RE = re.compile(
    r"\b(?:request|req|trace|txn|transaction|correlation|corr|session|sess|span|block|"
    r"pod|container|job|task|flow|order|instance)[ _-]?id\b\s*[=:]?\s*([A-Za-z0-9._\-/]+)",
    re.IGNORECASE,
)

_BOS = "\x00BOS"
_EOS = "\x00EOS"


def extract_session_key(text: str) -> str | None:
    m = _BLK_RE.search(text)
    if m:
        return m.group(0)
    m = _UUID_RE.search(text)
    if m:
        return m.group(0)
    m = _IDKEY_RE.search(text)
    if m:
        return m.group(1)
    return None


def _short(template: str, limit: int = 48) -> str:
    t = template.strip()
    return t if len(t) <= limit else t[: limit - 1] + "…"


def sequence_anomaly_scores(
    entries: Sequence[LogEntry],
    *,
    min_sessions: int = 5,
    min_coverage: float = 0.5,
    min_pred: int = 5,
    flag_at: float = 0.70,
) -> tuple[np.ndarray, list[list[str]], str]:

    n = len(entries)
    scores = np.zeros(n, dtype=np.float64)
    reasons: list[list[str]] = [[] for _ in range(n)]
    if n == 0:
        return scores, reasons, ""

    sessions: dict[str, list[tuple[int, str]]] = defaultdict(list)
    keyed = 0
    for i, e in enumerate(entries):
        key = extract_session_key(e.message or e.raw or "")
        if key is None:
            continue
        keyed += 1
        sessions[key].append((i, template_key(e.message or "")))

    coverage = keyed / n
    if len(sessions) < min_sessions or coverage < min_coverage:
        return (
            scores,
            reasons,
            (
                f"sequence detection skipped: only {len(sessions)} session(s) / "
                f"{coverage:.0%} of lines keyed (need ≥{min_sessions} and ≥{min_coverage:.0%})"
            ),
        )

    trans: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    pred: dict[str, int] = defaultdict(int)
    vocab: set[str] = {_EOS}
    for events in sessions.values():
        prev = _BOS
        for _idx, tmpl in events:
            trans[prev][tmpl] += 1
            pred[prev] += 1
            vocab.add(tmpl)
            prev = tmpl
        trans[prev][_EOS] += 1
        pred[prev] += 1

    v = len(vocab)
    alpha = 1.0

    flagged_sessions = 0
    for key, events in sessions.items():
        idxs = [idx for idx, _ in events]
        worst = 0.0
        prev = _BOS
        prev_idx = -1
        for idx, tmpl in events:
            if pred[prev] >= min_pred:
                p = (trans[prev].get(tmpl, 0) + alpha) / (pred[prev] + alpha * v)
                surprise = 1.0 - p
                if surprise > scores[idx]:
                    scores[idx] = surprise
                if surprise >= flag_at:
                    from_t = "session start" if prev == _BOS else f"'{_short(prev)}'"
                    reasons[idx].append(
                        f"rare sequence in session {key}: {from_t} → '{_short(tmpl)}' (p={p:.3f})"
                    )
                worst = max(worst, surprise)
            prev, prev_idx = tmpl, idx
        if pred[prev] >= min_pred:
            p_end = (trans[prev].get(_EOS, 0) + alpha) / (pred[prev] + alpha * v)
            surprise_end = 1.0 - p_end
            if surprise_end >= flag_at and prev_idx >= 0:
                if surprise_end > scores[prev_idx]:
                    scores[prev_idx] = surprise_end
                reasons[prev_idx].append(
                    f"session {key} ended unexpectedly after '{_short(prev)}' (p={p_end:.3f})"
                )
            worst = max(worst, surprise_end)
        if worst >= flag_at:
            flagged_sessions += 1
            for idx in idxs:
                if worst > scores[idx]:
                    scores[idx] = worst
            reasons[idxs[0]].insert(
                0, f"anomalous session {key}: unlikely event order (worst step p={1 - worst:.3f})"
            )

    note = (
        f"sequence: {len(sessions)} sessions ({coverage:.0%} of lines keyed), "
        f"{flagged_sessions} with an anomalous order"
    )
    return scores, reasons, note
