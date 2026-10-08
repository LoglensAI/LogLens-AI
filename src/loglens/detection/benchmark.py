from __future__ import annotations

import itertools
import json
import statistics as _st
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, train_test_split

from loglens.detection.detector import (
    DetectorConfig,
    detect,
    get_severity,
)
from loglens.detection.embeddings import EmbeddingEngine, features_cached
from loglens.detection.parser import detect_format, parse_line
from loglens.domain.errors import LogLensError
from loglens.domain.models import LogEntry

_LABEL_FORMATS = ("bgl", "jsonl", "labeled")


def _guess_label_format(line: str) -> str:
    """Best guess at the label format of a sample line (for a helpful hint)."""
    s = line.strip()
    if s.startswith("{") and '"label"' in s:
        return "jsonl"
    if "\t" in line and line.split("\t", 1)[0].strip() in ("0", "1"):
        return "labeled"
    return "bgl"


def _label_format_error(path: str, fmt: str, lineno: int, sample: str) -> LogLensError:
    guess = _guess_label_format(sample)
    snippet = sample.strip()[:70]
    hint = f" This looks like a '{guess}' file — try --format {guess}." if guess != fmt else ""
    return LogLensError(
        f"{path}: line {lineno} isn't valid '{fmt}' label format "
        f"(got: {snippet!r}).{hint}\n"
        f"Supported --format values: {', '.join(_LABEL_FORMATS)}. "
        "bgl = '<label> message' ('-' is normal); "
        "labeled = '<0|1>\\t<message>'; "
        'jsonl = \'{"label": 0, "line": "..."}\' per line.'
    )


@dataclass
class Metrics:
    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    fn: int
    tn: int
    support_pos: int
    n: int

    def as_dict(self) -> dict[str, float]:
        return self.__dict__.copy()

    def __str__(self) -> str:
        return (
            f"P={self.precision:.3f}  R={self.recall:.3f}  "
            f"F1={self.f1:.3f}  (tp={self.tp} fp={self.fp} "
            f"fn={self.fn} tn={self.tn}, pos={self.support_pos}/{self.n})"
        )


def score_prf1(y_true: Sequence[int], y_pred: Sequence[bool]) -> Metrics:
    yt = np.asarray(y_true, dtype=bool)
    yp = np.asarray(y_pred, dtype=bool)
    tp = int((yt & yp).sum())
    fp = int((~yt & yp).sum())
    fn = int((yt & ~yp).sum())
    tn = int((~yt & ~yp).sum())
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return Metrics(p, r, f, tp, fp, fn, tn, int(yt.sum()), len(yt))


def _iter_labeled(path: str, fmt: str) -> Iterable[tuple[int, str]]:
    if fmt not in _LABEL_FORMATS:
        raise LogLensError(f"unknown --format '{fmt}'. Supported: {', '.join(_LABEL_FORMATS)}.")
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            if fmt == "bgl":
                tok, _, rest = line.partition(" ")
                yield (0 if tok == "-" else 1), rest
            elif fmt == "labeled":
                tok, _, rest = line.partition("\t")
                if not _ and not rest:
                    raise _label_format_error(path, fmt, lineno, line)
                try:
                    label = int(tok.strip())
                except ValueError:
                    raise _label_format_error(path, fmt, lineno, line) from None
                yield label, rest
            elif fmt == "jsonl":
                try:
                    obj = json.loads(line)
                except ValueError:
                    raise _label_format_error(path, fmt, lineno, line) from None
                if not isinstance(obj, dict):
                    raise _label_format_error(path, fmt, lineno, line)
                try:
                    label = int(obj.get("label", 0))
                except (ValueError, TypeError):
                    raise _label_format_error(path, fmt, lineno, line) from None
                yield label, str(obj.get("line", ""))


def load_labeled(
    path: str, fmt: str = "bgl", limit: int | None = None
) -> tuple[list[LogEntry], np.ndarray]:
    raw: list[tuple[int, str]] = []
    for i, (lab, text) in enumerate(_iter_labeled(path, fmt)):
        if limit is not None and i >= limit:
            break
        raw.append((lab, text))
    if not raw:
        return [], np.zeros(0, dtype=int)

    log_fmt = detect_format(raw[0][1])
    entries: list[LogEntry] = []
    labels: list[int] = []
    for lab, text in raw:
        e = parse_line(text, log_fmt)
        if e is None:
            e = LogEntry(
                timestamp="", level="INFO", service="unknown", message=text, raw=text, parsed=False
            )
        entries.append(e)
        labels.append(int(lab))
    return entries, np.asarray(labels, dtype=int)


def evaluate(
    entries: Sequence[LogEntry],
    labels: Sequence[int],
    cfg: DetectorConfig | None = None,
    feature_weight: float | None = None,
    min_df: float | None = None,
) -> tuple[Metrics, object]:
    engine = (
        EmbeddingEngine(feature_weight=feature_weight)
        if feature_weight is not None
        else EmbeddingEngine()
    )
    if min_df is not None:
        engine.vectorizer.set_params(min_df=int(min_df))
    vecs = engine.embed(list(entries))
    res = detect(list(entries), vecs, cfg or DetectorConfig())
    return score_prf1(labels, res.flagged), res


@dataclass
class GridResult:
    best_f1: float
    best_params: dict[str, float | None]
    best_metrics: Metrics
    table: list[dict[str, float | None]] = field(default_factory=list)


DEFAULT_GRID = {
    "feature_weight": [0.3, 0.4, 0.5],
    "flag_threshold": [0.5, 0.6, 0.7, 0.8],
}


def grid_search(
    entries: Sequence[LogEntry],
    labels: Sequence[int],
    grid: dict[str, list[float]] | None = None,
) -> GridResult:
    grid = grid or DEFAULT_GRID
    fws = grid.get("feature_weight", [None])
    ths = grid.get("flag_threshold", [0.70])
    mdfs = grid.get("min_df", [None])

    best: GridResult | None = None
    table: list[dict[str, float | None]] = []
    for fw, th, mdf in itertools.product(fws, ths, mdfs):
        cfg = DetectorConfig(flag_threshold=th)
        m, _ = evaluate(entries, labels, cfg, feature_weight=fw, min_df=mdf)
        row = {
            "feature_weight": fw,
            "flag_threshold": th,
            "min_df": mdf,
            "precision": m.precision,
            "recall": m.recall,
            "f1": m.f1,
        }
        table.append(row)
        if best is None or m.f1 > best.best_f1:
            best = GridResult(
                best_f1=m.f1,
                best_params={"feature_weight": fw, "flag_threshold": th, "min_df": mdf},
                best_metrics=m,
                table=table,
            )
    if best is None:
        raise ValueError("empty grid")
    best.table = table
    return best


def build_feature_matrix(entries: Sequence[LogEntry], scores: np.ndarray) -> np.ndarray:
    sev = np.array([get_severity(e.level) for e in entries], dtype=np.float32) / 7.0
    logf = np.array([features_cached(e) for e in entries], dtype=np.float32)
    return np.column_stack([scores.astype(np.float32), sev, logf])


class SupervisedHead:
    def __init__(
        self,
        model: str = "rf",
        class_weight: str = "balanced",
        max_iter: int = 1000,
        n_estimators: int = 300,
        random_state: int = 0,
    ):
        if model == "rf":
            self.clf = RandomForestClassifier(
                n_estimators=n_estimators, class_weight=class_weight, random_state=random_state
            )
        else:
            self.clf = LogisticRegression(class_weight=class_weight, max_iter=max_iter)
        self.fitted = False

    def fit(self, X: np.ndarray, y: Sequence[int]) -> SupervisedHead:
        self.clf.fit(X, np.asarray(y, dtype=int))
        self.fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.clf.predict(X).astype(bool)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.clf.predict_proba(X)[:, 1]

    def save(self, path: str) -> None:
        joblib.dump({"clf": self.clf, "version": 1}, path, compress=3)

    @classmethod
    def load(cls, path: str) -> SupervisedHead:
        obj = cls.__new__(cls)
        blob = joblib.load(path)
        obj.clf = blob["clf"] if isinstance(blob, dict) else blob
        obj.fitted = True
        return obj


def train_supervised(
    entries: Sequence[LogEntry],
    labels: Sequence[int],
    test_size: float = 0.4,
    random_state: int = 0,
) -> tuple[SupervisedHead, Metrics]:
    engine = EmbeddingEngine()
    vecs = engine.embed(list(entries))
    res = detect(list(entries), vecs, DetectorConfig())
    X = build_feature_matrix(entries, res.scores)
    y = np.asarray(labels, dtype=int)

    stratify = y if len(set(y.tolist())) > 1 else None
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=stratify
    )
    head = SupervisedHead().fit(Xtr, ytr)
    metrics = score_prf1(yte, head.predict(Xte))
    return head, metrics


def cross_validate_supervised(
    entries: Sequence[LogEntry],
    labels: Sequence[int],
    n_splits: int = 5,
    model: str = "rf",
    random_state: int = 0,
) -> dict[str, object]:
    engine = EmbeddingEngine()
    vecs = engine.embed(list(entries))
    res = detect(list(entries), vecs, DetectorConfig())
    X = build_feature_matrix(entries, res.scores)
    y = np.asarray(labels, dtype=int)
    if len(set(y.tolist())) < 2:
        raise ValueError("need both classes present for cross-validation")

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    ps, rs, fs = [], [], []
    for tr, te in skf.split(X, y):
        head = SupervisedHead(model=model).fit(X[tr], y[tr])
        m = score_prf1(y[te], head.predict(X[te]))
        ps.append(m.precision)
        rs.append(m.recall)
        fs.append(m.f1)

    def _ms(a):
        return {"mean": sum(a) / len(a), "std": _st.pstdev(a) if len(a) > 1 else 0.0}

    return {
        "folds": n_splits,
        "model": model,
        "precision": _ms(ps),
        "recall": _ms(rs),
        "f1": _ms(fs),
    }


def train_and_save(
    entries: Sequence[LogEntry], labels: Sequence[int], out_path: str, model: str = "rf"
) -> SupervisedHead:
    engine = EmbeddingEngine()
    vecs = engine.embed(list(entries))
    res = detect(list(entries), vecs, DetectorConfig())
    X = build_feature_matrix(entries, res.scores)
    head = SupervisedHead(model=model).fit(X, np.asarray(labels, dtype=int))
    head.save(out_path)
    return head


def run_benchmark(
    path: str,
    fmt: str = "bgl",
    limit: int | None = None,
    do_grid: bool = False,
    do_supervised: bool = False,
) -> dict[str, object]:
    entries, labels = load_labeled(path, fmt, limit=limit)
    out: dict[str, object] = {
        "dataset": path,
        "format": fmt,
        "entries": len(entries),
        "positives": int(labels.sum()),
    }
    if not entries:
        return out

    baseline, _ = evaluate(entries, labels)
    out["baseline"] = baseline.as_dict()

    if do_grid:
        gr = grid_search(entries, labels)
        out["grid_best_f1"] = gr.best_f1
        out["grid_best_params"] = gr.best_params

    if do_supervised and len(set(labels.tolist())) > 1:
        _, sup = train_supervised(entries, labels)
        out["supervised"] = sup.as_dict()

    return out
