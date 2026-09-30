from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, cast

from loglens.application.api import analyze_entries
from loglens.detection.parser import parse_line, sniff_format
from loglens.detection.run import RunConfig
from loglens.detection.templates import template_key

SCHEMA = "loglens.bench.v1"


@dataclass
class FileMetrics:
    name: str
    lines: int
    parsed: int
    labeled: int
    flagged: int
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    precision_at_k: float
    pr_auc: float | None
    families: int
    compression: float
    parse_seconds: float
    analyze_seconds: float
    lines_per_sec: float
    fmt: str
    fmt_confidence: float
    window_size: int = 100
    window_precision: float = 0.0
    window_recall: float = 0.0
    window_f1: float = 0.0
    template_precision: float = 0.0
    template_recall: float = 0.0
    template_f1: float = 0.0
    sup_precision: float | None = None
    sup_recall: float | None = None
    sup_f1: float | None = None


@dataclass
class SuiteReport:
    schema: str
    directory: str
    mode: str
    seed: int
    files: list[FileMetrics] = field(default_factory=list)
    micro: dict[str, float] = field(default_factory=dict)
    macro: dict[str, float] = field(default_factory=dict)
    totals: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def _pr_auc(scores: list[float], labels: list[int]) -> float | None:
    if len(set(labels)) < 2:
        return None
    try:
        from sklearn.metrics import average_precision_score

        return round(float(average_precision_score(labels, scores)), 4)
    except Exception:
        return None


def _set_prf(pred: set, truth: set) -> tuple[float, float, float]:
    if not truth:
        clean = len(pred) == 0
        return (1.0, 1.0, 1.0) if clean else (0.0, 1.0, 0.0)
    return _prf(len(pred & truth), len(pred - truth), len(truth - pred))


def _window_prf(
    n: int, flagged_lines: set[int], labeled: set[int], window: int
) -> tuple[float, float, float]:
    pred: set[int] = set()
    truth: set[int] = set()
    for i in range(n):
        w = i // window
        if (i + 1) in flagged_lines:
            pred.add(w)
        if (i + 1) in labeled:
            truth.add(w)
    return _set_prf(pred, truth)


def _template_prf(
    tmpl_of: list[str], flagged_lines: set[int], labeled: set[int]
) -> tuple[float, float, float]:
    pred = {tmpl_of[i] for i in range(len(tmpl_of)) if (i + 1) in flagged_lines}
    truth = {tmpl_of[i] for i in range(len(tmpl_of)) if (i + 1) in labeled}
    return _set_prf(pred, truth)


def _supervised_prf(entries, labeled: set[int], seed: int) -> tuple[float, float, float] | None:
    n = len(entries)
    y = [1 if (i + 1) in labeled else 0 for i in range(n)]
    pos = sum(y)
    if pos < 5 or (n - pos) < 5:  # 5-fold CV needs ≥5 of each class
        return None
    try:
        from loglens.detection.benchmark import cross_validate_supervised

        cv = cast(
            "dict[str, Any]",
            cross_validate_supervised(entries, y, n_splits=5, model="rf", random_state=seed),
        )
        return (
            round(float(cv["precision"]["mean"]), 4),
            round(float(cv["recall"]["mean"]), 4),
            round(float(cv["f1"]["mean"]), 4),
        )
    except Exception:
        return None


def _seed(seed: int) -> None:
    try:
        import numpy as np

        np.random.seed(seed)
    except Exception:
        pass


def bench_file(
    path: str,
    anomaly_lines: list[int],
    mode: str = "fast",
    seed: int = 0,
    window: int = 100,
    supervised: bool = False,
) -> FileMetrics:
    _seed(seed)
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = fh.readlines()

    t0 = time.perf_counter()
    fmt, confidence, layout = sniff_format(raw)
    entries = []
    for line in raw:
        e = parse_line(line, fmt, layout)
        if e is not None:
            entries.append(e)
    parse_seconds = time.perf_counter() - t0

    t1 = time.perf_counter()
    result = analyze_entries(entries, RunConfig(mode=mode), fmt=fmt)
    analyze_seconds = time.perf_counter() - t1

    n = len(entries)
    labeled = set(anomaly_lines)
    flagged_lines = {a.index + 1 for a in result.anomalies if a.index is not None}
    tp = len(flagged_lines & labeled)
    fp = len(flagged_lines - labeled)
    fn = len(labeled - flagged_lines)
    scores = result.detection.scores
    if not labeled:
        recall = 1.0
        precision = 1.0 if fp == 0 else 0.0
        f1 = 1.0 if fp == 0 else 0.0
        precision_at_k = 1.0 if fp == 0 else 0.0
    else:
        precision, recall, f1 = _prf(tp, fp, fn)
        order = sorted(range(n), key=lambda i: (-float(scores[i]), i))
        topk = order[: len(labeled)]
        precision_at_k = sum(1 for i in topk if (i + 1) in labeled) / len(topk) if topk else 0.0
    pr_auc = _pr_auc(
        [float(scores[i]) for i in range(n)],
        [1 if (i + 1) in labeled else 0 for i in range(n)],
    )

    wp, wr, wf = _window_prf(n, flagged_lines, labeled, window)
    tmpl_of = [template_key(e.message or "") for e in entries]
    tp_p, tp_r, tp_f = _template_prf(tmpl_of, flagged_lines, labeled)
    sup = _supervised_prf(entries, labeled, seed) if supervised else None

    families = len(result.detection.groups)
    compression = (len(flagged_lines) / families) if families else 0.0
    total_seconds = parse_seconds + analyze_seconds
    lines = len(raw)
    lines_per_sec = lines / total_seconds if total_seconds else 0.0

    return FileMetrics(
        name=os.path.basename(path),
        lines=lines,
        parsed=n,
        labeled=len(labeled),
        flagged=len(flagged_lines),
        tp=tp,
        fp=fp,
        fn=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        precision_at_k=round(precision_at_k, 4),
        pr_auc=pr_auc,
        families=families,
        compression=round(compression, 2),
        parse_seconds=round(parse_seconds, 4),
        analyze_seconds=round(analyze_seconds, 4),
        lines_per_sec=round(lines_per_sec, 1),
        fmt=fmt,
        fmt_confidence=confidence,
        window_size=window,
        window_precision=round(wp, 4),
        window_recall=round(wr, 4),
        window_f1=round(wf, 4),
        template_precision=round(tp_p, 4),
        template_recall=round(tp_r, 4),
        template_f1=round(tp_f, 4),
        sup_precision=None if sup is None else sup[0],
        sup_recall=None if sup is None else sup[1],
        sup_f1=None if sup is None else sup[2],
    )


def run_suite(
    directory: str,
    mode: str = "fast",
    seed: int = 0,
    exclude: list[str] | None = None,
    window: int = 100,
    supervised: bool = False,
) -> SuiteReport:
    labels_path = os.path.join(directory, "labels.json")
    if not os.path.isfile(labels_path):
        raise FileNotFoundError(
            f"no labels.json in {directory!r} — generate one with scripts/gen_test_logs.py"
        )
    with open(labels_path, encoding="utf-8") as fh:
        labels = json.load(fh)

    exclude_set = set(exclude or [])
    report = SuiteReport(schema=SCHEMA, directory=directory, mode=mode, seed=seed)

    for name in sorted(labels):  # sorted → deterministic file order
        if name in exclude_set:
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        anomaly_lines = labels[name].get("anomaly_lines", [])
        report.files.append(
            bench_file(
                path, anomaly_lines, mode=mode, seed=seed, window=window, supervised=supervised
            )
        )

    _aggregate(report)
    return report


def _aggregate(report: SuiteReport) -> None:
    files = report.files
    if not files:
        return
    tp = sum(f.tp for f in files)
    fp = sum(f.fp for f in files)
    fn = sum(f.fn for f in files)
    mp, mr, mf = _prf(tp, fp, fn)
    report.micro = {
        "precision": round(mp, 4),
        "recall": round(mr, 4),
        "f1": round(mf, 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }
    k = len(files)
    report.macro = {
        "precision": round(sum(f.precision for f in files) / k, 4),
        "recall": round(sum(f.recall for f in files) / k, 4),
        "f1": round(sum(f.f1 for f in files) / k, 4),
        "precision_at_k": round(sum(f.precision_at_k for f in files) / k, 4),
        "window_precision": round(sum(f.window_precision for f in files) / k, 4),
        "window_recall": round(sum(f.window_recall for f in files) / k, 4),
        "window_f1": round(sum(f.window_f1 for f in files) / k, 4),
        "template_f1": round(sum(f.template_f1 for f in files) / k, 4),
    }
    sp = [f.sup_precision for f in files if f.sup_precision is not None]
    sr = [f.sup_recall for f in files if f.sup_recall is not None]
    sf = [f.sup_f1 for f in files if f.sup_f1 is not None]
    if sf:
        report.macro["supervised_precision"] = round(sum(sp) / len(sp), 4)
        report.macro["supervised_recall"] = round(sum(sr) / len(sr), 4)
        report.macro["supervised_f1"] = round(sum(sf) / len(sf), 4)
    total_lines = sum(f.lines for f in files)
    total_seconds = sum(f.parse_seconds + f.analyze_seconds for f in files)
    report.totals = {
        "files": k,
        "lines": total_lines,
        "seconds": round(total_seconds, 3),
        "lines_per_sec": round(total_lines / total_seconds, 1) if total_seconds else 0.0,
    }


def to_markdown(report: SuiteReport) -> str:
    lines = [
        f"# LogLens Bench — `{report.directory}`",
        "",
        f"mode: `{report.mode}` · seed: `{report.seed}` · schema: `{report.schema}`",
        "",
        "| file | fmt | lines | labeled | line F1 | **win F1** | win P | win R | tmpl F1 "
        "| sup F1 | compress | lines/s |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for f in report.files:
        sup = "—" if f.sup_f1 is None else f"{f.sup_f1:.3f}"
        lines.append(
            f"| {f.name} | {f.fmt} | {f.lines:,} | {f.labeled} | {f.f1:.3f} | "
            f"**{f.window_f1:.3f}** | {f.window_precision:.3f} | {f.window_recall:.3f} | "
            f"{f.template_f1:.3f} | {sup} | {f.compression:.1f}× | {f.lines_per_sec:,.0f} |"
        )
    m, ma, t = report.micro, report.macro, report.totals
    lines += [
        "",
        "## Aggregate",
        "",
        f"- **Window-level (headline)**: P {ma.get('window_precision', 0):.3f} · "
        f"R {ma.get('window_recall', 0):.3f} · **F1 {ma.get('window_f1', 0):.3f}**",
        f"- **Template-level**: F1 {ma.get('template_f1', 0):.3f}",
        f"- **Line-level**: micro-F1 {m.get('f1', 0):.3f} "
        f"(P {m.get('precision', 0):.3f} · R {m.get('recall', 0):.3f}) — reported, not the headline",
    ]
    if "supervised_f1" in ma:
        lines.append(
            f"- **Supervised head (5-fold CV)**: P {ma['supervised_precision']:.3f} · "
            f"R {ma['supervised_recall']:.3f} · **F1 {ma['supervised_f1']:.3f}**"
        )
    lines += [
        f"- **Throughput**: {t.get('lines', 0):,} lines in {t.get('seconds', 0):.2f}s "
        f"→ {t.get('lines_per_sec', 0):,.0f} lines/sec",
        "",
    ]
    return "\n".join(lines)
