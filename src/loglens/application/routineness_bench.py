from __future__ import annotations

import random
from dataclasses import dataclass

from loglens.detection.routineness import compute_routineness
from loglens.detection.templates import template_key

_MODES = ("normal", "drop", "invert")
_PROMOTE_AUC = 0.65


@dataclass
class VariantResult:
    mode: str
    auc: float | None
    ci_low: float | None
    ci_high: float | None
    n_benign: int
    n_anomalous: int

    @property
    def promotable(self) -> bool:
        return (
            self.auc is not None
            and self.ci_low is not None
            and self.auc >= _PROMOTE_AUC
            and self.ci_low > 0.5
        )


def _auc(benign: list[float], anom: list[float]) -> float | None:
    if not benign or not anom:
        return None
    pooled = sorted(((v, 0) for v in benign), key=lambda x: x[0]) + [(v, 1) for v in anom]
    pooled.sort(key=lambda x: x[0])
    ranks: dict[int, float] = {}
    i = 0
    N = len(pooled)
    while i < N:
        j = i
        while j < N and pooled[j][0] == pooled[i][0]:
            j += 1
        avg = (i + 1 + j) / 2.0  # average of ranks i+1..j
        for k in range(i, j):
            ranks[k] = avg
        i = j
    sum_benign_ranks = sum(ranks[k] for k, (_, lbl) in enumerate(pooled) if lbl == 0)
    n_b = len(benign)
    n_a = len(anom)
    u = sum_benign_ranks - n_b * (n_b + 1) / 2.0
    return u / (n_b * n_a)


def _bootstrap_ci(
    pairs: list[tuple[float, int]], *, n_boot: int = 1000, seed: int = 0
) -> tuple[float | None, float | None]:
    benign = [r for r, lbl in pairs if lbl == 0]
    anom = [r for r, lbl in pairs if lbl == 1]
    if not benign or not anom:
        return None, None
    rng = random.Random(seed)
    aucs: list[float] = []
    for _ in range(n_boot):
        bs = [rng.choice(pairs) for _ in pairs]
        b = [r for r, lbl in bs if lbl == 0]
        a = [r for r, lbl in bs if lbl == 1]
        val = _auc(b, a)
        if val is not None:
            aucs.append(val)
    if not aucs:
        return None, None
    aucs.sort()
    lo = aucs[int(0.025 * len(aucs))]
    hi = aucs[min(int(0.975 * len(aucs)), len(aucs) - 1)]
    return round(lo, 4), round(hi, 4)


def _template_labels(entries: list, anomaly_ordinals: set[int]) -> dict[str, bool]:
    anom: dict[str, bool] = {}
    for i, e in enumerate(entries):
        tk = template_key(getattr(e, "message", "") or "")
        ordinal = i + 1  # 1-based, matches labels.json convention
        anom[tk] = anom.get(tk, False) or (ordinal in anomaly_ordinals)
    return anom


def evaluate(
    entries: list,
    anomaly_ordinals: set[int],
    *,
    min_count: int = 5,
    n_boot: int = 1000,
    seed: int = 0,
) -> dict[str, VariantResult]:
    labels = _template_labels(entries, anomaly_ordinals)
    out: dict[str, VariantResult] = {}
    for mode in _MODES:
        rmap = compute_routineness(entries, min_count=min_count, host_spread_mode=mode)
        pairs = [
            (r.r, 1 if labels.get(tk, False) else 0) for tk, r in rmap.items() if r.r is not None
        ]
        benign = [r for r, lbl in pairs if lbl == 0]
        anom = [r for r, lbl in pairs if lbl == 1]
        auc = _auc(benign, anom)
        lo, hi = _bootstrap_ci(pairs, n_boot=n_boot, seed=seed) if auc is not None else (None, None)
        out[mode] = VariantResult(
            mode=mode,
            auc=(round(auc, 4) if auc is not None else None),
            ci_low=lo,
            ci_high=hi,
            n_benign=len(benign),
            n_anomalous=len(anom),
        )
    return out


def best_variant(results: dict[str, VariantResult]) -> VariantResult:
    ordered = sorted(
        results.values(),
        key=lambda v: (-(v.auc or 0.0), _MODES.index(v.mode)),
    )
    return ordered[0]
