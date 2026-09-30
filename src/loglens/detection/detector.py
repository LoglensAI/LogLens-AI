from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import normalize

from loglens.detection.cooccurrence import cooccurrence_boost
from loglens.detection.parameters import parameter_anomaly_scores
from loglens.detection.rate import rate_burst_scores
from loglens.detection.safety_floor import safety_floor
from loglens.detection.sequence import sequence_anomaly_scores
from loglens.detection.templates import TemplateRegistry, parse_timestamp
from loglens.domain.models import LogEntry
from loglens.domain.scoring import (
    HISTORY_HEAD,
    Signals,
    soft_cap,  # noqa: F401  (re-exported for callers/tests)
    volume_confidence,
)
from loglens.domain.scoring import score as policy_score
from loglens.domain.severity import (  # noqa: F401
    DEFAULT_SEVERITY,
    HARD_FLAG_SEVERITY,
    SEVERITY_BASE,
    get_severity,
)

# Signal-computation thresholds — these decide *whether* a signal fires. The
# scoring weights and soft-cap themselves live in loglens.domain.scoring, which
# is the single scoring policy every mode shares.
CHRONIC_SHARE = 0.15
CHRONIC_MIN_COUNT = 25
CHRONIC_SPREAD = 0.50
GLOBAL_RARE_SHARE = 0.005


def otsu_threshold(
    scores: np.ndarray, lo: float = 0.35, hi: float = 0.95, bins: int = 64
) -> float | None:
    s = np.asarray(scores, dtype=np.float64)
    s = s[(s > 0.0) & (s < 1.0)]  # 0/1 are already hard-decided
    if len(s) < 20:
        return None
    hist, edges = np.histogram(s, bins=bins, range=(0.0, 1.0))
    total = float(hist.sum())
    if total == 0:
        return None
    p = hist.astype(np.float64) / total
    centers = (edges[:-1] + edges[1:]) / 2.0
    omega = np.cumsum(p)
    mu = np.cumsum(p * centers)
    mu_t = mu[-1]
    denom = omega * (1.0 - omega)
    with np.errstate(divide="ignore", invalid="ignore"):
        sigma_b = (mu_t * omega - mu) ** 2 / denom
    sigma_b = np.nan_to_num(sigma_b)
    t = centers[int(np.argmax(sigma_b))]
    return float(np.clip(t, lo, hi))


@dataclass
class DetectorConfig:
    eps: float | None = None
    min_samples: int = 4
    rare_pct: float = 0.02
    rare_min: int = 3
    flag_threshold: float = 0.70
    auto_threshold: bool = False
    safe_rarity_damp: float = 0.5
    burst_window: float = 60.0
    burst_factor: float = 4.0
    burst_min: int = 10
    enable_burst: bool = True
    flood_share: float = 0.20
    incident_share: float = 0.30
    pattern_min: int = 5
    max_patterns: int = 15
    recurring_share: float = 0.002
    recurring_min: int = 5
    rarity_confidence_k: float = 0.0
    seed: int = 0  # RNG seed for any sampling (e.g. eps estimation) — P1.5 determinism
    enable_sequence: bool = True  # P3.C session-order detector (auto-silent w/o sessions)
    enable_parameters: bool = True  # P3.D numeric-parameter outlier detector
    enable_rate: bool = True  # P3.B per-template rate/burst change-point detector
    enable_cooccurrence: bool = True  # incident co-occurrence boost (recall lever)
    enable_safety_floor: bool = True  # surface rare severe non-routine events (recall backstop)

    @classmethod
    def from_sensitivity(cls, sensitivity: str = "normal", **overrides) -> DetectorConfig:
        thresholds = {"low": 0.80, "normal": 0.70, "high": 0.60}
        cfg = cls(flag_threshold=thresholds.get(sensitivity, 0.70))
        for k, v in overrides.items():
            if v is not None and hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg


@dataclass
class AnomalyGroup:
    level: str
    template: str
    representative: LogEntry
    count: int
    score: float
    reasons: list[str]
    services: list[str]
    entry_indices: list[int]


@dataclass
class PatternInfo:
    level: str
    template: str
    representative: LogEntry
    count: int
    share: float
    services: list[str]
    flagged: bool


@dataclass
class DetectionResult:
    entries: Sequence[LogEntry]
    scores: np.ndarray
    flagged: np.ndarray
    reasons: list[list[str]]
    labels: np.ndarray
    groups: list[AnomalyGroup]
    patterns: list[PatternInfo]
    incident_mode: bool
    incident_note: str
    meta: dict[str, object] = field(default_factory=dict)

    @property
    def anomalies(self) -> list[LogEntry]:
        idx = np.argsort(-self.scores, kind="stable")
        return [self.entries[i] for i in idx if self.flagged[i]]

    @property
    def normal(self) -> list[LogEntry]:
        return [e for e, f in zip(self.entries, self.flagged, strict=False) if not f]

    def summary(self) -> dict[str, object]:
        n_clusters = len(set(self.labels.tolist()) - {-1})
        return {
            "entries": len(self.entries),
            "clusters": n_clusters,
            "anomalies": int(self.flagged.sum()),
            "anomaly_groups": len(self.groups),
            "patterns": len(self.patterns),
            "incident_mode": self.incident_mode,
        }


def estimate_eps(
    vectors: np.ndarray, k: int = 4, lo: float = 0.15, hi: float = 0.90, seed: int = 0
) -> float:
    n = len(vectors)
    if n <= k + 1:
        return 0.5
    sample = vectors
    if n > 5000:
        rng = np.random.default_rng(seed)
        sample = vectors[rng.choice(n, 5000, replace=False)]
    nn = NearestNeighbors(n_neighbors=min(k + 1, len(sample))).fit(sample)
    dists, _ = nn.kneighbors(sample)
    kdist = np.sort(dists[:, -1])

    x = np.linspace(0.0, 1.0, len(kdist))
    y = kdist
    x0, y0, x1, y1 = x[0], y[0], x[-1], y[-1]
    denom = math.hypot(x1 - x0, y1 - y0) or 1.0
    d = np.abs((y1 - y0) * x - (x1 - x0) * y + x1 * y0 - y1 * x0) / denom
    eps = float(y[int(np.argmax(d))])
    return float(np.clip(eps if eps > 0 else 0.5, lo, hi))


def detect_bursts(entries: Sequence[LogEntry], cfg: DetectorConfig) -> tuple[np.ndarray, str]:
    n = len(entries)
    burst = np.zeros(n, dtype=bool)
    times = np.array([parse_timestamp(e.timestamp) or np.nan for e in entries])
    valid = ~np.isnan(times)
    if valid.sum() < max(cfg.burst_min * 2, 20):
        return burst, "burst detection skipped: not enough parseable timestamps"

    t0 = np.nanmin(times)
    windows = np.floor((times - t0) / cfg.burst_window)

    severities = np.array([get_severity(e.level) for e in entries])
    for sev_level in np.unique(severities):
        if sev_level > 4:  # only WARN and worse can "burst"
            continue
        mask = (severities == sev_level) & valid
        if mask.sum() < cfg.burst_min:
            continue
        wins, counts = np.unique(windows[mask], return_counts=True)
        if len(wins) < 2:
            # everything in one window: no in-file baseline to compare
            # against — be conservative, skip.
            continue
        baseline = float(np.median(counts))
        threshold = max(cfg.burst_min, cfg.burst_factor * max(baseline, 1.0))
        hot = set(wins[counts >= threshold].tolist())
        if hot:
            in_hot = np.isin(windows, list(hot)) & mask
            burst |= in_hot
    return burst, ""


@dataclass
class _Signals:
    n: int
    registry: TemplateRegistry
    severities: np.ndarray
    levels: np.ndarray
    level_totals: dict[str, int]
    group_labels: np.ndarray
    cluster_sizes: dict[int, float]
    group_outlier: np.ndarray
    group_outlier_z: np.ndarray
    group_outlier_dist: np.ndarray
    group_chronic: np.ndarray
    group_span: np.ndarray
    group_history: np.ndarray
    burst_mask: np.ndarray
    group_flood: np.ndarray
    group_recurring: np.ndarray
    group_global_rare: np.ndarray
    group_novel: np.ndarray
    group_surge: np.ndarray


def _cluster_templates(
    vectors: np.ndarray, registry: TemplateRegistry, cfg: DetectorConfig
) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[int, float], float]:
    n_groups = len(registry)
    group_counts = np.array(registry.counts, dtype=np.float64)
    group_vectors = np.zeros((n_groups, vectors.shape[1]), dtype=np.float32)
    for gi, g in enumerate(registry.groups):
        group_vectors[gi] = vectors[g.indices].mean(axis=0)
    group_vectors = normalize(group_vectors, norm="l2")

    eps = (
        cfg.eps
        if cfg.eps is not None
        else estimate_eps(group_vectors, k=cfg.min_samples, seed=cfg.seed)
    )
    db = DBSCAN(eps=eps, min_samples=cfg.min_samples, metric="euclidean", n_jobs=-1)
    group_labels = db.fit_predict(group_vectors, sample_weight=group_counts)

    cluster_sizes: dict[int, float] = {}
    for gl, c in zip(group_labels, group_counts, strict=False):
        cluster_sizes[int(gl)] = cluster_sizes.get(int(gl), 0.0) + c
    return group_vectors, group_counts, group_labels, cluster_sizes, eps


def _level_outliers(
    group_level: list[str], group_counts: np.ndarray, group_vectors: np.ndarray, n_groups: int
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    group_outlier = np.zeros(n_groups, dtype=bool)
    group_outlier_z = np.zeros(n_groups, dtype=np.float64)
    group_outlier_dist = np.zeros(n_groups, dtype=np.float64)
    for lv in set(group_level):
        gidx = [i for i, lev in enumerate(group_level) if lev == lv]
        if len(gidx) < 4:
            continue
        w = group_counts[gidx]
        vecs = group_vectors[gidx]
        centroid = (vecs * w[:, None]).sum(axis=0) / w.sum()
        cn = np.linalg.norm(centroid)
        if cn == 0:
            continue
        centroid = centroid / cn
        dist = 1.0 - vecs @ centroid
        mean = float(np.average(dist, weights=w))
        var = float(np.average((dist - mean) ** 2, weights=w))
        std = math.sqrt(var)
        cut = mean + 2.0 * std
        for j, gi in enumerate(gidx):
            if dist[j] > cut and dist[j] > 0.05:
                group_outlier[gi] = True
                group_outlier_z[gi] = (dist[j] - mean) / std if std > 1e-9 else 10.0
                group_outlier_dist[gi] = float(dist[j])
    return group_outlier, group_outlier_z, group_outlier_dist


def _score_entries(
    entries: Sequence[LogEntry], sig: _Signals, cfg: DetectorConfig
) -> tuple[np.ndarray, list[list[str]]]:
    n = sig.n
    registry = sig.registry
    levels = sig.levels
    level_totals = sig.level_totals
    group_labels = sig.group_labels
    cluster_sizes = sig.cluster_sizes
    group_outlier = sig.group_outlier
    group_outlier_z = sig.group_outlier_z
    group_outlier_dist = sig.group_outlier_dist
    group_chronic = sig.group_chronic
    group_span = sig.group_span
    group_history = sig.group_history
    burst_mask = sig.burst_mask
    group_flood = sig.group_flood
    group_recurring = sig.group_recurring
    group_global_rare = sig.group_global_rare
    group_novel = sig.group_novel
    group_surge = sig.group_surge

    scores = np.zeros(n, dtype=np.float64)
    reasons: list[list[str]] = [[] for _ in range(n)]
    conf = volume_confidence(n, cfg.rarity_confidence_k)

    for i, e in enumerate(entries):
        gi = registry.entry_group[i]
        g = registry.groups[gi]
        gl = int(group_labels[gi])
        level_total = level_totals.get(levels[i], 1)
        sig_i = Signals(
            level=e.level,
            message=e.message,
            template_count=g.count,
            level_total=level_total,
            file_total=n,
            has_clusters=True,
            cluster_label=gl,
            cluster_size=cluster_sizes.get(gl, 0.0) if gl != -1 else 0.0,
            rare_min=cfg.rare_min,
            rare_pct=cfg.rare_pct,
            safe_rarity_damp=cfg.safe_rarity_damp,
            is_outlier=bool(group_outlier[gi]),
            outlier_z=float(group_outlier_z[gi]),
            outlier_dist=float(group_outlier_dist[gi]),
            burst=bool(burst_mask[i]),
            burst_factor=cfg.burst_factor,
            burst_window=cfg.burst_window,
            is_flood=bool(group_flood[gi]),
            is_recurring=bool(group_recurring[gi]),
            is_global_rare=bool(group_global_rare[gi]),
            group_span=float(group_span[gi]),
            is_novel=bool(group_novel[gi]),
            is_surge=bool(group_surge[gi]),
            chronic=bool(group_chronic[gi]),
            history_routine=float(group_history[gi]),
            confidence=conf,
        )
        result = policy_score(sig_i)
        scores[i] = result.score
        reasons[i] = result.reason_texts
    return scores, reasons


def _build_groups(
    registry: TemplateRegistry,
    entries: Sequence[LogEntry],
    scores: np.ndarray,
    reasons: list[list[str]],
    flagged: np.ndarray,
) -> list[AnomalyGroup]:
    """Collapse flagged entries into per-template anomaly groups, worst first."""
    groups: list[AnomalyGroup] = []
    for g in registry.groups:
        fidx = [i for i in g.indices if flagged[i]]
        if not fidx:
            continue
        merged: list[str] = []
        for i in fidx:
            for r in reasons[i]:
                if r not in merged:
                    merged.append(r)
        groups.append(
            AnomalyGroup(
                level=g.level,
                template=g.template,
                representative=entries[fidx[0]],
                count=len(fidx),
                score=float(max(scores[i] for i in fidx)),
                reasons=merged,
                services=sorted({entries[i].service for i in fidx})[:5],
                entry_indices=fidx,
            )
        )
    groups.sort(key=lambda a: (-a.score, get_severity(a.level), -a.count))
    return groups


def _build_patterns(
    registry: TemplateRegistry,
    entries: Sequence[LogEntry],
    group_sev: np.ndarray,
    flagged: np.ndarray,
    n: int,
    cfg: DetectorConfig,
) -> list[PatternInfo]:
    """Summarize the dominant WARN+ templates (flagged or not) for reporting."""
    patterns: list[PatternInfo] = []
    for gi, g in enumerate(registry.groups):
        if group_sev[gi] <= 4 and g.count >= cfg.pattern_min:
            patterns.append(
                PatternInfo(
                    level=g.level,
                    template=g.template,
                    representative=g.representative,
                    count=g.count,
                    share=g.count / n,
                    services=sorted({entries[i].service for i in g.indices})[:5],
                    flagged=bool(any(flagged[i] for i in g.indices)),
                )
            )
    patterns.sort(key=lambda p: (get_severity(p.level), -p.count))
    return patterns[: cfg.max_patterns]


def detect(
    entries: Sequence[LogEntry],
    embeddings: np.ndarray,
    cfg: DetectorConfig | None = None,
    baseline: dict | None = None,
) -> DetectionResult:
    cfg = cfg or DetectorConfig()
    n = len(entries)
    if n == 0:
        return DetectionResult(
            entries, np.zeros(0), np.zeros(0, bool), [], np.zeros(0, int), [], [], False, "", {}
        )

    vectors = normalize(np.asarray(embeddings, dtype=np.float32), norm="l2")

    registry = TemplateRegistry(entries)
    n_groups = len(registry)
    group_vectors, group_counts, group_labels, cluster_sizes, eps = _cluster_templates(
        vectors, registry, cfg
    )

    severities = np.array([get_severity(e.level) for e in entries])
    levels = np.array([e.level.upper() for e in entries])
    level_totals: dict[str, int] = {}
    for lv in levels:
        level_totals[lv] = level_totals.get(lv, 0) + 1

    group_level = [g.level for g in registry.groups]
    group_sev = np.array([get_severity(lv) for lv in group_level])

    group_outlier, group_outlier_z, group_outlier_dist = _level_outliers(
        group_level, group_counts, group_vectors, n_groups
    )

    if cfg.enable_burst:
        burst_mask, burst_note = detect_bursts(entries, cfg)
    else:
        burst_mask, burst_note = np.zeros(n, dtype=bool), "burst detection disabled"

    severe_entries = int((severities <= 3).sum())  # ERROR and worse
    severe_share = severe_entries / n
    incident_mode = severe_share >= cfg.incident_share
    incident_note = ""
    if incident_mode:
        incident_note = (
            f"{severe_share:.0%} of entries are ERROR or worse "
            f"— corpus looks like an incident window"
        )

    group_flood = np.zeros(n_groups, dtype=bool)
    for gi, g in enumerate(registry.groups):
        if group_sev[gi] <= 4 and g.count / n >= cfg.flood_share:
            group_flood[gi] = True

    recurring_cut = max(cfg.recurring_min, int(n * cfg.recurring_share))
    group_recurring = np.zeros(n_groups, dtype=bool)
    group_span = np.zeros(n_groups, dtype=np.float64)
    group_history = np.zeros(n_groups, dtype=np.float64)  # head presence
    head_cut = int(n * HISTORY_HEAD)
    for gi, g in enumerate(registry.groups):
        if g.count > 1:
            group_span[gi] = (g.indices[-1] - g.indices[0]) / max(n - 1, 1)
        group_history[gi] = sum(1 for i in g.indices if i < head_cut) / g.count

    baseline_templates: dict[str, int] = {}
    baseline_total = 0
    if baseline:
        baseline_templates = baseline.get("templates", {}) or {}
        baseline_total = int(baseline.get("total", 0) or 0)
    group_novel = np.zeros(n_groups, dtype=bool)
    group_surge = np.zeros(n_groups, dtype=bool)
    if baseline_templates:
        for gi, g in enumerate(registry.groups):
            base_count = baseline_templates.get(f"{g.level.upper()}|{g.template}", 0)
            if base_count == 0:
                group_novel[gi] = True
            elif baseline_total > 0:
                base_rate = base_count / baseline_total
                now_rate = g.count / n
                if now_rate > 10 * base_rate and g.count >= cfg.rare_min:
                    group_surge[gi] = True

    for gi, g in enumerate(registry.groups):
        if group_sev[gi] > 4 or g.count < recurring_cut:
            continue  # WARN and worse, only recurring
        if baseline_templates:
            base_count = baseline_templates.get(f"{g.level.upper()}|{g.template}", 0)
            if base_count > 0 and not group_surge[gi]:
                continue  # known chronic noise: stay quiet
        group_recurring[gi] = True

    group_chronic = np.zeros(n_groups, dtype=bool)
    group_global_rare = np.zeros(n_groups, dtype=bool)
    for gi, g in enumerate(registry.groups):
        if g.count / n <= GLOBAL_RARE_SHARE:
            group_global_rare[gi] = True
        if group_sev[gi] > 4 or group_sev[gi] <= 1:
            continue
        if not (g.count / n >= CHRONIC_SHARE or g.count >= CHRONIC_MIN_COUNT):
            continue
        span = (g.indices[-1] - g.indices[0]) / max(n - 1, 1)
        if span < CHRONIC_SPREAD:
            continue
        if bool(burst_mask[g.indices].any()):
            continue
        group_chronic[gi] = True

    sig = _Signals(
        n=n,
        registry=registry,
        severities=severities,
        levels=levels,
        level_totals=level_totals,
        group_labels=group_labels,
        cluster_sizes=cluster_sizes,
        group_outlier=group_outlier,
        group_outlier_z=group_outlier_z,
        group_outlier_dist=group_outlier_dist,
        group_chronic=group_chronic,
        group_span=group_span,
        group_history=group_history,
        burst_mask=burst_mask,
        group_flood=group_flood,
        group_recurring=group_recurring,
        group_global_rare=group_global_rare,
        group_novel=group_novel,
        group_surge=group_surge,
    )
    scores, reasons = _score_entries(entries, sig, cfg)

    # P3.C: fuse in the session-sequence detector. It scores entries whose
    # session takes an unlikely turn (order anomalies line rarity can't see) and
    # is silent when the corpus isn't session-structured.
    seq_note = ""
    if cfg.enable_sequence:
        seq_scores, seq_reasons, seq_note = sequence_anomaly_scores(
            entries, flag_at=cfg.flag_threshold
        )
        for i in range(n):
            if seq_scores[i] > scores[i]:
                scores[i] = seq_scores[i]
            if seq_reasons[i]:
                reasons[i] = list(reasons[i]) + seq_reasons[i]

    # P3.D: fuse in the parameter-outlier detector — a normal template carrying an
    # abnormal numeric value (latency spike, odd status code) that rarity can't see.
    param_note = ""
    if cfg.enable_parameters:
        par_scores, par_reasons, param_note = parameter_anomaly_scores(
            entries, flag_at=cfg.flag_threshold
        )
        for i in range(n):
            if par_scores[i] > scores[i]:
                scores[i] = par_scores[i]
            if par_reasons[i]:
                reasons[i] = list(reasons[i]) + par_reasons[i]

    rate_note = ""
    if cfg.enable_rate:
        rate_scores, rate_reasons, rate_note = rate_burst_scores(
            entries, flag_at=cfg.flag_threshold
        )
        for i in range(n):
            if rate_scores[i] > scores[i]:
                scores[i] = rate_scores[i]
            if rate_reasons[i]:
                reasons[i] = list(reasons[i]) + rate_reasons[i]

    cooc_note = ""
    if cfg.enable_cooccurrence:
        scores, cooc_reasons, cooc_note = cooccurrence_boost(
            entries, scores, flag_at=cfg.flag_threshold
        )
        for i in range(n):
            if cooc_reasons[i]:
                reasons[i] = list(reasons[i]) + cooc_reasons[i]

    floor_note = ""
    if cfg.enable_safety_floor:
        scores, floor_reasons, floor_note = safety_floor(
            entries, scores, flag_at=cfg.flag_threshold
        )
        for i in range(n):
            if floor_reasons[i]:
                reasons[i] = list(reasons[i]) + floor_reasons[i]

    threshold = cfg.flag_threshold
    if cfg.auto_threshold:
        auto = otsu_threshold(scores)
        if auto is not None:
            threshold = auto
    flagged = scores >= threshold

    for i, e in enumerate(entries):
        e.anomaly_score = float(scores[i])
        e.anomaly_reasons = reasons[i]

    groups = _build_groups(registry, entries, scores, reasons, flagged)
    patterns = _build_patterns(registry, entries, group_sev, flagged, n, cfg)

    entry_labels = np.array([group_labels[registry.entry_group[i]] for i in range(n)])

    meta: dict[str, object] = {
        "eps": eps,
        "unique_templates": n_groups,
        "severe_share": severe_share,
        "flag_threshold": cfg.flag_threshold,
        "threshold_used": float(threshold),
        "auto_threshold": cfg.auto_threshold,
        "chronic_templates": int(group_chronic.sum()),
        "global_rare_templates": int(group_global_rare.sum()),
    }
    if burst_note:
        meta["burst_note"] = burst_note
    if seq_note:
        meta["sequence_note"] = seq_note
    if param_note:
        meta["parameter_note"] = param_note
    if rate_note:
        meta["rate_note"] = rate_note
    if cooc_note:
        meta["cooccurrence_note"] = cooc_note
    if floor_note:
        meta["safety_floor_note"] = floor_note

    return DetectionResult(
        entries=entries,
        scores=scores,
        flagged=flagged,
        reasons=reasons,
        labels=entry_labels,
        groups=groups,
        patterns=patterns,
        incident_mode=incident_mode,
        incident_note=incident_note,
        meta=meta,
    )


def detect_anomalies(
    entries: list[LogEntry],
    embeddings: np.ndarray,
    eps: float | None = None,
    min_samples: int = 4,
    config: DetectorConfig | None = None,
    baseline: dict | None = None,
) -> tuple[list[LogEntry], list[LogEntry], np.ndarray]:
    cfg = config or DetectorConfig()
    if eps is not None:
        cfg.eps = eps
    cfg.min_samples = min_samples
    result = detect(entries, embeddings, cfg, baseline=baseline)
    return result.normal, result.anomalies, result.labels


def cluster_summary(labels: np.ndarray, flagged: np.ndarray = None) -> dict:
    unique = set(np.asarray(labels).tolist())
    n_clusters = len(unique - {-1})
    n_noise = int(np.sum(np.asarray(labels) == -1))
    n_anomalies = int(flagged.sum()) if flagged is not None else n_noise
    return {"clusters": n_clusters, "noise_points": n_noise, "anomalies": n_anomalies}
