from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import normalize

from loglens.models import LogEntry
from loglens.pipeline.templates import TemplateRegistry, parse_timestamp

LEVEL_SEVERITY: Dict[str, int] = {
    "EMERGENCY": 0,
    "EMERG":     0,
    "PANIC":     0,
    "ALERT":     1,
    "FATAL":     1,
    "CRITICAL":  2,
    "CRIT":      2,
    "ERROR":     3,
    "ERR":       3,
    "WARN":      4,
    "WARNING":   4,
    "NOTICE":    5,
    "INFO":      6,
    "DEBUG":     7,
    "TRACE":     7,
}
DEFAULT_SEVERITY = 6
HARD_FLAG_SEVERITY = 1

SEVERITY_BASE: Dict[int, float] = {
    0: 1.0, 1: 1.0,           # hard-flagged anyway
    2: 0.70,                  # CRITICAL
    3: 0.55,                  # ERROR  (graded down: routine errors are common)
    4: 0.42,                  # WARN
    5: 0.08,                  # NOTICE
    6: 0.0,                   # INFO
    7: 0.0,                   # DEBUG/TRACE
}


CHRONIC_SHARE = 0.15          
CHRONIC_MIN_COUNT = 25        
CHRONIC_SPREAD = 0.50         
CHRONIC_DAMP = 0.45      

GLOBAL_RARE_SHARE = 0.005     
GLOBAL_RARE_BONUS = 0.18
OUTLIER_Z_EXEMPT = 4.0
OUTLIER_DIST_FLOOR = 0.08

SOFTCAP_START = 0.80
SOFTCAP_TAU = 0.60


HISTORY_HEAD = 0.25          
HISTORY_MIN_COUNT = 5         
HISTORY_MIN_SPAN = 0.40       
HISTORY_MAX_DAMP = 0.45       


def volume_confidence(n: int, k: float) -> float:
    if k <= 0:
        return 1.0
    return n / (n + k)


def soft_cap(raw: float) -> float:
    if raw <= SOFTCAP_START:
        return max(0.0, raw)
    return SOFTCAP_START + (1.0 - SOFTCAP_START) * (
        1.0 - math.exp(-(raw - SOFTCAP_START) / SOFTCAP_TAU))


CATASTROPHE_PATTERNS = [
    r"kernel panic", r"\bpanic\b", r"segfault", r"sigsegv",
    r"data loss", r"\bcorrupt\w*", r"split[- ]brain", r"power failure",
    r"cascading failure", r"unrecoverable", r"security breach",
    r"\bhalted\b", r"double fault", r"filesystem read-?only",
]
_CATASTROPHE_RE = re.compile("|".join(CATASTROPHE_PATTERNS), re.IGNORECASE)

FAILURE_PATTERNS = [
    r"fail(?:ed|ure|ing)?\b", r"error", r"exception", r"timed?[ _-]?out",
    r"exhaust(?:ed|ion)", r"declin(?:ed|e)\b", r"denied", r"refus(?:ed|al)",
    r"reject(?:ed|ion)", r"crash(?:ed|ing)?", r"abort(?:ed|ing)?",
    r"out[ _-]?of[ _-]?memory", r"\boom\b", r"unreachable", r"unavailable",
    r"dead[ -]?lock", r"\bcannot\b", r"\bcan't\b", r"could not",
    r"unable to", r"no space left", r"enospc", r"\bexpired\b", r"\blost\b",
    r"too many", r"\bdown\b", r"not responding",
]
_FAILURE_RE = re.compile("|".join(FAILURE_PATTERNS), re.IGNORECASE)


def get_severity(level: str) -> int:
    return LEVEL_SEVERITY.get(level.upper(), DEFAULT_SEVERITY)


def otsu_threshold(scores: np.ndarray,
                   lo: float = 0.35, hi: float = 0.95,
                   bins: int = 64) -> Optional[float]:
    s = np.asarray(scores, dtype=np.float64)
    s = s[(s > 0.0) & (s < 1.0)]          # 0/1 are already hard-decided
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
    eps: Optional[float] = None
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

    @classmethod
    def from_sensitivity(cls, sensitivity: str = "normal", **overrides) -> "DetectorConfig":
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
    reasons: List[str]
    services: List[str]
    entry_indices: List[int]


@dataclass
class PatternInfo:
    level: str
    template: str
    representative: LogEntry
    count: int
    share: float
    services: List[str]
    flagged: bool


@dataclass
class DetectionResult:
    entries: Sequence[LogEntry]
    scores: np.ndarray
    flagged: np.ndarray
    reasons: List[List[str]]
    labels: np.ndarray
    groups: List[AnomalyGroup]
    patterns: List[PatternInfo]
    incident_mode: bool
    incident_note: str
    meta: Dict[str, object] = field(default_factory=dict)

    @property
    def anomalies(self) -> List[LogEntry]:
        idx = np.argsort(-self.scores, kind="stable")
        return [self.entries[i] for i in idx if self.flagged[i]]

    @property
    def normal(self) -> List[LogEntry]:
        return [e for e, f in zip(self.entries, self.flagged) if not f]

    def summary(self) -> Dict[str, object]:
        n_clusters = len(set(self.labels.tolist()) - {-1})
        return {
            "entries": len(self.entries),
            "clusters": n_clusters,
            "anomalies": int(self.flagged.sum()),
            "anomaly_groups": len(self.groups),
            "patterns": len(self.patterns),
            "incident_mode": self.incident_mode,
        }


def estimate_eps(vectors: np.ndarray, k: int = 4,
                 lo: float = 0.15, hi: float = 0.90) -> float:
    n = len(vectors)
    if n <= k + 1:
        return 0.5
    sample = vectors
    if n > 5000:
        rng = np.random.default_rng(0)
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


def detect_bursts(entries: Sequence[LogEntry], cfg: DetectorConfig
                  ) -> Tuple[np.ndarray, str]:
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
        if sev_level > 4:              # only WARN and worse can "burst"
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


def detect(entries: Sequence[LogEntry],
           embeddings: np.ndarray,
           cfg: Optional[DetectorConfig] = None,
           baseline: Optional[dict] = None) -> DetectionResult:
    cfg = cfg or DetectorConfig()
    n = len(entries)
    if n == 0:
        return DetectionResult(entries, np.zeros(0), np.zeros(0, bool), [],
                               np.zeros(0, int), [], [], False, "", {})

    vectors = normalize(np.asarray(embeddings, dtype=np.float32), norm="l2")

    registry = TemplateRegistry(entries)
    n_groups = len(registry)
    group_counts = np.array(registry.counts, dtype=np.float64)
    group_vectors = np.zeros((n_groups, vectors.shape[1]), dtype=np.float32)
    for gi, g in enumerate(registry.groups):
        group_vectors[gi] = vectors[g.indices].mean(axis=0)
    group_vectors = normalize(group_vectors, norm="l2")

    eps = cfg.eps if cfg.eps is not None else estimate_eps(
        group_vectors, k=cfg.min_samples)
    db = DBSCAN(eps=eps, min_samples=cfg.min_samples, metric="euclidean",
                n_jobs=-1)
    group_labels = db.fit_predict(group_vectors, sample_weight=group_counts)

    # weighted cluster sizes (in ENTRIES, not templates)
    cluster_sizes: Dict[int, float] = {}
    for gl, c in zip(group_labels, group_counts):
        cluster_sizes[int(gl)] = cluster_sizes.get(int(gl), 0.0) + c

    severities = np.array([get_severity(e.level) for e in entries])
    levels = np.array([e.level.upper() for e in entries])
    level_totals: Dict[str, int] = {}
    for lv in levels:
        level_totals[lv] = level_totals.get(lv, 0) + 1

    group_level = [g.level for g in registry.groups]
    group_sev = np.array([get_severity(lv) for lv in group_level])

    group_outlier = np.zeros(n_groups, dtype=bool)
    group_outlier_z = np.zeros(n_groups, dtype=np.float64)
    group_outlier_dist = np.zeros(n_groups, dtype=np.float64)
    for lv in set(group_level):
        gidx = [i for i, l in enumerate(group_level) if l == lv]
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
                group_outlier_z[gi] = ((dist[j] - mean) / std
                                       if std > 1e-9 else 10.0)
                group_outlier_dist[gi] = float(dist[j])

    if cfg.enable_burst:
        burst_mask, burst_note = detect_bursts(entries, cfg)
    else:
        burst_mask, burst_note = np.zeros(n, dtype=bool), "burst detection disabled"

    severe_entries = int((severities <= 3).sum())          # ERROR and worse
    severe_share = severe_entries / n
    incident_mode = severe_share >= cfg.incident_share
    incident_note = ""
    if incident_mode:
        incident_note = (f"{severe_share:.0%} of entries are ERROR or worse "
                         f"— corpus looks like an incident window")

    group_flood = np.zeros(n_groups, dtype=bool)
    for gi, g in enumerate(registry.groups):
        if group_sev[gi] <= 4 and g.count / n >= cfg.flood_share:
            group_flood[gi] = True

    recurring_cut = max(cfg.recurring_min, int(n * cfg.recurring_share))
    group_recurring = np.zeros(n_groups, dtype=bool)
    group_span = np.zeros(n_groups, dtype=np.float64)
    group_history = np.zeros(n_groups, dtype=np.float64)   # head presence
    head_cut = int(n * HISTORY_HEAD)
    for gi, g in enumerate(registry.groups):
        if g.count > 1:
            group_span[gi] = (g.indices[-1] - g.indices[0]) / max(n - 1, 1)
        group_history[gi] = sum(1 for i in g.indices if i < head_cut) / g.count

    baseline_templates: Dict[str, int] = {}
    baseline_total = 0
    if baseline:
        baseline_templates = baseline.get("templates", {}) or {}
        baseline_total = int(baseline.get("total", 0) or 0)
    group_novel = np.zeros(n_groups, dtype=bool)
    group_surge = np.zeros(n_groups, dtype=bool)
    if baseline_templates:
        for gi, g in enumerate(registry.groups):
            base_count = baseline_templates.get(
                f"{g.level.upper()}|{g.template}", 0)
            if base_count == 0:
                group_novel[gi] = True
            elif baseline_total > 0:
                base_rate = base_count / baseline_total
                now_rate = g.count / n
                if now_rate > 10 * base_rate and g.count >= cfg.rare_min:
                    group_surge[gi] = True

    for gi, g in enumerate(registry.groups):
        if group_sev[gi] > 4 or g.count < recurring_cut:
            continue                    # WARN and worse, only recurring
        if baseline_templates:
            base_count = baseline_templates.get(
                f"{g.level.upper()}|{g.template}", 0)
            if base_count > 0 and not group_surge[gi]:
                continue                # known chronic noise: stay quiet
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

    scores = np.zeros(n, dtype=np.float64)
    reasons: List[List[str]] = [[] for _ in range(n)]

    conf = volume_confidence(n, cfg.rarity_confidence_k)

    for i, e in enumerate(entries):
        sev = int(severities[i])
        gi = registry.entry_group[i]
        g = registry.groups[gi]
        gl = int(group_labels[gi])
        entry_reasons: List[str] = []

        chronic = bool(group_chronic[gi])
        if sev <= HARD_FLAG_SEVERITY:
            score = 1.0
            entry_reasons.append(f"{e.level.upper()} level is always flagged")
        else:
            score = SEVERITY_BASE.get(sev, 0.15)
            if chronic:
                score *= CHRONIC_DAMP    # routine, high-volume severe pattern
            if (3 <= sev <= 4 and g.count >= HISTORY_MIN_COUNT
                    and group_span[gi] >= HISTORY_MIN_SPAN):
                hp = group_history[gi]
                routine = min(1.0, max(0.0, (hp - HISTORY_HEAD)
                                       / (1.0 - HISTORY_HEAD)))
                if routine > 0:
                    score *= (1.0 - HISTORY_MAX_DAMP * routine)
                    entry_reasons.append(
                        f"routine by own history "
                        f"({hp:.0%} of occurrences in leading window)")
            if score > 0:
                entry_reasons.append(f"severity {e.level.upper()}")

        level_total = level_totals.get(levels[i], 1)
        dyn_threshold = max(cfg.rare_min, int(level_total * cfg.rare_pct))
        rarity = 0.0
        if gl == -1:
            rarity = 0.75
            entry_reasons.append("unclustered (semantic noise point)")
        else:
            csize = cluster_sizes.get(gl, 0.0)
            if csize <= dyn_threshold:
                rarity = 0.45 + 0.30 * (1.0 - csize / (dyn_threshold + 1.0))
                entry_reasons.append(
                    f"rare pattern ({int(csize)} of {level_total} "
                    f"{levels[i]} entries)")
        if group_outlier[gi]:
            z = group_outlier_z[gi]
            rarity = max(rarity, min(0.35 + 0.10 * max(0.0, z - 2.0), 0.75))
            entry_reasons.append(
                f"semantic outlier within {levels[i]} level (z={z:.1f})")
        if g.count <= max(2, int(0.005 * level_total)):
            rarity = max(rarity, 0.40)
            if not any("rare" in r for r in entry_reasons):
                entry_reasons.append(f"template seen only {g.count}x")
        _extreme_outlier = (group_outlier[gi]
                            and group_outlier_z[gi] >= OUTLIER_Z_EXEMPT
                            and group_outlier_dist[gi] > OUTLIER_DIST_FLOOR)
        if sev >= 5 and gl != -1 and not _extreme_outlier:
            rarity *= cfg.safe_rarity_damp
        if chronic:
            rarity *= CHRONIC_DAMP
            if not any("chronic" in r for r in entry_reasons):
                entry_reasons.append(
                    f"chronic pattern ({g.count}x) — damped as routine noise")
        rarity *= conf          # thin-sample rarity is unreliable; damp it
        score += rarity

        if group_global_rare[gi] and sev <= 4 and not chronic:
            score += GLOBAL_RARE_BONUS * conf
            entry_reasons.append(
                f"globally rare ({g.count/n:.2%} of file)")

        if burst_mask[i]:
            score += 0.50
            entry_reasons.append(
                f"rate burst (> {cfg.burst_factor:g}x baseline "
                f"in {cfg.burst_window:g}s window)")

        if group_flood[gi]:
            score += 0.35 + 0.25 * min(1.0, g.count / n)
            entry_reasons.append(
                f"flood: pattern is {g.count / n:.0%} of the whole file")

        if group_recurring[gi] and not chronic:
            conc = (g.count / (g.count + 8.0)) * (1.0 - group_span[gi])
            score += 0.02 + 0.25 * conc
            entry_reasons.append(
                f"recurring {e.level.upper()} pattern "
                f"({g.count}x, concentration {conc:.2f})")

        if sev <= 4 and not chronic and _CATASTROPHE_RE.search(e.message):
            score += 0.20
            entry_reasons.append("catastrophic keyword")

        if sev <= 4 and not chronic and _FAILURE_RE.search(e.message):
            score += 0.22
            entry_reasons.append("failure keyword in severe entry")

        if group_novel[gi] and sev <= 4:
            score += 0.35
            entry_reasons.append("never seen in baseline")
        elif group_surge[gi] and sev <= 4:
            score += 0.30
            entry_reasons.append("frequency surge vs baseline (>10x)")

        scores[i] = soft_cap(score)
        reasons[i] = entry_reasons

    threshold = cfg.flag_threshold
    if cfg.auto_threshold:
        auto = otsu_threshold(scores)
        if auto is not None:
            threshold = auto
    flagged = scores >= threshold

    for i, e in enumerate(entries):
        e.anomaly_score = float(scores[i])
        e.anomaly_reasons = reasons[i]

    groups: List[AnomalyGroup] = []
    for gi, g in enumerate(registry.groups):
        fidx = [i for i in g.indices if flagged[i]]
        if not fidx:
            continue
        merged: List[str] = []
        for i in fidx:
            for r in reasons[i]:
                if r not in merged:
                    merged.append(r)
        groups.append(AnomalyGroup(
            level=g.level,
            template=g.template,
            representative=entries[fidx[0]],
            count=len(fidx),
            score=float(max(scores[i] for i in fidx)),
            reasons=merged,
            services=sorted({entries[i].service for i in fidx})[:5],
            entry_indices=fidx,
        ))
    groups.sort(key=lambda a: (-a.score, get_severity(a.level), -a.count))

    patterns: List[PatternInfo] = []
    for gi, g in enumerate(registry.groups):
        if group_sev[gi] <= 4 and g.count >= cfg.pattern_min:
            patterns.append(PatternInfo(
                level=g.level,
                template=g.template,
                representative=g.representative,
                count=g.count,
                share=g.count / n,
                services=sorted({entries[i].service for i in g.indices})[:5],
                flagged=bool(any(flagged[i] for i in g.indices)),
            ))
    patterns.sort(key=lambda p: (get_severity(p.level), -p.count))
    patterns = patterns[:cfg.max_patterns]

    entry_labels = np.array([group_labels[registry.entry_group[i]]
                             for i in range(n)])

    meta = {
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

    return DetectionResult(
        entries=entries, scores=scores, flagged=flagged, reasons=reasons,
        labels=entry_labels, groups=groups, patterns=patterns,
        incident_mode=incident_mode, incident_note=incident_note, meta=meta,
    )


def detect_anomalies(entries: List[LogEntry],
                     embeddings: np.ndarray,
                     eps: Optional[float] = None,
                     min_samples: int = 4,
                     config: Optional[DetectorConfig] = None,
                     baseline: Optional[dict] = None,
                     ) -> Tuple[List[LogEntry], List[LogEntry], np.ndarray]:
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