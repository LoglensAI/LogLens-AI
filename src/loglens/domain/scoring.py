from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from loglens.domain.severity import HARD_FLAG_SEVERITY, SEVERITY_BASE, get_severity

CHRONIC_DAMP = 0.45
GLOBAL_RARE_BONUS = 0.18
OUTLIER_Z_EXEMPT = 4.0
OUTLIER_DIST_FLOOR = 0.08

SOFTCAP_START = 0.80
SOFTCAP_TAU = 0.60

HISTORY_HEAD = 0.25
HISTORY_MIN_COUNT = 5
HISTORY_MIN_SPAN = 0.40
HISTORY_MAX_DAMP = 0.45

THRESHOLDS: dict[str, float] = {"low": 0.80, "normal": 0.70, "high": 0.60}
DEFAULT_THRESHOLD = 0.70


def threshold_for(sensitivity: str) -> float:
    return THRESHOLDS.get(sensitivity, DEFAULT_THRESHOLD)


def volume_confidence(n: int, k: float) -> float:
    if k <= 0:
        return 1.0
    return n / (n + k)


def soft_cap(raw: float) -> float:
    if raw <= SOFTCAP_START:
        return max(0.0, raw)
    return SOFTCAP_START + (1.0 - SOFTCAP_START) * (
        1.0 - math.exp(-(raw - SOFTCAP_START) / SOFTCAP_TAU)
    )


CATASTROPHE_PATTERNS = [
    r"kernel panic",
    r"\bpanic\b",
    r"segfault",
    r"sigsegv",
    r"data loss",
    r"\bcorrupt\w*",
    r"split[- ]brain",
    r"power failure",
    r"cascading failure",
    r"unrecoverable",
    r"security breach",
    r"\bhalted\b",
    r"double fault",
    r"filesystem read-?only",
]
_CATASTROPHE_RE = re.compile("|".join(CATASTROPHE_PATTERNS), re.IGNORECASE)

FAILURE_PATTERNS = [
    r"fail(?:ed|ure|ing)?\b",
    r"error",
    r"exception",
    r"timed?[ _-]?out",
    r"exhaust(?:ed|ion)",
    r"declin(?:ed|e)\b",
    r"denied",
    r"refus(?:ed|al)",
    r"reject(?:ed|ion)",
    r"crash(?:ed|ing)?",
    r"abort(?:ed|ing)?",
    r"out[ _-]?of[ _-]?memory",
    r"\boom\b",
    r"unreachable",
    r"unavailable",
    r"dead[ -]?lock",
    r"\bcannot\b",
    r"\bcan't\b",
    r"could not",
    r"unable to",
    r"no space left",
    r"enospc",
    r"\bexpired\b",
    r"\blost\b",
    r"too many",
    r"\bdown\b",
    r"not responding",
]
_FAILURE_RE = re.compile("|".join(FAILURE_PATTERNS), re.IGNORECASE)


def has_catastrophe(message: str) -> bool:
    return bool(_CATASTROPHE_RE.search(message))


def has_failure(message: str) -> bool:
    return bool(_FAILURE_RE.search(message))


@dataclass(frozen=True)
class Reason:
    code: str
    text: str
    weight: float = 0.0

    def __str__(self) -> str:
        return self.text


REASON_CODES = (
    "hard_flag",
    "severity",
    "routine_history",
    "unclustered",
    "rare",
    "semantic_outlier",
    "rare_template",
    "chronic",
    "global_rare",
    "burst",
    "flood",
    "recurring",
    "catastrophe",
    "failure",
    "novel",
    "surge",
)


@dataclass
class Signals:
    level: str
    message: str = ""

    template_count: int = 1
    level_total: int = 1
    file_total: int = 1

    has_clusters: bool = False  # True when DBSCAN clustering was run (classic/deep)
    cluster_label: int = 0  # -1 == unclustered noise point
    cluster_size: float = 0.0
    rare_min: int = 3
    rare_pct: float = 0.01
    safe_rarity_damp: float = 1.0

    is_outlier: bool = False
    outlier_z: float = 0.0
    outlier_dist: float = 0.0

    burst: bool = False
    burst_factor: float = 3.0
    burst_window: float = 2.0

    is_flood: bool = False
    is_recurring: bool = False
    is_global_rare: bool = False
    group_span: float = 0.0

    is_novel: bool = False
    is_surge: bool = False

    chronic: bool = False
    history_routine: float = 0.0
    group_span_ok: bool = False

    confidence: float = 1.0

    @property
    def severity(self) -> int:
        return get_severity(self.level)


@dataclass
class ScoreResult:
    score: float
    reasons: list[Reason] = field(default_factory=list)

    @property
    def reason_texts(self) -> list[str]:
        return [r.text for r in self.reasons]

    @property
    def reason_codes(self) -> list[str]:
        return [r.code for r in self.reasons]


def score(sig: Signals) -> ScoreResult:
    sev = sig.severity
    level = sig.level.upper()
    reasons: list[Reason] = []

    base = SEVERITY_BASE.get(sev, 0.15)
    if sev <= HARD_FLAG_SEVERITY:
        total = base
        reasons.append(Reason("hard_flag", f"{level} level — always flagged", base))
    else:
        if sig.chronic:
            base *= CHRONIC_DAMP
        if (
            3 <= sev <= 4
            and sig.template_count >= HISTORY_MIN_COUNT
            and sig.group_span >= HISTORY_MIN_SPAN
        ):
            routine = min(
                1.0, max(0.0, (sig.history_routine - HISTORY_HEAD) / (1.0 - HISTORY_HEAD))
            )
            if routine > 0:
                base *= 1.0 - HISTORY_MAX_DAMP * routine
                reasons.append(
                    Reason(
                        "routine_history",
                        f"routine by own history ({sig.history_routine:.0%} of occurrences "
                        "in leading window)",
                        0.0,
                    )
                )
        total = base
        if base > 0:
            reasons.append(Reason("severity", f"severity {level}", base))

    dyn_threshold = max(sig.rare_min, int(sig.level_total * sig.rare_pct))
    rarity = 0.0
    if sig.has_clusters:
        if sig.cluster_label == -1:
            rarity = 0.75
            reasons.append(Reason("unclustered", "unclustered (semantic noise point)", 0.0))
        elif sig.cluster_size <= dyn_threshold:
            rarity = 0.45 + 0.30 * (1.0 - sig.cluster_size / (dyn_threshold + 1.0))
            reasons.append(
                Reason(
                    "rare",
                    f"rare pattern ({int(sig.cluster_size)} of {sig.level_total} {level} entries)",
                    0.0,
                )
            )
    elif sig.template_count <= dyn_threshold:
        rarity = 0.45 + 0.30 * (1.0 - sig.template_count / (dyn_threshold + 1.0))
        reasons.append(
            Reason(
                "rare",
                f"rare pattern ({sig.template_count} of {sig.level_total} {level} entries)",
                0.0,
            )
        )

    if sig.is_outlier:
        z = sig.outlier_z
        rarity = max(rarity, min(0.35 + 0.10 * max(0.0, z - 2.0), 0.75))
        reasons.append(
            Reason("semantic_outlier", f"semantic outlier within {level} level (z={z:.1f})", 0.0)
        )

    if sig.template_count <= max(2, int(0.005 * sig.level_total)):
        rarity = max(rarity, 0.40)
        if not any(r.code in ("rare", "unclustered") for r in reasons):
            reasons.append(
                Reason("rare_template", f"template seen only {sig.template_count}x", 0.0)
            )

    extreme_outlier = (
        sig.is_outlier
        and sig.outlier_z >= OUTLIER_Z_EXEMPT
        and sig.outlier_dist > OUTLIER_DIST_FLOOR
    )
    if sev >= 5 and not extreme_outlier:
        rarity *= sig.safe_rarity_damp
    if sig.chronic:
        rarity *= CHRONIC_DAMP
        if not any(r.code == "chronic" for r in reasons):
            reasons.append(
                Reason(
                    "chronic",
                    f"chronic pattern ({sig.template_count}x) — damped as routine noise",
                    0.0,
                )
            )
    rarity *= sig.confidence
    if rarity > 0:
        for idx, r in enumerate(reasons):
            if r.code in ("rare", "unclustered", "semantic_outlier", "rare_template"):
                reasons[idx] = Reason(r.code, r.text, round(rarity, 4))
                break
    total += rarity

    if sig.is_global_rare and sev <= 4 and not sig.chronic:
        w = GLOBAL_RARE_BONUS * sig.confidence
        total += w
        reasons.append(
            Reason(
                "global_rare",
                f"globally rare ({sig.template_count / sig.file_total:.2%} of file)",
                round(w, 4),
            )
        )

    if sig.burst:
        total += 0.50
        reasons.append(
            Reason(
                "burst",
                f"rate burst (> {sig.burst_factor:g}x baseline in {sig.burst_window:g}s window)",
                0.50,
            )
        )

    if sig.is_flood:
        w = 0.35 + 0.25 * min(1.0, sig.template_count / sig.file_total)
        total += w
        reasons.append(
            Reason(
                "flood",
                f"flood: pattern is {sig.template_count / sig.file_total:.0%} of the whole file",
                round(w, 4),
            )
        )

    if sig.is_recurring and not sig.chronic:
        conc = (sig.template_count / (sig.template_count + 8.0)) * (1.0 - sig.group_span)
        w = 0.02 + 0.25 * conc
        total += w
        reasons.append(
            Reason(
                "recurring",
                f"recurring {level} pattern ({sig.template_count}x, concentration {conc:.2f})",
                round(w, 4),
            )
        )

    if sev <= 4 and not sig.chronic and has_catastrophe(sig.message):
        total += 0.20
        reasons.append(Reason("catastrophe", "catastrophic keyword", 0.20))
    if sev <= 4 and not sig.chronic and has_failure(sig.message):
        total += 0.22
        reasons.append(Reason("failure", "failure keyword in severe entry", 0.22))

    if sig.is_novel and sev <= 4:
        total += 0.35
        reasons.append(Reason("novel", "never seen in baseline", 0.35))
    elif sig.is_surge and sev <= 4:
        total += 0.30
        reasons.append(Reason("surge", "frequency surge vs baseline (>10x)", 0.30))

    return ScoreResult(soft_cap(total), reasons)
