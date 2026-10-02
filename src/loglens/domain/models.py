from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class LogEntry:
    timestamp: str = ""
    level: str = "INFO"
    service: str = "unknown"
    message: str = ""
    raw: str = ""
    parsed: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    anomaly_score: float = 0.0
    anomaly_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "service": self.service,
            "message": self.message,
            "parsed": self.parsed,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class Anomaly:
    level: str
    score: float
    message: str
    service: str = "unknown"
    timestamp: str = ""
    reasons: list[str] = field(default_factory=list)
    raw: str = ""
    index: int | None = None
    entry: LogEntry | None = field(default=None, repr=False)

    def __str__(self) -> str:
        why = ("  [" + "; ".join(self.reasons) + "]") if self.reasons else ""
        svc = f" {self.service}" if self.service not in ("", "unknown") else ""
        return f"[{self.level}]{svc} (score {self.score:.2f}) {self.message}{why}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "score": round(self.score, 4),
            "message": self.message,
            "service": self.service,
            "timestamp": self.timestamp,
            "reasons": list(self.reasons),
            "index": self.index,
        }


def _to_anomaly(e: LogEntry, score: float, reasons, idx) -> Anomaly:
    return Anomaly(
        level=e.level,
        score=float(score),
        message=e.message,
        service=e.service,
        timestamp=e.timestamp,
        reasons=list(reasons),
        raw=e.raw,
        index=idx,
        entry=e,
    )
