from __future__ import annotations

from dataclasses import dataclass

_DAY = 86400.0


@dataclass
class ServiceBudget:
    service: str
    alerts: int  # flagged families attributed to this service
    measured_per_day: float | None  # extrapolated when the window < 1 day; None if unknown
    budget_per_day: float
    within_budget: bool
    suggested_cutoff: float | None  # score cutoff that would meet the budget (None if N/A)
    basis: str  # "measured" (>=1 day) | "extrapolated" (<1 day) | "unknown" (no window)


def _rate(n: int, window_seconds: float | None) -> tuple[float | None, str]:
    if not window_seconds or window_seconds <= 0:
        return None, "unknown"
    per_day = n / (window_seconds / _DAY)
    return per_day, ("measured" if window_seconds >= _DAY else "extrapolated")


def calibrate(
    alerts: list[tuple[str, float]],
    *,
    budget_per_day: float = 5.0,
    window_seconds: float | None = None,
) -> list[ServiceBudget]:

    by_service: dict[str, list[float]] = {}
    for service, score in alerts:
        by_service.setdefault(service or "unknown", []).append(float(score))

    out: list[ServiceBudget] = []
    for service in sorted(by_service):
        scores = sorted(by_service[service], reverse=True)
        n = len(scores)
        per_day, basis = _rate(n, window_seconds)
        within = per_day is None or per_day <= budget_per_day

        # how many alerts the budget allows over THIS window (>=1 so we never suggest
        # hiding everything), and the score that admits exactly that many.
        cutoff: float | None = None
        if window_seconds and per_day is not None and not within:
            window_budget = budget_per_day * (window_seconds / _DAY)
            k = max(1, round(window_budget))
            if n > k:
                cutoff = round(scores[k - 1], 4)  # the k-th highest score

        out.append(
            ServiceBudget(
                service=service,
                alerts=n,
                measured_per_day=(round(per_day, 1) if per_day is not None else None),
                budget_per_day=budget_per_day,
                within_budget=within,
                suggested_cutoff=cutoff,
                basis=basis,
            )
        )
    return out


def to_payload(budgets: list[ServiceBudget], budget_per_day: float) -> dict:
    return {
        "budget_per_day_per_service": budget_per_day,
        "wording": "calibrated budget (measured estimate, not a guarantee)",
        "by_service": [
            {
                "service": b.service,
                "alerts": b.alerts,
                "measured_per_day": b.measured_per_day,
                "within_budget": b.within_budget,
                "suggested_cutoff": b.suggested_cutoff,
                "basis": b.basis,
            }
            for b in budgets
        ],
        "over_budget_services": [b.service for b in budgets if not b.within_budget],
    }
