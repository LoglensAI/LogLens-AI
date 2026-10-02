from __future__ import annotations

from loglens.application.scheduler import (
    DeficitScheduler,
    detect_cores,
    effective_workers,
    plan_assignment,
)
from loglens.application.sources import SourceSpec


def test_detect_cores_positive():
    assert detect_cores() >= 1


def test_effective_workers_reserves_coordinator(monkeypatch):
    monkeypatch.setattr("loglens.application.scheduler.detect_cores", lambda: 8)
    # 8 cores, reserve 1 → up to 7, capped by source count
    assert effective_workers(100) == 7
    assert effective_workers(3) == 3


def test_effective_workers_single_core_is_serial(monkeypatch):
    monkeypatch.setattr("loglens.application.scheduler.detect_cores", lambda: 1)
    assert effective_workers(50) == 1


def test_effective_workers_honours_request(monkeypatch):
    monkeypatch.setattr("loglens.application.scheduler.detect_cores", lambda: 16)
    assert effective_workers(100, requested=4) == 4
    # request larger than budget is still capped by cores-1
    assert effective_workers(100, requested=1000) == 15


def test_assignment_covers_all_sources_once():
    specs = [SourceSpec(id=f"s{i}", path=f"/{i}.log") for i in range(10)]
    a = plan_assignment(specs, workers=4)
    seen = [sid for v in a.sources_by_worker.values() for sid in v]
    assert sorted(seen) == sorted(s.id for s in specs)
    assert len(seen) == len(set(seen))  # no source assigned twice


def test_assignment_is_deterministic():
    specs = [SourceSpec(id=f"s{i}", path=f"/{i}.log") for i in range(12)]
    a1 = plan_assignment(specs, workers=4)
    a2 = plan_assignment(specs, workers=4)
    assert a1.worker_of == a2.worker_of


def test_assignment_more_sources_than_workers_shares():
    specs = [SourceSpec(id=f"s{i}", path=f"/{i}.log") for i in range(9)]
    a = plan_assignment(specs, workers=3)
    assert a.shared is True
    # load is spread: no worker gets everything
    assert all(len(v) > 0 for v in a.sources_by_worker.values())


def test_deficit_scheduler_no_starvation():
    sch = DeficitScheduler(quantum=1.0)
    sch.add("firehose", weight=1.0)
    sch.add("trickle", weight=1.0)
    ready = {"firehose", "trickle"}
    picks = [sch.select(ready) for _ in range(100)]
    # Equal weights → both serviced roughly equally; neither starved.
    assert picks.count("firehose") > 30
    assert picks.count("trickle") > 30


def test_deficit_scheduler_respects_weight():
    sch = DeficitScheduler(quantum=1.0)
    sch.add("heavy", weight=3.0)
    sch.add("light", weight=1.0)
    ready = {"heavy", "light"}
    picks = [sch.select(ready) for _ in range(400)]
    # heavy has 3x the weight → serviced more, but light is NEVER starved.
    assert picks.count("heavy") > picks.count("light")
    assert picks.count("light") > 0


def test_deficit_scheduler_skips_not_ready():
    sch = DeficitScheduler()
    sch.add("a")
    sch.add("b")
    # only b is ready → every pick is b
    assert all(sch.select({"b"}) == "b" for _ in range(20))
    assert sch.select(set()) is None
