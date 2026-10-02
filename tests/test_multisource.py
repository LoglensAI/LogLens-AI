from __future__ import annotations

import os

from loglens.application.api import analyze
from loglens.application.multisource import analyze_sources, correlate
from loglens.application.sources import SourceSpec, parse_sources
from loglens.detection.run import RunConfig

_LOGS = ["error_burst.log", "rate_burst.log", "service_outage.log", "param_anomaly.log"]


def _log(name: str) -> str:
    return os.path.join("testlogs", name)


def test_per_source_identical_to_single_source():
    """The core accuracy proof: multi == single, byte-for-byte."""
    specs = [SourceSpec(id=n.split(".")[0], path=_log(n)) for n in _LOGS]
    multi = analyze_sources(specs, mode="fast", workers=1)

    by_id = {s["id"]: s for s in multi.per_source}
    for n in _LOGS:
        sid = n.split(".")[0]
        single = analyze(source=_log(n), config=RunConfig(mode="fast"))
        single_anoms = [a.to_dict() for a in single.anomalies]
        assert by_id[sid]["anomalies"] == single_anoms, f"{sid} diverged from single-source"
        assert by_id[sid]["lines_parsed"] == single.total
        assert by_id[sid]["format"] == single.format


def test_sources_are_isolated():
    """Analysing a noisy source alongside a quiet one must not change the quiet
    one's result (no shared baseline/registry)."""
    quiet_alone = analyze(source=_log("param_anomaly.log"), config=RunConfig(mode="fast"))
    specs = parse_sources([_log("error_burst.log"), _log("param_anomaly.log")])
    multi = analyze_sources(specs, mode="fast", workers=1)
    quiet = next(s for s in multi.per_source if s["id"] == "param_anomaly.log")
    assert quiet["anomalies"] == [a.to_dict() for a in quiet_alone.anomalies]


def test_deterministic_merge_order():
    specs = parse_sources([_log("service_outage.log"), _log("error_burst.log")])
    m1 = analyze_sources(specs, mode="fast", workers=1)
    m2 = analyze_sources(specs, mode="fast", workers=1)
    ids1 = [s["id"] for s in m1.per_source]
    assert ids1 == sorted(ids1)  # sorted by id regardless of input order
    # detection content identical across runs (timing excluded)
    assert [s["anomalies"] for s in m1.per_source] == [s["anomalies"] for s in m2.per_source]
    assert [c.to_dict() for c in m1.cross_incidents] == [c.to_dict() for c in m2.cross_incidents]


def test_json_detection_payload_byte_identical():
    """The detection sections of the JSON must be reproducible run-to-run; only
    the `load` telemetry (wall-clock timing) may vary."""
    import json

    specs = parse_sources([_log("error_burst.log"), _log("rate_burst.log")])

    def detection_json():
        d = analyze_sources(specs, mode="fast", workers=1).to_dict()
        d.pop("load", None)
        d.pop("workers", None)
        return json.dumps(d, sort_keys=True)

    assert detection_json() == detection_json()


def test_missing_file_is_faulted_not_fatal():
    specs = parse_sources([_log("error_burst.log"), "missing=/no/such/file.log"])
    multi = analyze_sources(specs, mode="fast", workers=1)
    good = next(s for s in multi.per_source if s["id"] == "error_burst.log")
    bad = next(s for s in multi.per_source if s["id"] == "missing")
    assert good["anomalies"]  # the healthy source still produced results
    assert bad.get("error")  # the broken one is reported, not crashed
    assert "missing" in multi.stats.faulted


def test_empty_sources():
    multi = analyze_sources([], mode="fast")
    assert multi.per_source == []
    assert multi.workers == 0


def test_cross_incident_needs_two_sources():
    # Two events close in time but from different sources → one cross-incident.
    per_source = [
        {"id": "a", "anomalies": [{"timestamp": "2024-01-01T00:00:00Z", "level": "ERROR"}]},
        {"id": "b", "anomalies": [{"timestamp": "2024-01-01T00:00:05Z", "level": "CRITICAL"}]},
    ]
    inc = correlate(per_source, gap_seconds=30)
    assert len(inc) == 1
    assert inc[0].sources == ["a", "b"]
    assert inc[0].worst_level == "CRITICAL"

    # Same two events but from ONE source → not a cross-incident.
    one = [
        {
            "id": "a",
            "anomalies": [
                {"timestamp": "2024-01-01T00:00:00Z", "level": "ERROR"},
                {"timestamp": "2024-01-01T00:00:05Z", "level": "CRITICAL"},
            ],
        }
    ]
    assert correlate(one, gap_seconds=30) == []


def test_cross_incident_respects_gap():
    per_source = [
        {"id": "a", "anomalies": [{"timestamp": "2024-01-01T00:00:00Z", "level": "ERROR"}]},
        {"id": "b", "anomalies": [{"timestamp": "2024-01-01T00:10:00Z", "level": "ERROR"}]},
    ]
    # 10 minutes apart, gap 30s → no correlation
    assert correlate(per_source, gap_seconds=30) == []
