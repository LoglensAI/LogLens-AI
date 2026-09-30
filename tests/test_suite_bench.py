import json

from loglens.application.suite_bench import bench_file, run_suite, to_markdown


def _write_suite(tmp_path):
    clean = tmp_path / "clean.log"
    clean.write_text(
        "\n".join(f"2024-01-01 00:00:{i:02d} INFO api request {i} ok" for i in range(40)) + "\n",
        encoding="utf-8",
    )
    incident = tmp_path / "incident.log"
    lines, anomaly_lines = [], []
    for i in range(40):
        if i in (10, 20, 30):
            lines.append(f"2024-01-01 00:01:{i:02d} CRITICAL db database connection pool exhausted")
            anomaly_lines.append(i + 1)  # 1-based ordinal
        else:
            lines.append(f"2024-01-01 00:01:{i:02d} INFO api request {i} ok")
    incident.write_text("\n".join(lines) + "\n", encoding="utf-8")

    labels = {
        "clean.log": {"total_lines": 40, "anomaly_lines": []},
        "incident.log": {"total_lines": 40, "anomaly_lines": anomaly_lines},
    }
    (tmp_path / "labels.json").write_text(json.dumps(labels), encoding="utf-8")
    return tmp_path


def test_bench_file_detects_obvious_incident(tmp_path):
    _write_suite(tmp_path)
    labels = json.load(open(tmp_path / "labels.json"))
    fm = bench_file(
        str(tmp_path / "incident.log"),
        labels["incident.log"]["anomaly_lines"],
        seed=0,
    )
    assert fm.labeled == 3
    assert fm.recall == 1.0
    assert fm.precision == 1.0
    assert fm.f1 == 1.0
    assert fm.fmt == "GENERIC"
    assert fm.lines_per_sec > 0
    assert 0.0 <= fm.window_f1 <= 1.0
    assert fm.window_recall == 1.0
    assert 0.0 <= fm.template_f1 <= 1.0
    assert fm.window_size == 100


def test_window_metric_rewards_incident_windows(tmp_path):
    _write_suite(tmp_path)
    labels = json.load(open(tmp_path / "labels.json"))
    fm = bench_file(
        str(tmp_path / "incident.log"),
        labels["incident.log"]["anomaly_lines"],
        window=10,
        seed=0,
    )
    assert fm.window_size == 10
    assert fm.window_recall == 1.0
    assert fm.window_precision > 0.0


def test_supervised_head_benchmarks_when_enabled(tmp_path):
    _write_suite(tmp_path)
    labels = json.load(open(tmp_path / "labels.json"))
    fm_small = bench_file(
        str(tmp_path / "incident.log"),
        labels["incident.log"]["anomaly_lines"],
        supervised=True,
        seed=0,
    )
    assert fm_small.sup_f1 is None  # gracefully skipped, not an error

    big = tmp_path / "big_incident.log"
    lines, anom = [], []
    for i in range(200):
        if i % 4 == 0:
            lines.append(f"2024-01-01 00:00:{i % 60:02d} CRITICAL db pool exhausted node {i}")
            anom.append(i + 1)
        else:
            lines.append(f"2024-01-01 00:00:{i % 60:02d} INFO api request {i} ok")
    big.write_text("\n".join(lines) + "\n", encoding="utf-8")
    fm = bench_file(str(big), anom, supervised=True, seed=0)
    assert fm.sup_f1 is not None
    assert 0.0 <= fm.sup_f1 <= 1.0


def test_clean_file_scores_perfect(tmp_path):
    _write_suite(tmp_path)
    fm = bench_file(str(tmp_path / "clean.log"), [], seed=0)
    assert fm.labeled == 0
    assert fm.fp == 0
    assert fm.f1 == 1.0


def test_run_suite_aggregates(tmp_path):
    _write_suite(tmp_path)
    report = run_suite(str(tmp_path), seed=0)
    assert {f.name for f in report.files} == {"clean.log", "incident.log"}
    assert report.micro["precision"] == 1.0
    assert report.micro["recall"] == 1.0
    assert report.micro["f1"] == 1.0
    assert report.totals["files"] == 2
    assert report.totals["lines"] == 80
    md = to_markdown(report)
    assert "Aggregate" in md and "incident.log" in md


def test_run_suite_metrics_are_deterministic(tmp_path):
    _write_suite(tmp_path)
    a = run_suite(str(tmp_path), seed=0)
    b = run_suite(str(tmp_path), seed=0)
    assert a.micro == b.micro
    assert a.macro == b.macro
    assert [(f.name, f.f1, f.precision, f.recall) for f in a.files] == [
        (f.name, f.f1, f.precision, f.recall) for f in b.files
    ]


def test_run_suite_missing_labels_raises(tmp_path):
    import pytest

    (tmp_path / "some.log").write_text("2024-01-01 00:00:00 INFO api ok\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        run_suite(str(tmp_path))
