import json

import numpy as np

from loglens.detection.benchmark import (
    build_feature_matrix,
    evaluate,
    grid_search,
    load_labeled,
    run_benchmark,
    score_prf1,
    train_supervised,
)
from loglens.domain.models import LogEntry


def _synthetic_corpus(n_normal: int = 60, n_anom: int = 20):
    entries, labels = [], []
    for i in range(n_normal):
        entries.append(
            LogEntry("2024-01-01T00:00:00Z", "INFO", "web", f"request served ok id={i}", "raw")
        )
        labels.append(0)
    for i in range(n_anom):
        entries.append(
            LogEntry(
                "2024-01-01T00:00:00Z", "ERROR", "db", f"connection refused timeout id={i}", "raw"
            )
        )
        labels.append(1)
    return entries, np.array(labels)


def test_prf1_perfect():
    m = score_prf1([1, 0, 1, 0], [True, False, True, False])
    assert m.precision == 1.0 and m.recall == 1.0 and m.f1 == 1.0


def test_prf1_all_wrong():
    m = score_prf1([1, 1], [False, False])
    assert m.recall == 0.0 and m.f1 == 0.0


def test_load_labeled_bgl(tmp_path):
    p = tmp_path / "bgl.log"
    p.write_text("- INFO node boot ok\nKERNEL_PANIC FATAL kernel panic on cpu0\n")
    entries, labels = load_labeled(str(p), fmt="bgl")
    assert len(entries) == 2
    assert labels.tolist() == [0, 1]


def test_load_labeled_jsonl(tmp_path):
    p = tmp_path / "d.jsonl"
    p.write_text(
        json.dumps({"label": 0, "line": "all good"})
        + "\n"
        + json.dumps({"label": 1, "line": "disk failure error"})
        + "\n"
    )
    entries, labels = load_labeled(str(p), fmt="jsonl")
    assert labels.tolist() == [0, 1]


def test_load_labeled_empty(tmp_path):
    p = tmp_path / "empty.log"
    p.write_text("")
    entries, labels = load_labeled(str(p), fmt="bgl")
    assert entries == [] and len(labels) == 0


def test_load_labeled_wrong_format_is_clean_error(tmp_path):

    import pytest

    from loglens.domain.errors import LogLensError

    p = tmp_path / "bgl.log"
    p.write_text("- INFO node boot ok\nKERNEL_PANIC FATAL kernel panic\n")
    with pytest.raises(LogLensError) as ei:
        load_labeled(str(p), fmt="jsonl")
    msg = str(ei.value)
    assert "jsonl" in msg
    assert "--format bgl" in msg  # the guess hint


def test_load_labeled_bad_labeled_format(tmp_path):
    import pytest

    from loglens.domain.errors import LogLensError

    p = tmp_path / "x.log"
    p.write_text("not-a-label line without tab\n")
    with pytest.raises(LogLensError):
        load_labeled(str(p), fmt="labeled")


def test_load_labeled_unknown_format(tmp_path):
    import pytest

    from loglens.domain.errors import LogLensError

    p = tmp_path / "x.log"
    p.write_text("- hello\n")
    with pytest.raises(LogLensError):
        load_labeled(str(p), fmt="nope")


def test_evaluate_recovers_anomalies():
    entries, labels = _synthetic_corpus()
    m, res = evaluate(entries, labels)
    # ERROR-level failures should be caught -> decent recall
    assert m.recall >= 0.8
    assert 0.0 <= m.precision <= 1.0
    assert len(res.flagged) == len(entries)


def test_grid_search_returns_best():
    entries, labels = _synthetic_corpus()
    gr = grid_search(entries, labels)
    assert 0.0 <= gr.best_f1 <= 1.0
    assert "feature_weight" in gr.best_params
    assert "flag_threshold" in gr.best_params
    assert len(gr.table) == 3 * 4  # default grid size


def test_supervised_head_matrix_shape():
    entries, labels = _synthetic_corpus()
    scores = np.linspace(0, 1, len(entries)).astype("float32")
    X = build_feature_matrix(entries, scores)
    assert X.shape[0] == len(entries)
    assert X.shape[1] == 16  # score + severity + 14 log features


def test_supervised_head_learns_separable_labels():
    entries, labels = _synthetic_corpus(n_normal=80, n_anom=40)
    _, m = train_supervised(entries, labels, test_size=0.4)
    # labels are cleanly separable -> head should score very high
    assert m.f1 >= 0.8


def test_run_benchmark_smoke(tmp_path):
    lines = ["- INFO heartbeat ok"] * 40 + ["ERR ERROR payment declined timeout"] * 15
    p = tmp_path / "bench.log"
    p.write_text("\n".join(lines))
    out = run_benchmark(str(p), fmt="bgl", do_grid=True, do_supervised=True)
    assert out["entries"] == 55
    assert "baseline" in out
    assert "grid_best_f1" in out
