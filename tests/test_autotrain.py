import os

import numpy as np

from loglens.application import autotrain as at


def _feats(n, seed):
    rng = np.random.default_rng(seed)
    return rng.random((n, 3)).astype(np.float32)


def test_not_fittable_with_one_class(tmp_path):
    sd = str(tmp_path / "baselines")
    X = _feats(40, 1)
    y = np.zeros(40, dtype=int)
    path, ready = at.record_and_maybe_fit("k", X, y, sd)
    assert ready is False
    assert path is None


def test_fits_once_both_classes_accumulate(tmp_path):
    sd = str(tmp_path / "baselines")
    X = _feats(60, 2)
    y = np.array([1] * 30 + [0] * 30, dtype=int)
    path, ready = at.record_and_maybe_fit("k", X, y, sd)
    assert ready is True
    assert path is not None and os.path.isfile(path)
    assert path == at.auto_model_path("k", sd)


def test_accumulates_across_calls(tmp_path):
    sd = str(tmp_path / "baselines")
    at.record_and_maybe_fit("k", _feats(30, 3), np.zeros(30, dtype=int), sd)
    assert not os.path.isfile(at.auto_model_path("k", sd))
    _p, ready = at.record_and_maybe_fit("k", _feats(30, 4), np.ones(30, dtype=int), sd)
    assert ready is True
    assert os.path.isfile(at.auto_model_path("k", sd))


def test_auto_model_loads_and_predicts(tmp_path):
    sd = str(tmp_path / "baselines")
    X = _feats(60, 5)
    y = np.array([1] * 30 + [0] * 30, dtype=int)
    path, _ = at.record_and_maybe_fit("k", X, y, sd)
    from loglens.detection.benchmark import SupervisedHead

    head = SupervisedHead.load(path)
    preds = head.predict(_feats(10, 6))
    assert len(preds) == 10


def test_never_raises_on_bad_input(tmp_path):
    sd = str(tmp_path / "baselines")
    path, ready = at.record_and_maybe_fit("k", np.zeros((0, 3), dtype=np.float32), np.array([]), sd)
    assert ready is False


def test_models_stay_inside_state_dir(tmp_path):
    sd = str(tmp_path / "custom")
    assert os.path.commonpath([sd, at.models_dir(sd)]) == os.path.normpath(sd)
    X = _feats(60, 7)
    y = np.array([1] * 30 + [0] * 30, dtype=int)
    path, ready = at.record_and_maybe_fit("k", X, y, sd)
    assert ready is True
    assert os.path.normpath(path).startswith(os.path.normpath(sd) + os.sep)
    assert os.listdir(tmp_path) == ["custom"]
