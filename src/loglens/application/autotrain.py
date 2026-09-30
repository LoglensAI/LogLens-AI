from __future__ import annotations

import os

import numpy as np

_MAX_ROWS = 50_000
_MIN_PER_CLASS = 25
_REFIT_EVERY = 200


def models_dir(state_dir: str | None = None) -> str:
    from loglens.application.baseline_store import default_state_dir

    base = state_dir or default_state_dir()
    return os.path.join(base, "models")


def _buffer_path(key: str, state_dir: str | None) -> str:
    return os.path.join(models_dir(state_dir), f"{key}.buffer.npz")


def auto_model_path(key: str, state_dir: str | None = None) -> str:
    return os.path.join(models_dir(state_dir), f"{key}.model.pkl")


def _load_buffer(path: str) -> tuple[np.ndarray | None, np.ndarray | None, int]:
    if not os.path.isfile(path):
        return None, None, 0
    try:
        d = np.load(path)
        return d["X"], d["y"], int(d["last_fit"][0])
    except Exception:
        return None, None, 0


def record_and_maybe_fit(
    key: str,
    features: np.ndarray,
    pseudo_labels: np.ndarray,
    state_dir: str | None = None,
) -> tuple[str | None, bool]:
    try:
        os.makedirs(models_dir(state_dir), exist_ok=True)
        bpath = _buffer_path(key, state_dir)
        X0, y0, last_fit = _load_buffer(bpath)
        X = features.astype(np.float32)
        y = pseudo_labels.astype(np.int8)
        if X0 is not None and X0.shape[1] == X.shape[1]:
            X = np.vstack([X0, X])
            y = np.concatenate([y0, y])
        if len(X) > _MAX_ROWS:  # keep most-recent
            X, y = X[-_MAX_ROWS:], y[-_MAX_ROWS:]

        mpath = auto_model_path(key, state_dir)
        model_exists = os.path.isfile(mpath)
        pos = int((y == 1).sum())
        neg = int((y == 0).sum())
        fittable = pos >= _MIN_PER_CLASS and neg >= _MIN_PER_CLASS
        grown = len(X) - last_fit
        should_fit = fittable and (not model_exists or grown >= _REFIT_EVERY)

        if should_fit:
            from loglens.detection.benchmark import SupervisedHead

            SupervisedHead(model="rf").fit(X, y).save(mpath)
            last_fit = len(X)
            model_exists = True

        np.savez_compressed(bpath, X=X, y=y, last_fit=np.array([last_fit]))
        return (mpath if model_exists else None), model_exists
    except Exception:
        return None, False
