from __future__ import annotations

import numpy as np
import pytest
import typer

from loglens.detection import detector as det
from loglens.detection import limits
from loglens.detection.synonyms import SynonymLearner


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(limits.ENV_MAX_CLUSTER_GROUPS, raising=False)
    monkeypatch.delenv(limits.ENV_MAX_SYNONYM_VOCAB, raising=False)


def test_defaults():
    assert limits.max_cluster_groups() == limits.DEFAULT_MAX_CLUSTER_GROUPS == 40_000
    assert limits.max_synonym_vocab() == limits.DEFAULT_MAX_SYNONYM_VOCAB == 2_000


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("123", 123),
        ("50_000", 50_000),
        ("1,000", 1_000),
        (" AUTO ", "auto"),
        ("0", None),
        ("-5", None),
        ("lots", None),
        (None, None),
    ],
)
def test_parse_cap(raw, expected):
    assert limits.parse_cap(raw) == expected


def test_env_overrides_are_read_at_call_time(monkeypatch):
    monkeypatch.setenv(limits.ENV_MAX_CLUSTER_GROUPS, "123")
    monkeypatch.setenv(limits.ENV_MAX_SYNONYM_VOCAB, "45")
    assert limits.max_cluster_groups() == 123
    assert limits.max_synonym_vocab() == 45


def test_invalid_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv(limits.ENV_MAX_CLUSTER_GROUPS, "-1")
    monkeypatch.setenv(limits.ENV_MAX_SYNONYM_VOCAB, "auto")  # auto: default for synonyms
    assert limits.max_cluster_groups() == 40_000
    assert limits.max_synonym_vocab() == 2_000


def test_auto_scales_with_sqrt_of_ram_and_is_clamped():
    gib = 1024**3
    assert limits.auto_cluster_groups(8 * gib) == 40_000
    assert limits.auto_cluster_groups(32 * gib) == 80_000  # 4x RAM -> 2x groups
    assert limits.auto_cluster_groups(1 * gib // 4) == 10_000  # clamped at 1/4
    assert limits.auto_cluster_groups(10_000 * gib) == 160_000  # clamped at 4x
    assert limits.auto_cluster_groups(0) == 40_000


def test_auto_env_uses_available_ram(monkeypatch):
    monkeypatch.setenv(limits.ENV_MAX_CLUSTER_GROUPS, "auto")
    monkeypatch.setattr(limits, "_available_ram_bytes", lambda: 2 * 1024**3)
    assert limits.max_cluster_groups() == 20_000


def test_lowered_cluster_cap_skips_clustering(monkeypatch):
    rng = np.random.default_rng(0)
    gv = rng.standard_normal((50, 8)).astype(np.float32)
    gc = np.ones(50, dtype=np.float64)
    cfg = det.DetectorConfig()

    *_, labels, _, eps = det._cluster_from_group_vectors(gv, gc, registry=None, cfg=cfg)
    assert eps > 0  # clustered normally

    monkeypatch.setenv(limits.ENV_MAX_CLUSTER_GROUPS, "10")
    *_, labels, sizes, eps = det._cluster_from_group_vectors(gv, gc, registry=None, cfg=cfg)
    assert eps == 0.0 and set(labels.tolist()) == {-1} and sizes == {-1: 50.0}


def test_synonym_cap_limits_search_and_keys_the_cache(tmp_path, monkeypatch):
    msgs = [f"error: conection refused to db host-{i}" for i in range(10)] + [
        f"error: connection refused to db host-{i}" for i in range(200)
    ]
    learner = SynonymLearner(cache_dir=str(tmp_path))
    learner.fit(msgs)
    assert learner.learned.get("conection") == "connection"

    # A cap of 1 keeps only the single most frequent token, so nothing can merge,
    # and the cached result from the default cap must not be reused.
    monkeypatch.setenv(limits.ENV_MAX_SYNONYM_VOCAB, "1")
    capped = SynonymLearner(cache_dir=str(tmp_path))
    capped.fit(msgs)
    assert "conection" not in capped.learned


def test_cli_flags_set_env_and_validate(monkeypatch):
    from loglens.interface import cli

    cli._apply_cap_flags("75000", "3000")
    assert limits.max_cluster_groups() == 75_000
    assert limits.max_synonym_vocab() == 3_000
    cli._apply_cap_flags("auto", "")
    assert limits.parse_cap(__import__("os").environ[limits.ENV_MAX_CLUSTER_GROUPS]) == "auto"
    with pytest.raises(typer.BadParameter):
        cli._apply_cap_flags("", "auto")
    with pytest.raises(typer.BadParameter):
        cli._apply_cap_flags("zero", "")
