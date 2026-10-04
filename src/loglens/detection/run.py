from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

from loglens.detection.detector import (
    DetectionResult,
    DetectorConfig,
    detect,
)
from loglens.detection.embeddings import EmbeddingEngine
from loglens.detection.templates import TemplateRegistry
from loglens.domain.models import LogEntry


@dataclass
class RunConfig:
    mode: str = "fast"
    sensitivity: str = "normal"
    template_level: bool = True
    auto_threshold: bool = False
    threshold: float | None = None
    eps: float | None = None
    min_samples: int = 4


def _build_engine(mode: str):
    if mode == "deep":
        from loglens.detection.deep_embeddings import DeepEmbeddingEngine

        return DeepEmbeddingEngine()
    return EmbeddingEngine()


def run(
    entries: Sequence[LogEntry], config: RunConfig | None = None, baseline: dict | None = None
) -> DetectionResult:

    cfg = config or RunConfig()
    entries = list(entries)
    det_cfg = DetectorConfig.from_sensitivity(
        cfg.sensitivity,
        eps=cfg.eps,
        min_samples=cfg.min_samples,
    )
    det_cfg.auto_threshold = cfg.auto_threshold
    if cfg.threshold is not None:
        det_cfg.flag_threshold = float(cfg.threshold)

    if not entries:
        return detect(entries, np.zeros((0, 1), dtype=np.float32), det_cfg, baseline=baseline)

    engine = _build_engine(cfg.mode)
    engine.fit(entries)

    if cfg.template_level and hasattr(engine, "embed_group_templates"):
        registry = TemplateRegistry(entries)
        group_embeddings = engine.embed_group_templates(entries, registry)
        return detect(entries, cfg=det_cfg, baseline=baseline, group_embeddings=group_embeddings)

    embeddings = engine.embed(entries)
    return detect(entries, embeddings, det_cfg, baseline=baseline)
