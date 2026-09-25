from __future__ import annotations

import os
import warnings


def install() -> None:
    if os.environ.get("LOGLENS_WARNINGS", "").strip().lower() in ("1", "on", "true", "yes"):
        return

    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")
    os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")

    warnings.filterwarnings("ignore", message=r"Trying to unpickle estimator")
    warnings.filterwarnings(
        "ignore", message=r".*InconsistentVersionWarning.*", category=UserWarning
    )

    for module in (r"sklearn\..*", r"transformers\..*", r"torch\..*", r"huggingface_hub\..*"):
        for category in (DeprecationWarning, FutureWarning, UserWarning):
            warnings.filterwarnings("ignore", category=category, module=module)
