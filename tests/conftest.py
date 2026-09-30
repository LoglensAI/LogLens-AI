import os
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _isolate_baseline_state(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="loglens-state-") as d:
        monkeypatch.setenv("LOGLENS_STATE_DIR", os.path.join(d, "baselines"))
        yield
