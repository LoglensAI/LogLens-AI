import numpy as np

from loglens.detection.safety_floor import safety_floor
from loglens.domain.models import LogEntry


def _e(level, msg):
    return LogEntry(level=level, service="db", message=msg)


def test_rare_severe_is_floored():
    entries = [_e("INFO", f"request {i} ok") for i in range(60)]
    entries.append(_e("FATAL", "kernel disk controller meltdown xyz"))
    scores = np.array([0.1] * 60 + [0.55])
    out, reasons, note = safety_floor(entries, scores, flag_at=0.70)
    assert out[60] >= 0.70
    assert any("safety floor" in r for r in reasons[60])
    assert "rare severe" in note


def test_non_severe_rare_not_floored():
    entries = [_e("INFO", f"request {i} ok") for i in range(60)]
    entries.append(_e("INFO", "some rare but harmless info line zzz"))
    scores = np.array([0.1] * 60 + [0.55])
    out, _r, _n = safety_floor(entries, scores, flag_at=0.70)
    assert out[60] < 0.70


def test_common_severe_not_floored():
    entries = [_e("INFO", f"request {i} ok") for i in range(40)]
    for _ in range(30):
        entries.append(_e("ERROR", "disk read retry on controller"))
    scores = np.array([0.1] * 40 + [0.55] * 30)
    out, _r, _n = safety_floor(entries, scores, flag_at=0.70)
    assert all(out[i] < 0.70 for i in range(40, 70))  # common severe stays put


def test_near_duplicate_of_common_not_floored():
    common = "ras kernel error double hummer alignment exception on core"
    entries = [_e("ERROR", common) for _ in range(30)]  # common severe template
    variant = "ras kernel error double hummer alignment exception on unit"  # 1 token diff
    entries.append(_e("ERROR", variant))
    scores = np.array([0.1] * 30 + [0.55])
    out, _r, _n = safety_floor(entries, scores, flag_at=0.70)
    assert out[30] < 0.70


def test_floor_never_lowers_scores():
    entries = [_e("ERROR", f"unique failure {i}") for i in range(5)]
    scores = np.array([0.95, 0.2, 0.8, 0.1, 0.5])
    out, _r, _n = safety_floor(entries, scores, flag_at=0.70)
    assert np.all(out >= scores)


def test_already_flagged_untouched():
    entries = [_e("FATAL", "already high scoring rare event")]
    scores = np.array([0.92])
    out, reasons, note = safety_floor(entries, scores, flag_at=0.70)
    assert out[0] == 0.92
    assert reasons[0] == []
