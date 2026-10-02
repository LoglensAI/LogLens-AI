from __future__ import annotations

import os

from loglens.infrastructure.workerpool import TaskError, run_pool


def _square(x):
    return x * x


def _raise_on_three(x):
    if x == 3:
        raise ValueError("task three fails")
    return x


def _crash_on_two(x):
    if x == 2:
        os._exit(1)  # hard-kill the worker process
    return x * 10


def test_parallel_map_preserves_order():
    assert run_pool(_square, [1, 2, 3, 4, 5], workers=3) == [1, 4, 9, 16, 25]


def test_empty_args():
    assert run_pool(_square, [], workers=4) == []


def test_serial_path():
    assert run_pool(_square, [1, 2, 3], workers=1) == [1, 4, 9]


def test_task_exception_is_isolated():
    out = run_pool(_raise_on_three, [1, 2, 3, 4], workers=2)
    assert out[0] == 1 and out[1] == 2 and out[3] == 4
    assert isinstance(out[2], TaskError)
    assert out[2].kind == "exception"
    assert "ValueError" in out[2].message


def test_worker_crash_only_quarantines_culprit():
    events = []
    out = run_pool(
        _crash_on_two, [1, 2, 3, 4, 5], workers=3, on_event=lambda k, d: events.append(k)
    )
    # Innocent tasks all complete; only the crasher (index 1) is quarantined.
    assert out[0] == 10 and out[2] == 30 and out[3] == 40 and out[4] == 50
    assert isinstance(out[1], TaskError)
    assert out[1].kind == "worker_crash"
    assert "worker_restart" in events
    assert "quarantine" in events


def test_serial_exception_isolated():
    out = run_pool(_raise_on_three, [3], workers=1)
    assert isinstance(out[0], TaskError)
