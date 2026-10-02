from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("loglens.workerpool")


@dataclass(slots=True)
class TaskError:
    index: int
    kind: str  # "exception" | "worker_crash"
    message: str

    @property
    def ok(self) -> bool:
        return False


def _is_error(x: Any) -> bool:
    return isinstance(x, TaskError)


def run_pool(
    func: Callable[[Any], Any],
    args: Sequence[Any],
    workers: int,
    *,
    max_attempts: int = 2,
    on_event: Callable[[str, str], None] | None = None,
) -> list[Any]:

    n = len(args)
    results: list[Any] = [None] * n
    if n == 0:
        return results

    if workers <= 1:
        return [_safe_serial(func, a, i) for i, a in enumerate(args)]

    done = [False] * n
    attempts = [0] * n
    isolate = False

    while not all(done):
        pending = [i for i in range(n) if not done[i]]
        for i in list(pending):
            if attempts[i] >= max_attempts:
                results[i] = TaskError(i, "worker_crash", "task repeatedly crashed a worker")
                done[i] = True
                if on_event:
                    on_event("quarantine", f"task {i}")
        pending = [i for i in range(n) if not done[i]]
        if not pending:
            break

        try:
            broke = _run_batch(func, args, pending, attempts, results, done, workers, isolate)
        except (BrokenProcessPool, OSError) as exc:
            logger.warning("process pool unavailable (%s); running serially", exc)
            if on_event:
                on_event("serial_fallback", str(exc))
            for i in pending:
                results[i] = _safe_serial(func, args[i], i)
                done[i] = True
            break

        if broke:
            isolate = True
            if on_event:
                on_event("worker_restart", "rebuilding pool after worker crash")

    return results


def _run_batch(
    func: Callable[[Any], Any],
    args: Sequence[Any],
    pending: list[int],
    attempts: list[int],
    results: list[Any],
    done: list[bool],
    workers: int,
    isolate: bool,
) -> bool:
    from concurrent.futures import as_completed

    if isolate:
        broke_any = False
        for i in pending:
            attempts[i] += 1
            try:
                with ProcessPoolExecutor(max_workers=1) as ex:
                    fut = ex.submit(func, args[i])
                    try:
                        results[i] = fut.result()
                        done[i] = True
                    except BrokenProcessPool:
                        broke_any = True
                    except Exception as exc:
                        results[i] = TaskError(i, "exception", f"{type(exc).__name__}: {exc}")
                        done[i] = True
            except BrokenProcessPool:
                broke_any = True
        return broke_any

    with ProcessPoolExecutor(max_workers=workers) as ex:
        fut_to_i = {}
        for i in pending:
            attempts[i] += 1
            fut_to_i[ex.submit(func, args[i])] = i
        try:
            for fut in as_completed(fut_to_i):
                i = fut_to_i[fut]
                try:
                    results[i] = fut.result()
                    done[i] = True
                except BrokenProcessPool:
                    return True
                except Exception as exc:  # task-level fault → isolate the result
                    results[i] = TaskError(i, "exception", f"{type(exc).__name__}: {exc}")
                    done[i] = True
        except BrokenProcessPool:
            return True
    return False


def _safe_serial(func: Callable[[Any], Any], arg: Any, index: int) -> Any:
    try:
        return func(arg)
    except Exception as exc:  # isolate, mirror the pool's behaviour
        return TaskError(index, "exception", f"{type(exc).__name__}: {exc}")
