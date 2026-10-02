from __future__ import annotations

import threading

from loglens.application.pipeline import (
    LADDER,
    DegradationLadder,
    LadderConfig,
    OverflowPolicy,
    SheddingQueue,
    is_protected,
)


def test_protected_levels():
    assert is_protected("ERROR")
    assert is_protected("CRITICAL")
    assert is_protected("FATAL")
    assert not is_protected("WARN")
    assert not is_protected("INFO")
    assert not is_protected("DEBUG")


def test_block_policy_is_lossless_under_capacity():
    q = SheddingQueue(maxsize=5, policy=OverflowPolicy.BLOCK)
    for i in range(5):
        assert q.put("INFO", i) is True
    assert q.drops.dropped == 0


def test_drop_newest_sheds_info_not_error():
    q = SheddingQueue(maxsize=2, policy=OverflowPolicy.DROP_NEWEST)
    assert q.put("INFO", 1) is True
    assert q.put("INFO", 2) is True
    # full now; a new INFO is shed
    assert q.put("INFO", 3) is False
    assert q.drops.dropped == 1
    # but an ERROR is never shed — it is force-admitted
    assert q.put("ERROR", "boom") is True
    assert q.drops.by_level.get("ERROR") is None


def test_drop_oldest_evicts_sheddable_keeps_protected():
    q = SheddingQueue(maxsize=2, policy=OverflowPolicy.DROP_OLDEST)
    q.put("ERROR", "e1")  # protected, queued
    q.put("INFO", "i1")  # queued
    # full; inserting another INFO evicts the oldest *sheddable* (i1), not e1
    assert q.put("INFO", "i2") is True
    drained = []
    q.close()
    while (item := q.get(timeout=0.1)) is not None:
        drained.append(item)
    levels = [lvl for lvl, _ in drained]
    assert "ERROR" in levels  # protected survived
    assert q.drops.by_level.get("INFO") == 1


def test_error_never_dropped_even_when_full():
    q = SheddingQueue(maxsize=1, policy=OverflowPolicy.DROP_NEWEST)
    q.put("INFO", 1)
    # queue full of a sheddable; an ERROR must still get in
    assert q.put("ERROR", "critical") is True


def test_block_policy_blocks_then_unblocks():
    q = SheddingQueue(maxsize=1, policy=OverflowPolicy.BLOCK)
    q.put("INFO", "first")
    admitted = threading.Event()

    def producer():
        q.put("INFO", "second")  # blocks until consumer drains
        admitted.set()

    t = threading.Thread(target=producer)
    t.start()
    assert not admitted.wait(0.2)  # still blocked
    q.get()  # drain one → unblocks producer
    assert admitted.wait(1.0)
    t.join()


def test_ladder_steps_down_and_up_with_hysteresis():
    seen = []
    ladder = DegradationLadder(
        LadderConfig(capacity=100, high=0.8, low=0.4, dwell=3),
        on_change=lambda a, b: seen.append((a, b)),
    )
    # A single spike must NOT move the mode (hysteresis).
    ladder.observe(90)
    assert ladder.mode == "full"
    # Sustained pressure steps down.
    for _ in range(3):
        ladder.observe(90)
    assert ladder.mode == "no_embeddings"
    # Sustained recovery steps back up.
    for _ in range(3):
        ladder.observe(10)
    assert ladder.mode == "full"
    assert ("full", "no_embeddings") in seen
    assert ("no_embeddings", "full") in seen


def test_ladder_never_exceeds_bounds():
    ladder = DegradationLadder(LadderConfig(capacity=10, high=0.5, low=0.4, dwell=1))
    for _ in range(50):
        ladder.observe(10)
    assert ladder.mode == LADDER[-1]
    for _ in range(50):
        ladder.observe(0)
    assert ladder.mode == LADDER[0]
