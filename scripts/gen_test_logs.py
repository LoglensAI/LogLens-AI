#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import random
from datetime import datetime, timedelta

LEVELS_NORMAL = ["INFO", "INFO", "INFO", "INFO", "DEBUG"]
SERVICES = ["api", "db", "auth", "worker", "cache", "gateway"]

INFO_MSGS = [
    "handling GET /health ok",
    "handling GET /users ok",
    "handling POST /orders ok",
    "cache hit for key user:{n}",
    "request {n} completed in {ms}ms",
    "background job {n} finished",
    "heartbeat ok",
    "connection pool size {n}",
]
WARN_MSGS = [
    "slow response {ms}ms on /users",
    "retrying request {n}",
    "cache miss for key user:{n}",
    "high memory usage {n}%",
]
ERROR_MSGS = [
    "connection refused host=db-{n}",
    "request {n} failed with status 500",
    "timeout waiting for upstream after {ms}ms",
    "failed to acquire lock {n}",
]
CRIT_MSGS = [
    "database connection pool exhausted",
    "out of memory: killing process {n}",
    "disk full on /var/log",
    "unhandled exception in worker {n}",
]
FATAL_MSGS = [
    "kernel panic not syncing",
    "segmentation fault in pid {n}",
    "data corruption detected in shard {n}",
]


def _fmt(ts: datetime, level: str, service: str, msg: str) -> str:
    return f"{ts:%Y-%m-%d %H:%M:%S} {level} {service} {msg}"


def _msg(rng: random.Random, pool: list[str]) -> str:
    return rng.choice(pool).format(n=rng.randint(1, 999), ms=rng.randint(5, 300))


class Writer:

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.anomaly_lines: list[int] = []

    def add(self, line: str, anomaly: bool = False) -> None:
        self.lines.append(line)
        if anomaly:
            self.anomaly_lines.append(len(self.lines))  # 1-indexed

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.lines) + "\n")


def gen_clean(rng: random.Random, t0: datetime, n: int = 200) -> Writer:
    w = Writer()
    ts = t0
    for _ in range(n):
        ts += timedelta(seconds=rng.randint(1, 3))
        w.add(_fmt(ts, rng.choice(LEVELS_NORMAL), rng.choice(SERVICES), _msg(rng, INFO_MSGS)))
    return w


def gen_point_fatal(rng: random.Random, t0: datetime, n: int = 200) -> Writer:
    
    w = Writer()
    ts = t0
    inject_at = {rng.randint(20, n - 5) for _ in range(4)}
    for i in range(n):
        ts += timedelta(seconds=rng.randint(1, 3))
        if i in inject_at:
            lvl = rng.choice(["FATAL", "CRITICAL"])
            pool = FATAL_MSGS if lvl == "FATAL" else CRIT_MSGS
            w.add(_fmt(ts, lvl, rng.choice(SERVICES), _msg(rng, pool)), anomaly=True)
        else:
            w.add(_fmt(ts, rng.choice(LEVELS_NORMAL), rng.choice(SERVICES), _msg(rng, INFO_MSGS)))
    return w


def gen_error_burst(rng: random.Random, t0: datetime, n: int = 300) -> Writer:
    
    w = Writer()
    ts = t0
    for _ in range(n // 2):
        ts += timedelta(seconds=rng.randint(1, 2))
        w.add(_fmt(ts, rng.choice(LEVELS_NORMAL), "api", _msg(rng, INFO_MSGS)))
    # burst: 80 identical errors in a tight window
    for _ in range(80):
        ts += timedelta(milliseconds=rng.randint(20, 120))
        w.add(_fmt(ts, "ERROR", "db", "connection refused host=db-1"), anomaly=True)
    for _ in range(n // 2):
        ts += timedelta(seconds=rng.randint(1, 2))
        w.add(_fmt(ts, rng.choice(LEVELS_NORMAL), "api", _msg(rng, INFO_MSGS)))
    return w


def gen_incident_heavy(rng: random.Random, t0: datetime, n: int = 250) -> Writer:
    w = Writer()
    ts = t0
    for i in range(n):
        ts += timedelta(seconds=rng.randint(1, 2))
        if i % 5 == 0:
            lvl = rng.choice(["CRITICAL", "FATAL", "CRITICAL", "ERROR"])
            pool = {
                "CRITICAL": CRIT_MSGS,
                "FATAL": FATAL_MSGS,
                "ERROR": ERROR_MSGS,
            }[lvl]
            w.add(_fmt(ts, lvl, rng.choice(SERVICES), _msg(rng, pool)), anomaly=True)
        else:
            w.add(_fmt(ts, rng.choice(LEVELS_NORMAL), rng.choice(SERVICES), _msg(rng, INFO_MSGS)))
    return w


def gen_param_anomaly(rng: random.Random, t0: datetime, n: int = 200) -> Writer:
    
    w = Writer()
    ts = t0
    inject_at = {rng.randint(20, n - 5) for _ in range(5)}
    for i in range(n):
        ts += timedelta(seconds=rng.randint(1, 2))
        if i in inject_at:
            w.add(_fmt(ts, "WARNING", "api", f"request {rng.randint(1, 999)} completed in {rng.randint(8000, 12000)}ms"), anomaly=True)
        else:
            w.add(_fmt(ts, "INFO", "api", f"request {rng.randint(1, 999)} completed in {rng.randint(8, 40)}ms"))
    return w


def gen_service_outage(rng: random.Random, t0: datetime, n: int = 300) -> Writer:
    w = Writer()
    ts = t0
    for _ in range(n // 2):
        ts += timedelta(seconds=rng.randint(1, 2))
        w.add(_fmt(ts, "INFO", rng.choice(["api", "auth", "db"]), _msg(rng, INFO_MSGS)))
    # db goes down first
    ts += timedelta(seconds=1)
    w.add(_fmt(ts, "CRITICAL", "db", "database connection pool exhausted"), anomaly=True)
    for _ in range(40):
        ts += timedelta(milliseconds=rng.randint(50, 200))
        svc = rng.choice(["api", "auth", "api"])
        w.add(_fmt(ts, "ERROR", svc, "connection refused host=db-1"), anomaly=True)
    return w


def gen_rate_burst(rng: random.Random, t0: datetime, n: int = 360) -> Writer:
    w = Writer()
    ts = t0

    def background() -> None:
        nonlocal ts
        ts += timedelta(seconds=rng.randint(1, 3))
        if rng.random() < 0.03:  
            w.add(_fmt(ts, "INFO", "db", "reconnecting to database primary"))
        else:
            w.add(_fmt(ts, rng.choice(LEVELS_NORMAL), rng.choice(SERVICES), _msg(rng, INFO_MSGS)))

    for _ in range(n // 2):
        background()
    for _ in range(50):
        ts += timedelta(milliseconds=rng.randint(20, 150))
        w.add(_fmt(ts, "INFO", "db", "reconnecting to database primary"), anomaly=True)
    for _ in range(n // 2):
        background()
    return w


def gen_hdfs_sessions(rng: random.Random, t0: datetime, n_sessions: int = 90) -> Writer:
    w = Writer()
    normal_steps = [
        "Receiving block {blk} src: /10.0.0.{a} dest: /10.0.0.{b}",
        "Received block {blk} of size {n} from /10.0.0.{a}",
        "PacketResponder {p} for block {blk} terminating",
        "BLOCK* NameSystem.addStoredBlock: blockMap updated for {blk}",
        "Deleting block {blk} file /data/current/{blk}",
    ]

    def render(step: str, blk: str) -> str:
        return step.format(
            blk=blk,
            a=rng.randint(1, 254),
            b=rng.randint(1, 254),
            n=rng.randint(1000, 9_000_000),
            p=rng.randint(0, 3),
        )

    queues: list[list[tuple[str, bool]]] = []
    for _ in range(n_sessions):
        blk = f"blk_{rng.randint(10**9, 10**10)}"
        anomalous = rng.random() < 0.12
        steps = list(normal_steps)
        if anomalous:
            kind = rng.choice(["reorder", "truncate", "duplicate", "foreign"])
            if kind == "reorder":
                i = rng.randint(0, len(steps) - 2)
                steps[i], steps[i + 1] = steps[i + 1], steps[i]
            elif kind == "truncate":
                steps = steps[: rng.randint(1, 3)]  # block never finished
            elif kind == "duplicate":
                i = rng.randint(0, len(steps) - 1)
                steps.insert(i, steps[i])
            else:  # foreign event that never appears in a healthy block
                steps.insert(
                    rng.randint(1, len(steps) - 1),
                    "Exception writing block {blk} to mirror /10.0.0.{a}",
                )
        queues.append([(render(s, blk), anomalous) for s in steps])

    ts = t0
    while any(queues):
        live = [i for i, q in enumerate(queues) if q]
        qi = rng.choice(live)
        msg, anom = queues[qi].pop(0)
        ts += timedelta(seconds=rng.randint(0, 2))
        w.add(_fmt(ts, "INFO", "hdfs", msg), anomaly=anom)
    return w


def gen_big(rng: random.Random, t0: datetime, n: int) -> Writer:
    w = Writer()
    ts = t0
    inject = {rng.randint(1000, n - 1000) for _ in range(6)}
    for i in range(n):
        ts += timedelta(seconds=1)
        if i in inject:
            w.add(_fmt(ts, "FATAL", rng.choice(SERVICES), _msg(rng, FATAL_MSGS)), anomaly=True)
        else:
            r = rng.random()
            if r < 0.01:
                w.add(_fmt(ts, "ERROR", rng.choice(SERVICES), _msg(rng, ERROR_MSGS)))
            elif r < 0.05:
                w.add(_fmt(ts, "WARNING", rng.choice(SERVICES), _msg(rng, WARN_MSGS)))
            else:
                w.add(_fmt(ts, "INFO", rng.choice(SERVICES), _msg(rng, INFO_MSGS)))
    return w


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate LogLens test logs.")
    ap.add_argument("--out", default="testlogs", help="Output directory (default: ./testlogs)")
    ap.add_argument("--big", type=int, default=50000, help="Line count for big.log (default 50k)")
    ap.add_argument("--seed", type=int, default=42, help="Random seed (default 42)")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    t0 = datetime(2024, 1, 1, 0, 0, 0)
    os.makedirs(args.out, exist_ok=True)

    scenarios = {
        "clean.log": gen_clean(rng, t0),
        "point_fatal.log": gen_point_fatal(rng, t0),
        "error_burst.log": gen_error_burst(rng, t0),
        "incident_heavy.log": gen_incident_heavy(rng, t0),
        "param_anomaly.log": gen_param_anomaly(rng, t0),
        "service_outage.log": gen_service_outage(rng, t0),
        "rate_burst.log": gen_rate_burst(rng, t0),
        "hdfs_sessions.log": gen_hdfs_sessions(rng, t0),
        "big.log": gen_big(rng, t0, args.big),
    }

    labels: dict[str, dict] = {}
    print(f"Writing to {args.out}/ (seed={args.seed})\n")
    for name, w in scenarios.items():
        path = os.path.join(args.out, name)
        w.save(path)
        labels[name] = {"total_lines": len(w.lines), "anomaly_lines": w.anomaly_lines}
        print(f"  {name:<20} {len(w.lines):>7,} lines · {len(w.anomaly_lines):>4} anomalies")

    with open(os.path.join(args.out, "labels.json"), "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=2)
    print(f"\n  labels.json         ground truth (anomaly line numbers per file)")
    print("\nTry:")
    print(f"  loglens analyze --source {args.out}/incident_heavy.log --format json")
    print(f"  loglens analyze --source {args.out}/clean.log --format json     # expect 0 anomalies")
    print(f"  loglens analyze --source {args.out}/big.log --turbo --format json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())