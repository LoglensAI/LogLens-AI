#!/usr/bin/env python3
from __future__ import annotations

import sys
from datetime import datetime, timedelta


def build(now: datetime) -> str:
    lines: list[str] = []

    def add(dt: datetime, level: str, service: str, msg: str) -> None:
        lines.append(f"{dt:%Y-%m-%d %H:%M:%S} {level} {service} {msg}")

    def raw(text: str) -> None: 
        lines.append(text)

    base = now - timedelta(minutes=50)

    hosts = ["api", "web", "worker", "cache", "db"]
    for i in range(120):
        add(
            base + timedelta(seconds=i * 20),
            "INFO",
            hosts[i % len(hosts)],
            f"handled request {i} in 12ms",
        )

    for k in range(3):
        t = now - timedelta(minutes=18 - k * 6)
        add(t, "ERROR", "api", f"unhandled exception while processing order {1000 + k}")
        raw("Traceback (most recent call last):")
        raw('  File "/srv/app/api/orders.py", line 142, in checkout')
        raw("    charge = payments.charge(cart.total)")
        raw('  File "/srv/app/payments/gateway.py", line 88, in charge')
        raw("    resp = self._post(url, body)")
        raw('  File "/usr/lib/python3.12/http/client.py", line 1010, in _post')
        raw("    raise TimeoutError(msg)")
        raw("TimeoutError: upstream payment gateway timed out")

    t = now - timedelta(minutes=14)
    add(t, "ERROR", "worker", "job serialization failed")
    raw('  File "/usr/lib/python3.12/json/encoder.py", line 257, in iterencode')
    raw("TypeError: Object of type set is not JSON serializable")

    add(
        now - timedelta(minutes=11),
        "ERROR",
        "auth",
        "login failed: NullPointerException in token parser",
    )

    add(
        now - timedelta(minutes=9),
        "ERROR",
        "web",
        "config validation failed at config/settings.rb:42",
    )

    add(
        now - timedelta(minutes=6),
        "FATAL",
        "db",
        "kernel panic: out of memory, killing process 8123",
    )

    add(now - timedelta(minutes=4), "ERROR", "cache", "connection refused host=redis-1")
    add(
        now - timedelta(minutes=3, seconds=40),
        "INFO",
        "cache",
        "reconnected to redis-1, back to normal",
    )

    return "\n".join(lines) + "\n"


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "demo_incident.log"
    with open(out, "w", encoding="utf-8") as f:
        f.write(build(datetime.now()))
    print(f"wrote {out}")
    print("\nTry:")
    print(f"  loglens explain --source {out} --no-learn")
    print(f"  loglens explain --source {out} --no-learn --plain")
    print(f"  loglens explain --source {out} --no-learn --impact blocking")


if __name__ == "__main__":
    main()