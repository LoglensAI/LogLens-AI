#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import time
import tracemalloc


def _gen(n: int, seed: int = 42) -> list[str]:
    rng = random.Random(seed)
    svcs = ["api", "db", "auth", "cache", "worker", "gateway", "web"]
    lvls = ["INFO"] * 12 + ["WARN", "ERROR", "CRITICAL"]
    msgs = [
        "handled request {n} in {n}ms",
        "cache hit for key user:{n}",
        "connection pool size {n}",
        "GET /orders/{n} 200",
        "retry {n} for upstream call",
        "disk usage at {n} percent",
        "token refreshed for session {n}",
    ]
    out = []
    for i in range(n):
        sec = i % 60
        mn = (i // 60) % 60
        hr = (i // 3600) % 24
        svc = svcs[i % len(svcs)]
        lvl = lvls[rng.randrange(len(lvls))]
        msg = msgs[i % len(msgs)].format(n=rng.randrange(100000))
        out.append(f"2024-01-01 {hr:02d}:{mn:02d}:{sec:02d} {lvl} {svc} {msg}")
    return out


def _rate(n: int, secs: float) -> float:
    return n / secs if secs > 0 else float("inf")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lines", type=int, default=1_000_000, help="Synthetic line count.")
    ap.add_argument("--source", default="", help="Measure a real log file instead of synthetic.")
    ap.add_argument("--detect", action="store_true", help="Also time full analyze_entries.")
    ap.add_argument("--json", action="store_true", help="Emit JSON only.")
    args = ap.parse_args()

    from loglens.detection.parser import parse_line, sniff_format
    from loglens.detection.templates import template_key

    if args.source:
        with open(args.source, encoding="utf-8", errors="replace") as fh:
            raw = fh.readlines()
        label = args.source
    else:
        raw = _gen(args.lines)
        label = f"synthetic/{args.lines:,} lines"
    n = len(raw)

    tracemalloc.start()
    t0 = time.perf_counter()
    fmt, _conf, layout = sniff_format(raw[:200])
    entries = [e for line in raw if (e := parse_line(line, fmt, layout)) is not None]
    parse_s = time.perf_counter() - t0
    _cur, peak_parse = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    parsed = len(entries)

    t0 = time.perf_counter()
    for e in entries:
        template_key(e.message)
    tmpl_s = time.perf_counter() - t0

    combined_s = parse_s + tmpl_s

    peak_mb = peak_parse / 1e6
    mb_per_m = peak_mb / (parsed / 1e6) if parsed else 0.0

    result = {
        "source": label,
        "lines_read": n,
        "lines_parsed": parsed,
        "parse": {"seconds": round(parse_s, 3), "lines_per_sec": round(_rate(parsed, parse_s))},
        "template": {"seconds": round(tmpl_s, 3), "lines_per_sec": round(_rate(parsed, tmpl_s))},
        "parse_plus_template": {
            "seconds": round(combined_s, 3),
            "lines_per_sec": round(_rate(parsed, combined_s)),
        },
        "memory": {
            "peak_mb_for_parsed": round(peak_mb, 1),
            "mb_per_million_lines": round(mb_per_m, 1),
            "projected_mb_at_10M": round(mb_per_m * 10, 1),
        },
        "targets": {
            "parse_plus_template_ge_100k_lps": _rate(parsed, combined_s) >= 100_000,
            "ram_under_200mb_at_10M": (mb_per_m * 10) < 200,
        },
    }

    if args.detect:
        from loglens.application.api import analyze_entries
        from loglens.detection.run import RunConfig

        t0 = time.perf_counter()
        analyze_entries(list(entries), RunConfig(mode="fast"), fmt=fmt)
        det_s = time.perf_counter() - t0
        result["detect"] = {
            "seconds": round(det_s, 3),
            "lines_per_sec": round(_rate(parsed, det_s)),
        }

    if args.json:
        print(json.dumps(result, indent=2))
        return

    p = result
    print(f"\nLogLens perf — {label}  ({parsed:,} parsed lines)\n")
    print(f"  parse            {p['parse']['lines_per_sec']:>12,} lines/s")
    print(f"  template         {p['template']['lines_per_sec']:>12,} lines/s")
    print(
        f"  parse+template   {p['parse_plus_template']['lines_per_sec']:>12,} lines/s   "
        f"{'✓' if p['targets']['parse_plus_template_ge_100k_lps'] else '✗'} ≥100k target"
    )
    if "detect" in p:
        print(f"  detect (full)    {p['detect']['lines_per_sec']:>12,} lines/s")
    m = p["memory"]
    print(
        f"\n  peak RAM         {m['peak_mb_for_parsed']:>8} MB for {parsed:,} lines  "
        f"→ ~{m['projected_mb_at_10M']} MB at 10M   "
        f"{'✓' if p['targets']['ram_under_200mb_at_10M'] else '✗'} <200 MB target"
    )


if __name__ == "__main__":
    main()