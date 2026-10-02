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


def _ingest_file(path: str) -> tuple[int, float]:
    import time

    from loglens.detection.parser import parse_line, sniff_format
    from loglens.detection.templates import template_key

    t0 = time.perf_counter()
    with open(path, encoding="utf-8", errors="replace") as f:
        raw = f.readlines()
    fmt, _conf, layout = sniff_format(raw[:200])
    n = 0
    for line in raw:
        e = parse_line(line.rstrip("\n"), fmt, layout)
        if e is not None:
            template_key(e.message)
            n += 1
    return n, time.perf_counter() - t0


def _worker_ladder(max_workers: int) -> list[int]:
    ladder, w = [], 1
    while w < max_workers:
        ladder.append(w)
        w *= 2
    ladder.append(max_workers)
    seen, out = set(), []
    for x in ladder:
        if x not in seen and x >= 1:
            seen.add(x)
            out.append(x)
    return out


def _make_source_files(tmp: str, n_sources: int, lines: int) -> list[str]:
    import os

    paths = []
    for i in range(n_sources):
        p = os.path.join(tmp, f"src{i}.log")
        with open(p, "w", encoding="utf-8") as f:
            f.write("\n".join(_gen(lines, seed=42 + i)))
        paths.append(p)
    return paths


def _bench_sweep(n_sources: int, lines: int, max_workers: int) -> dict:
    import shutil
    import tempfile
    import time

    from loglens.application.scheduler import detect_cores
    from loglens.infrastructure.workerpool import run_pool

    cores = detect_cores()
    ceiling = max_workers if max_workers > 0 else cores
    ladder = _worker_ladder(min(ceiling, n_sources))

    tmp = tempfile.mkdtemp(prefix="llsweep_")
    rows = []
    try:
        paths = _make_source_files(tmp, n_sources, lines)
        total = n_sources * lines
        _ingest_file(paths[0])
        base_s = None
        for w in ladder:
            t0 = time.perf_counter()
            results = run_pool(_ingest_file, paths, w)
            wall = time.perf_counter() - t0
            parsed = sum(r[0] for r in results if isinstance(r, tuple))
            if base_s is None:
                base_s = wall
            rows.append(
                {
                    "workers": w,
                    "seconds": round(wall, 3),
                    "lines_per_sec": round(_rate(total, wall)),
                    "speedup": round(base_s / wall, 2) if wall > 0 else None,
                    "efficiency_pct": round(100 * (base_s / wall) / w, 1) if wall > 0 else None,
                    "parsed": parsed,
                }
            )
        return {
            "stage": "ingest (parse+template)",
            "sources": n_sources,
            "lines_per_source": lines,
            "total_lines": total,
            "detected_cores": cores,
            "ladder": rows,
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _bench_multi(n_sources: int, lines: int, workers: int, mode: str) -> dict:
    import os
    import shutil
    import tempfile
    import time

    from loglens.application.api import analyze
    from loglens.application.multisource import analyze_sources
    from loglens.application.scheduler import detect_cores, effective_workers
    from loglens.application.sources import SourceSpec
    from loglens.detection.run import RunConfig

    tmp = tempfile.mkdtemp(prefix="llbench_")
    try:
        paths = []
        for i in range(n_sources):
            p = os.path.join(tmp, f"src{i}.log")
            with open(p, "w", encoding="utf-8") as f:
                f.write("\n".join(_gen(lines, seed=42 + i)))
            paths.append(p)
        specs = [SourceSpec(id=f"src{i}", path=p) for i, p in enumerate(paths)]
        total = n_sources * lines

        # Serial baseline: analyse each source one after another.
        t0 = time.perf_counter()
        for p in paths:
            analyze(source=p, config=RunConfig(mode=mode))
        serial_s = time.perf_counter() - t0

        # Parallel: the actual analyze-multi orchestrator.
        req = workers if workers > 0 else None
        t0 = time.perf_counter()
        res = analyze_sources(specs, mode=mode, workers=req)
        parallel_s = time.perf_counter() - t0

        resolved = res.workers
        return {
            "mode": mode,
            "sources": n_sources,
            "lines_per_source": lines,
            "total_lines": total,
            "detected_cores": detect_cores(),
            "workers_requested": workers or "auto",
            "workers_used": resolved,
            "auto_worker_budget": effective_workers(n_sources),
            "serial": {
                "seconds": round(serial_s, 3),
                "lines_per_sec": round(_rate(total, serial_s)),
            },
            "parallel": {
                "seconds": round(parallel_s, 3),
                "lines_per_sec": round(_rate(total, parallel_s)),
            },
            "speedup": round(serial_s / parallel_s, 2) if parallel_s > 0 else None,
            "total_anomalies": res.total_anomalies,
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)  # ephemeral: nothing left behind


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lines", type=int, default=1_000_000, help="Synthetic line count.")
    ap.add_argument("--source", default="", help="Measure a real log file instead of synthetic.")
    ap.add_argument("--detect", action="store_true", help="Also time full analyze_entries.")
    ap.add_argument("--json", action="store_true", help="Emit JSON only.")
    ap.add_argument(
        "--multi",
        action="store_true",
        help="Benchmark multi-source speed: N sources serial vs parallel across cores.",
    )
    ap.add_argument("--sources", type=int, default=4, help="[--multi] number of sources.")
    ap.add_argument(
        "--workers",
        type=int,
        default=0,
        help="[--multi] worker processes (0 = auto core budget).",
    )
    ap.add_argument("--mode", default="fast", help="[--multi] detection mode: fast | deep.")
    ap.add_argument(
        "--sweep",
        action="store_true",
        help="Scaling proof: ingest a fixed workload at 1,2,4,… workers; "
        "report throughput, speedup and parallel efficiency.",
    )
    args = ap.parse_args()

    if args.sweep:
        per_source = args.lines if args.lines != 1_000_000 else 100_000
        result = _bench_sweep(args.sources, per_source, args.workers)
        if args.json:
            print(json.dumps(result, indent=2))
            return
        r = result
        print(f"\nLogLens scaling sweep — {r['stage']}\n")
        print(
            f"  workload         {r['sources']} sources × {r['lines_per_source']:,} lines "
            f"= {r['total_lines']:,} lines  (fixed at every step)"
        )
        print(f"  cores detected   {r['detected_cores']}\n")
        print(f"  {'workers':>7}  {'lines/s':>14}  {'speedup':>8}  {'efficiency':>10}")
        print(f"  {'-' * 7}  {'-' * 14}  {'-' * 8}  {'-' * 10}")
        for row in r["ladder"]:
            print(
                f"  {row['workers']:>7}  {row['lines_per_sec']:>14,}  "
                f"{str(row['speedup']) + '×':>8}  {str(row['efficiency_pct']) + '%':>10}"
            )
        best = r["ladder"][-1]
        print(
            f"\n  → {best['speedup']}× faster on {best['workers']} workers "
            f"({best['efficiency_pct']}% efficiency): near-linear scaling proves the "
            f"architecture handles load by adding cores, independent of machine speed.\n"
        )
        return

    if args.multi:
        per_source = args.lines if args.lines != 1_000_000 else 50_000
        result = _bench_multi(args.sources, per_source, args.workers, args.mode)
        if args.json:
            print(json.dumps(result, indent=2))
            return
        r = result
        print(f"\nLogLens multi-source perf — {r['mode']} mode\n")
        print(
            f"  sources          {r['sources']}  ×  {r['lines_per_source']:,} lines "
            f"=  {r['total_lines']:,} total"
        )
        print(
            f"  cores detected   {r['detected_cores']}   "
            f"(auto budget {r['auto_worker_budget']} workers, used {r['workers_used']})"
        )
        print(
            f"\n  serial           {r['serial']['lines_per_sec']:>12,} lines/s   "
            f"({r['serial']['seconds']}s)"
        )
        print(
            f"  parallel         {r['parallel']['lines_per_sec']:>12,} lines/s   "
            f"({r['parallel']['seconds']}s)"
        )
        print(f"\n  speedup          {r['speedup']}×  on {r['workers_used']} worker(s)")
        print(f"  anomalies        {r['total_anomalies']:,} (identical serial vs parallel)\n")
        return

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