#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys

_MODE_FLAG = {"fast": [], "turbo": ["--turbo"], "deep": ["--deep"]}
_ANNOTATION = {
    "EMERGENCY": "error",
    "ALERT": "error",
    "FATAL": "error",
    "CRITICAL": "error",
    "ERROR": "error",
    "WARNING": "warning",
    "WARN": "warning",
}
_SARIF_LEVEL = {
    "EMERGENCY": "error",
    "ALERT": "error",
    "FATAL": "error",
    "CRITICAL": "error",
    "ERROR": "error",
    "WARNING": "warning",
    "WARN": "warning",
}


def _run_loglens(source: str, mode: str, fail_on: str) -> tuple[dict, int]:
    """Invoke the CLI and return (parsed_json, exit_code)."""
    cmd = ["loglens", "analyze", "--source", source, "--format", "json"]
    cmd += _MODE_FLAG.get(mode, [])
    if fail_on:
        cmd += ["--fail-on", fail_on]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        sys.stderr.write(f"LogLens: could not parse analyzer output for {source}.\n")
        sys.stderr.write(proc.stdout[:2000])
        sys.stderr.write(proc.stderr[:2000])
        raise SystemExit(1) from None
    return data, proc.returncode


def _emoji(level: str) -> str:
    lvl = level.upper()
    if lvl in ("EMERGENCY", "ALERT", "FATAL", "CRITICAL"):
        return "🔴"
    if lvl in ("ERROR",):
        return "🟠"
    if lvl in ("WARNING", "WARN"):
        return "🟡"
    return "⚪"


def _write_summary(data: dict, limit: int = 25) -> str:
    """Build the Markdown job summary for one analyzed file and return it."""
    anomalies = data.get("anomalies", [])
    n = data.get("anomaly_count", len(anomalies))
    mode = data.get("mode", "fast")
    parsed = data.get("lines_parsed", 0)
    incident = data.get("incident", False)

    lines = [
        "## 🔍 LogLens AI — log analysis",
        "",
        f"**{n} anomaly{'ies' if n != 1 else ''}** in **{parsed:,}** parsed lines "
        f"· mode `{mode}`" + ("  ·  🚨 **INCIDENT**" if incident else ""),
        "",
    ]
    if not anomalies:
        lines.append("✅ No anomalies detected.")
        return "\n".join(lines) + "\n"

    lines += [
        "| | Level | Service | ×N | Score | Message | Why |",
        "|--|--|--|--|--|--|--|",
    ]
    for a in anomalies[:limit]:
        msg = str(a.get("message", "")).replace("|", "\\|")[:80]
        why = "; ".join(a.get("reasons", []) or []).replace("|", "\\|")[:90]
        lines.append(
            f"| {_emoji(a.get('level', ''))} | {a.get('level', '')} | "
            f"{a.get('service', '')} | {a.get('count', 1):,} | "
            f"{a.get('score', 0):.2f} | {msg} | {why} |"
        )
    if n > limit:
        lines.append("")
        lines.append(f"_…and {n - limit} more._")
    return "\n".join(lines) + "\n"


def _emit_annotations(data: dict, limit: int = 20) -> None:
    """Emit GitHub inline annotations for the top anomalies."""
    for a in data.get("anomalies", [])[:limit]:
        level = _ANNOTATION.get(str(a.get("level", "")).upper())
        if not level:
            continue
        title = f"LogLens: {a.get('level')} in {a.get('service', 'log')}"
        msg = str(a.get("message", ""))[:180]
        why = "; ".join(a.get("reasons", []) or [])
        body = f"{msg}  —  {why}" if why else msg
        # Annotations without a file attach to the run; safe and always valid.
        print(f"::{level} title={title}::{body}")


def _expand_sources(source: str) -> list[str]:

    out: list[str] = []
    raw = [p.strip() for chunk in source.splitlines() for p in chunk.split(",")]
    for pat in filter(None, raw):
        if any(ch in pat for ch in "*?[]"):
            out.extend(sorted(glob.glob(pat, recursive=True)))
        else:
            out.append(pat)
    # de-dupe, preserve order
    seen: set[str] = set()
    return [p for p in out if not (p in seen or seen.add(p))]


def _filter_min_score(data: dict, min_score: float) -> dict:
    if min_score <= 0:
        return data
    kept = [a for a in data.get("anomalies", []) if float(a.get("score", 0)) >= min_score]
    d = dict(data)
    d["anomalies"] = kept
    d["anomaly_count"] = len(kept)
    return d


def _set_outputs(total: int, incident: bool, report_path: str | None) -> None:
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if not gh_out:
        return
    with open(gh_out, "a", encoding="utf-8") as fh:
        fh.write(f"anomaly-count={total}\n")
        fh.write(f"incident={'true' if incident else 'false'}\n")
        if report_path:
            fh.write(f"report-json={report_path}\n")


def _sarif(results_by_file: list[tuple[str, dict]]) -> dict:
    rules: dict[str, dict] = {}
    sarif_results: list[dict] = []
    for src, data in results_by_file:
        for a in data.get("anomalies", []):
            lvl = str(a.get("level", "")).upper()
            rule_id = f"loglens/{lvl or 'ANOMALY'}"
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": f"LogLens{lvl.title() or 'Anomaly'}",
                    "shortDescription": {"text": f"LogLens {lvl or 'anomaly'}"},
                },
            )
            why = "; ".join(a.get("reasons", []) or [])
            text = f"[{lvl}] {a.get('message', '')}".strip()
            if why:
                text += f"  —  {why}"
            region = {}
            ln = a.get("line")
            if ln is None:
                nums = a.get("line_numbers") or []
                ln = nums[0] if nums else None
            if ln is not None:
                try:
                    region = {"startLine": max(1, int(ln))}
                except (TypeError, ValueError):
                    region = {}
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": _SARIF_LEVEL.get(lvl, "note"),
                    "message": {"text": text or "LogLens anomaly"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": src},
                                **({"region": region} if region else {}),
                            }
                        }
                    ],
                }
            )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LogLens AI",
                        "informationUri": "https://github.com/LoglensAI/LogLens-AI",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, help="File, glob, or newline/comma list.")
    ap.add_argument("--mode", default="fast")
    ap.add_argument("--fail-on", default="")
    ap.add_argument("--min-score", type=float, default=0.0)
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--sarif", default="", help="Write a SARIF file to this path.")
    ap.add_argument("--report-json", default="", help="Write the aggregated JSON report here.")
    ap.add_argument("--comment-file", default="", help="Write the Markdown summary here.")
    args = ap.parse_args()

    sources = _expand_sources(args.source)
    if not sources:
        sys.stderr.write(f"LogLens: no files matched --source '{args.source}'.\n")
        return 1

    results: list[tuple[str, dict]] = []
    total = 0
    any_incident = False
    worst_code = 0
    summary_parts: list[str] = []

    for src in sources:
        data, code = _run_loglens(src, args.mode, args.fail_on)
        data = _filter_min_score(data, args.min_score)
        results.append((src, data))
        total += int(data.get("anomaly_count", 0))
        any_incident = any_incident or bool(data.get("incident", False))
        worst_code = max(worst_code, code)
        header = f"### `{src}`\n\n" if len(sources) > 1 else ""
        summary_parts.append(header + _write_summary(data, limit=args.limit))
        _emit_annotations(data)

    summary = "\n".join(summary_parts)
    if len(sources) > 1:
        summary = (
            f"# 🔍 LogLens AI — {total} anomaly(ies) across {len(sources)} file(s)"
            + ("  ·  🚨 **INCIDENT**" if any_incident else "")
            + "\n\n"
            + summary
        )

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary)
    else:  # local run — print it so the script is testable outside CI
        print(summary)

    if args.comment_file:
        marker = "<!-- loglens-ai-report -->\n"
        with open(args.comment_file, "w", encoding="utf-8") as fh:
            fh.write(marker + summary)

    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(_sarif(results), fh, indent=2)

    report_path = args.report_json or None
    if report_path:
        payload = {
            "anomaly_count": total,
            "incident": any_incident,
            "files": [{"source": s, **d} for s, d in results],
        }
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

    _set_outputs(total, any_incident, report_path)

    print(f"LogLens: {total} anomaly(ies) across {len(sources)} file(s) (mode={args.mode}).")
    return worst_code  # propagate --fail-on gating (2 == build should fail)


if __name__ == "__main__":
    raise SystemExit(main())
