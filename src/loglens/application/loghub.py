from __future__ import annotations

import csv
import json
import os
import re
import urllib.request

BGL_SAMPLE_URL = "https://raw.githubusercontent.com/logpai/loghub/master/BGL/BGL_2k.log"
_BLK_RE = re.compile(r"blk_-?\d+")


def _download(url: str, dest: str) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "loglens-bench"})
    with urllib.request.urlopen(req, timeout=90) as resp, open(dest, "wb") as out:  # noqa: S310
        out.write(resp.read())


def _write(out_dir: str, name: str, lines: list[str], anomaly_lines: list[int]) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, name), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    labels_path = os.path.join(out_dir, "labels.json")
    labels: dict = {}
    if os.path.exists(labels_path):
        with open(labels_path, encoding="utf-8") as fh:
            labels = json.load(fh)
    labels[name] = {"total_lines": len(lines), "anomaly_lines": anomaly_lines}
    with open(labels_path, "w", encoding="utf-8") as fh:
        json.dump(labels, fh, indent=2)


def convert_bgl(
    src: str, out_dir: str, name: str = "bgl.log", max_lines: int | None = None
) -> tuple[str, int, int]:
    lines: list[str] = []
    anomaly_lines: list[int] = []
    with open(src, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            label = line.split(None, 1)[0]
            lines.append(line)
            if label != "-":  # any alert tag => anomaly
                anomaly_lines.append(len(lines))  # 1-based ordinal
            if max_lines and len(lines) >= max_lines:
                break
    _write(out_dir, name, lines, anomaly_lines)
    return name, len(lines), len(anomaly_lines)


def convert_hdfs(
    log_path: str,
    label_csv: str,
    out_dir: str,
    name: str = "hdfs.log",
    max_lines: int | None = None,
) -> tuple[str, int, int]:
    blk_label: dict[str, str] = {}
    with open(label_csv, encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            keys = {k.lower(): k for k in row}
            bid = row[keys["blockid"]] if "blockid" in keys else row[keys["block_id"]]
            lab = row[keys["label"]]
            blk_label[bid.strip()] = lab.strip().lower()

    lines: list[str] = []
    anomaly_lines: list[int] = []
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            lines.append(line)
            m = _BLK_RE.search(line)
            if m and blk_label.get(m.group(0)) == "anomaly":
                anomaly_lines.append(len(lines))
            if max_lines and len(lines) >= max_lines:
                break
    _write(out_dir, name, lines, anomaly_lines)
    return name, len(lines), len(anomaly_lines)


def fetch_bgl_sample(out_dir: str, name: str = "bgl.log") -> tuple[str, int, int]:
    os.makedirs(out_dir, exist_ok=True)
    tmp = os.path.join(out_dir, "_BGL_2k.log")
    _download(BGL_SAMPLE_URL, tmp)
    result = convert_bgl(tmp, out_dir, name=name)
    try:
        os.remove(tmp)
    except OSError:
        pass
    return result
