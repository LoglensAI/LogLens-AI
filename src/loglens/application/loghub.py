from __future__ import annotations

import csv
import json
import os
import re
import tarfile
import tempfile
import urllib.request

BGL_SAMPLE_URL = "https://raw.githubusercontent.com/logpai/loghub/master/BGL/BGL_2k.log"
_BLK_RE = re.compile(r"blk_-?\d+")

_ZENODO = "https://zenodo.org/records/3227177/files/{archive}?download=1"
DATASET_ARCHIVES = {
    "bgl": ("BGL.tar.gz", "bgl.log"),  # ~63 MB gz → ~700 MB log
    "thunderbird": ("Thunderbird.tar.gz", "thunderbird.log"),  # ~2 GB gz → ~30 GB log
}


def _download(url: str, dest: str, on_progress=None) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "loglens-bench"})
    with (
        urllib.request.urlopen(req, timeout=300) as resp,  # noqa: S310
        open(dest, "wb") as out,
    ):
        total_hdr = resp.headers.get("Content-Length")
        total = int(total_hdr) if total_hdr and total_hdr.isdigit() else None
        done = 0
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)
            done += len(chunk)
            if on_progress is not None:
                on_progress(done, total)


def _convert_label_prefixed(
    lines, out_dir: str, name: str, max_lines: int | None, on_line=None
) -> tuple[str, int, int]:
    kept: list[str] = []
    anomaly_lines: list[int] = []
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        label = line.split(None, 1)[0]
        kept.append(line)
        if label != "-":
            anomaly_lines.append(len(kept))  # 1-based ordinal
        if on_line is not None and len(kept) % 50_000 == 0:
            on_line(len(kept))
        if max_lines and len(kept) >= max_lines:
            break
    _write(out_dir, name, kept, anomaly_lines)
    return name, len(kept), len(anomaly_lines)


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
    with open(src, encoding="utf-8", errors="replace") as fh:
        return _convert_label_prefixed(fh, out_dir, name, max_lines)


def convert_thunderbird(
    src: str, out_dir: str, name: str = "thunderbird.log", max_lines: int | None = None
) -> tuple[str, int, int]:
    return convert_bgl(src, out_dir, name=name, max_lines=max_lines)


def fetch_dataset(
    system: str,
    out_dir: str,
    max_lines: int | None = None,
    on_download=None,
    on_line=None,
) -> tuple[str, int, int]:

    key = system.strip().lower()
    if key not in DATASET_ARCHIVES:
        raise ValueError(f"no downloadable archive for {system!r} (bgl | thunderbird)")
    archive, name = DATASET_ARCHIVES[key]
    url = _ZENODO.format(archive=archive)

    tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    tmp.close()
    try:
        _download(url, tmp.name, on_progress=on_download)
        with tarfile.open(tmp.name, "r:gz") as tf:
            member = _pick_log_member(tf)
            if member is None:
                raise OSError(f"no .log file found inside {archive}")
            fh = tf.extractfile(member)
            if fh is None:
                raise OSError(f"could not read {member.name} from {archive}")
            lines = (raw.decode("utf-8", "replace") for raw in fh)
            return _convert_label_prefixed(lines, out_dir, name, max_lines, on_line=on_line)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def _pick_log_member(tf: tarfile.TarFile) -> tarfile.TarInfo | None:
    logs = [m for m in tf.getmembers() if m.isfile() and m.name.lower().endswith(".log")]
    pool = logs or [m for m in tf.getmembers() if m.isfile()]
    return max(pool, key=lambda m: m.size) if pool else None


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
