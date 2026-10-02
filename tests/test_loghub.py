import io
import json
import shutil
import tarfile

from loglens.application import loghub
from loglens.application.loghub import convert_bgl, convert_hdfs, convert_thunderbird


def test_fetch_dataset_downloads_extracts_converts(tmp_path, monkeypatch):
    # build a fake BGL.tar.gz with the label-prefixed format
    raw = (
        "\n".join(
            [
                "- 1 node1 INFO ok",
                "KERNEL 2 node1 FATAL tlb",
                "- 3 node1 INFO ok",
                "APPREAD 4 node1 ERROR read",
            ]
        )
        + "\n"
    ).encode()
    arc = tmp_path / "BGL.tar.gz"
    with tarfile.open(arc, "w:gz") as tf:
        ti = tarfile.TarInfo("BGL.log")
        ti.size = len(raw)
        tf.addfile(ti, io.BytesIO(raw))

    # stub the network: copy our local archive into the requested dest
    monkeypatch.setattr(
        loghub, "_download", lambda url, dest, on_progress=None: shutil.copyfile(arc, dest)
    )

    out = tmp_path / "suite"
    name, total, anom = loghub.fetch_dataset("bgl", str(out), max_lines=None)
    assert name == "bgl.log" and total == 4 and anom == 2
    labels = json.load(open(out / "labels.json"))
    assert labels["bgl.log"]["anomaly_lines"] == [2, 4]

    # max_lines takes a slice without reading the whole log
    _n, t2, a2 = loghub.fetch_dataset("bgl", str(tmp_path / "suite2"), max_lines=2)
    assert t2 == 2 and a2 == 1


def test_fetch_dataset_fires_progress_callbacks(tmp_path, monkeypatch):
    raw = ("\n".join([f"- {i} n1 INFO ok" for i in range(10)]) + "\n").encode()
    arc = tmp_path / "BGL.tar.gz"
    with tarfile.open(arc, "w:gz") as tf:
        ti = tarfile.TarInfo("BGL.log")
        ti.size = len(raw)
        tf.addfile(ti, io.BytesIO(raw))

    # a stub _download that honours the on_progress callback
    def fake_dl(url, dest, on_progress=None):
        shutil.copyfile(arc, dest)
        if on_progress:
            on_progress(len(raw), len(raw))

    monkeypatch.setattr(loghub, "_download", fake_dl)
    seen = {"dl": 0}
    loghub.fetch_dataset(
        "bgl", str(tmp_path / "out"), on_download=lambda d, t: seen.__setitem__("dl", d)
    )
    assert seen["dl"] == len(raw)  # download progress was reported


def test_convert_thunderbird_labels_from_alert_tag(tmp_path):
    src = tmp_path / "Thunderbird.log"
    src.write_text(
        "\n".join(
            [
                "- 1131566461 2005.11.09 tbird-admin1 Nov 9 ok",
                "VAPI 1131566462 2005.11.09 tbird-admin1 Nov 9 kernel fault",
                "- 1131566463 2005.11.09 tbird-admin1 Nov 9 ok again",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    name, total, anom = convert_thunderbird(str(src), str(tmp_path / "out"))
    assert name == "thunderbird.log"
    assert total == 3 and anom == 1
    labels = json.load(open(tmp_path / "out" / "labels.json"))
    assert labels[name]["anomaly_lines"] == [2]  # the one alert-tagged line


def test_convert_bgl_labels_from_alert_tag(tmp_path):
    src = tmp_path / "BGL.log"
    src.write_text(
        "\n".join(
            [
                "- 1117838570 2005.06.03 R02-M1 2005-06-03-15.42.50 R02-M1 RAS KERNEL INFO ok",
                "KERNDTLB 1117838571 2005.06.03 R02-M1 2005-06-03-15.42.51 R02-M1 RAS KERNEL FATAL tlb",
                "- 1117838572 2005.06.03 R02-M1 2005-06-03-15.42.52 R02-M1 RAS KERNEL INFO ok again",
                "APPREAD 1117838573 2005.06.03 R02-M1 2005-06-03-15.42.53 R02-M1 RAS APP ERROR read",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    name, total, anom = convert_bgl(str(src), str(tmp_path / "out"))
    assert total == 4
    assert anom == 2  # the two alert-tagged lines
    labels = json.load(open(tmp_path / "out" / "labels.json"))
    assert labels[name]["anomaly_lines"] == [2, 4]  # 1-based ordinals
    # the benchable log keeps the raw lines (HPC parser routes the tag to metadata)
    assert (tmp_path / "out" / name).exists()


def test_convert_hdfs_labels_by_block(tmp_path):
    log = tmp_path / "HDFS.log"
    log.write_text(
        "\n".join(
            [
                "081109 203615 148 INFO dfs.DataNode: PacketResponder for block blk_100 terminating",
                "081109 203616 149 INFO dfs.DataNode: Receiving block blk_200 src /1.2.3.4",
                "081109 203617 150 INFO dfs.DataNode: PacketResponder for block blk_100 done",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    label_csv = tmp_path / "anomaly_label.csv"
    label_csv.write_text("BlockId,Label\nblk_100,Anomaly\nblk_200,Normal\n", encoding="utf-8")

    name, total, anom = convert_hdfs(str(log), str(label_csv), str(tmp_path / "out"))
    assert total == 3
    labels = json.load(open(tmp_path / "out" / "labels.json"))
    # both blk_100 lines are anomalies; the blk_200 line is normal
    assert labels[name]["anomaly_lines"] == [1, 3]


def test_convert_bgl_max_lines(tmp_path):
    src = tmp_path / "BGL.log"
    src.write_text(
        "\n".join(f"- {i} 2005.06.03 node t node RAS K INFO ok {i}" for i in range(50)) + "\n",
        encoding="utf-8",
    )
    _name, total, _anom = convert_bgl(str(src), str(tmp_path / "out"), max_lines=10)
    assert total == 10


def test_labels_json_merges_multiple_systems(tmp_path):
    out = tmp_path / "out"
    b = tmp_path / "BGL.log"
    b.write_text(
        "- 1 2005.06.03 n t n RAS K INFO ok\nX 2 2005.06.03 n t n RAS K FATAL bad\n",
        encoding="utf-8",
    )
    convert_bgl(str(b), str(out), name="bgl.log")

    h = tmp_path / "HDFS.log"
    h.write_text("081109 203615 148 INFO x: block blk_1 ok\n", encoding="utf-8")
    csvp = tmp_path / "labels.csv"
    csvp.write_text("BlockId,Label\nblk_1,Normal\n", encoding="utf-8")
    convert_hdfs(str(h), str(csvp), str(out), name="hdfs.log")

    labels = json.load(open(out / "labels.json"))
    assert set(labels) == {"bgl.log", "hdfs.log"}  # both present in one labels.json
