import json

from loglens.application.loghub import convert_bgl, convert_hdfs


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