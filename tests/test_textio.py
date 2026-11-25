from __future__ import annotations

import bz2
import codecs
import gzip
import lzma

import pytest
from typer.testing import CliRunner

from loglens.detection.filetype import InvalidSourceError, check_source
from loglens.detection.textio import as_plain_utf8, encoding_of, needs_transcode, open_text
from loglens.interface import cli

TEXT = "".join(f"2026-01-01 10:00:{i:02d} INFO api ok {i}\n" for i in range(40))
TEXT += "2026-01-01 10:01:00 FATAL db kernel panic: out of memory\n"


def _variants(tmp_path):
    raw = TEXT.encode()
    files = {
        "plain.log": raw,
        "bom8.log": codecs.BOM_UTF8 + raw,
        "u16.log": TEXT.encode("utf-16"),
        "u16le_nobom.log": TEXT.encode("utf-16-le"),
        "u16be_nobom.log": TEXT.encode("utf-16-be"),
        "u32.log": TEXT.encode("utf-32"),
        "app.log.gz": gzip.compress(raw),
        "app.log.bz2": bz2.compress(raw),
        "app.log.xz": lzma.compress(raw),
        "u16.log.gz": gzip.compress(TEXT.encode("utf-16")),
        "crlf.log": TEXT.replace("\n", "\r\n").encode(),
    }
    out = {}
    for name, data in files.items():
        p = tmp_path / name
        p.write_bytes(data)
        out[name] = str(p)
    return out


def test_every_variant_reads_back_identically(tmp_path):
    for name, path in _variants(tmp_path).items():
        with open_text(path) as f:
            assert f.read() == TEXT, name
        check_source(path)  # accepted, not "binary"


def test_only_non_plain_files_need_transcoding(tmp_path):
    v = _variants(tmp_path)
    assert not needs_transcode(v["plain.log"])
    assert not needs_transcode(v["crlf.log"])
    for name in ("u16.log", "u16le_nobom.log", "app.log.gz", "app.log.xz"):
        assert needs_transcode(v[name]), name
    assert as_plain_utf8(v["plain.log"]) == v["plain.log"]
    copy = as_plain_utf8(v["u16.log.gz"])
    with open(copy, encoding="utf-8") as f:
        assert f.read() == TEXT


def test_encoding_sniffing():
    assert encoding_of(codecs.BOM_UTF16_LE + b"a\x00") == "utf-16"
    assert encoding_of("plain ascii text here".encode("utf-16-le")) == "utf-16-le"
    assert encoding_of(b"plain ascii text here") == "utf-8"


def test_archives_and_binaries_are_still_rejected(tmp_path):
    z = tmp_path / "logs.zip"
    z.write_bytes(b"PK\x03\x04junk")
    b = tmp_path / "blob.dat"
    b.write_bytes(bytes(range(256)) * 20)
    for p in (z, b):
        with pytest.raises(InvalidSourceError):
            check_source(str(p))


@pytest.mark.parametrize("mode", [[], ["--turbo"], ["--parallel"]])
@pytest.mark.parametrize("name", ["app.log.gz", "u16.log"])
def test_cli_finds_the_fatal_in_compressed_and_utf16_logs(tmp_path, monkeypatch, name, mode):
    monkeypatch.setenv("HOME", str(tmp_path))
    path = _variants(tmp_path)[name]
    r = CliRunner().invoke(cli.app, ["analyze", path, "--no-learn", *mode])
    assert r.exit_code == 0, r.output
    assert "kernel panic" in r.output.lower()
    assert "41" in r.output  # all 41 lines parsed
