import pytest

from loglens.detection.filetype import (
    InvalidSourceError,
    _looks_binary,
    check_source,
)


@pytest.mark.parametrize(
    "src", ["-", "stdin", "http://x/y.log", "https://x/y.log", "cmd:tail -f x"]
)
def test_passthrough_sources_ok(src):
    check_source(src)  # should not raise


def test_empty_source_raises():
    with pytest.raises(InvalidSourceError, match="No source"):
        check_source("")


def test_accepts_utf8_log(tmp_path):
    p = tmp_path / "app.log"
    p.write_text("2026-01-01 INFO started\nERROR boom\n", encoding="utf-8")
    check_source(str(p))  # no raise


def test_accepts_latin1_log(tmp_path):
    p = tmp_path / "legacy.log"
    p.write_bytes("INFO café münchen naïve\n".encode("latin-1"))
    check_source(str(p))  # no raise


def test_accepts_no_extension_text(tmp_path):
    p = tmp_path / "messages"
    p.write_text("INFO plain text with no extension\n")
    check_source(str(p))


def test_missing_file_raises(tmp_path):
    with pytest.raises(InvalidSourceError, match="not found"):
        check_source(str(tmp_path / "nope.log"))


def test_directory_raises(tmp_path):
    with pytest.raises(InvalidSourceError, match="directory"):
        check_source(str(tmp_path))


@pytest.mark.parametrize(
    "name,frag",
    [
        ("report.pdf", "PDF"),
        ("notes.docx", "Word"),
        ("photo.png", "image"),
        ("data.xlsx", "Excel"),
        ("prog.exe", "executable"),
    ],
)
def test_rejects_known_binary_extensions(tmp_path, name, frag):
    p = tmp_path / name
    p.write_bytes(b"anything")
    with pytest.raises(InvalidSourceError, match=frag):
        check_source(str(p))


def test_archive_gives_extract_hint(tmp_path):
    p = tmp_path / "logs.zip"
    p.write_bytes(b"PK\x03\x04")
    with pytest.raises(InvalidSourceError, match="Extract the log file"):
        check_source(str(p))


def test_truncated_gzip_is_reported_as_corrupt(tmp_path):
    p = tmp_path / "logs.gz"
    p.write_bytes(b"\x1f\x8b\x08\x00")
    with pytest.raises(InvalidSourceError, match="truncated or corrupt"):
        check_source(str(p))


def test_rejects_binary_content_without_extension(tmp_path):
    p = tmp_path / "weird"
    p.write_bytes(b"\x00\x01\x02\x03PNG\x00\x00binary\x00stuff")
    with pytest.raises(InvalidSourceError, match="binary"):
        check_source(str(p))


def test_rejects_null_bytes_even_with_log_extension(tmp_path):
    p = tmp_path / "corrupt.log"
    p.write_bytes(b"INFO ok\n\x00\x00\x00\x00 garbage \x00\x00")
    with pytest.raises(InvalidSourceError, match="binary"):
        check_source(str(p))


def test_looks_binary_helper():
    assert _looks_binary(b"\x00\x01\x02") is True
    assert _looks_binary(b"plain ascii log line") is False
    assert _looks_binary(b"") is False
    # undecodable, mostly non-printable bytes → binary
    assert _looks_binary(bytes([0x81, 0x8F, 0x90, 0x9D]) * 20) is True
    # valid-UTF-8 text with a few control chars is still text
    assert _looks_binary(b"INFO ok\tmore\ttext\n" * 5) is False


def test_empty_file_is_accepted(tmp_path):
    p = tmp_path / "empty.log"
    p.write_bytes(b"")
    check_source(str(p))  # empty sample is not "binary"
