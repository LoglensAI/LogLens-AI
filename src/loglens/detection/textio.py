"""Open any log file as UTF-8 text: plain, gzip/bz2/xz-compressed, or UTF-16/32.

Rotated logs are usually compressed (``syslog.2.gz``), and Windows PowerShell 5.1
writes UTF-16 when you redirect output (``app.exe > out.log``). Both used to be
rejected as binary.
"""

from __future__ import annotations

import atexit
import bz2
import codecs
import gzip
import io
import lzma
import os
import shutil
import tempfile
from typing import IO

_COMPRESSORS = (
    (b"\x1f\x8b", "gzip", gzip.open),
    (b"BZh", "bz2", bz2.open),
    (b"\xfd7zXZ\x00", "xz", lzma.open),
)

_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)

_HEAD = 4096


def _compression(path: str) -> tuple[str | None, object | None]:
    with open(path, "rb") as f:
        magic = f.read(6)
    for sig, name, opener in _COMPRESSORS:
        if magic.startswith(sig):
            return name, opener
    return None, None


def _open_raw(path: str) -> IO[bytes]:
    _name, opener = _compression(path)
    if opener is not None:
        return opener(path, "rb")  # type: ignore[operator]
    return open(path, "rb")


def encoding_of(head: bytes) -> str:
    """Text encoding of a file from its first bytes: a BOM, or the zero-byte
    pattern of BOM-less UTF-16 (ASCII text with every other byte zero)."""
    for bom, enc in _BOMS:
        if head.startswith(bom):
            return enc
    sample = head[:2048]
    if len(sample) >= 8:
        even_zero = sample[0::2].count(0) / len(sample[0::2])
        odd_zero = sample[1::2].count(0) / len(sample[1::2])
        if odd_zero > 0.4 and even_zero < 0.05:
            return "utf-16-le"
        if even_zero > 0.4 and odd_zero < 0.05:
            return "utf-16-be"
    return "utf-8"


def describe(path: str) -> tuple[str | None, str]:
    """(compression or None, text encoding) of a local file."""
    comp, _ = _compression(path)
    with _open_raw(path) as raw:
        head = raw.read(_HEAD)
    return comp, encoding_of(head)


def needs_transcode(path: str) -> bool:
    """True if the file can't be read byte-for-byte as UTF-8 text."""
    try:
        comp, enc = describe(path)
    except (OSError, EOFError, lzma.LZMAError):
        return False
    return comp is not None or enc not in ("utf-8", "utf-8-sig")


def head_text(path: str, n_bytes: int = 8192) -> tuple[bytes, str]:
    """First decoded bytes of a file (re-encoded as UTF-8) and its encoding."""
    with _open_raw(path) as raw:
        head = raw.read(n_bytes)
    enc = encoding_of(head)
    text = head.decode(enc, errors="replace")
    return text.encode("utf-8"), enc


def open_text(path: str) -> IO[str]:
    """Open ``path`` as text, decompressing and decoding as needed."""
    with _open_raw(path) as probe:
        enc = encoding_of(probe.read(_HEAD))
    return io.TextIOWrapper(_open_raw(path), encoding=enc, errors="replace", newline=None)


_TEMPS: list[str] = []


def _cleanup() -> None:
    for p in _TEMPS:
        try:
            os.remove(p)
        except OSError:
            pass


atexit.register(_cleanup)


def as_plain_utf8(path: str) -> str:
    """Path to a plain UTF-8 copy of ``path`` (``path`` itself if already plain).

    For the turbo and parallel scanners, which split files by byte offset and so
    can't read compressed or UTF-16 data directly. Temp copies are removed at exit.
    """
    if not needs_transcode(path):
        return path
    fd, tmp = tempfile.mkstemp(prefix="loglens-", suffix=".log")
    _TEMPS.append(tmp)
    with open_text(path) as src, os.fdopen(fd, "w", encoding="utf-8", newline="\n") as dst:
        shutil.copyfileobj(src, dst, 1 << 20)
    return tmp
