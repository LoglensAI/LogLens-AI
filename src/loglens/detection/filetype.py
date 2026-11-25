from __future__ import annotations

import os

_SNIFF_BYTES = 8192

# Known non-text extensions → a human-readable label for the error message.
_REJECT_EXT = {
    ".pdf": "a PDF document",
    ".doc": "a Word document",
    ".docx": "a Word document",
    ".xls": "an Excel spreadsheet",
    ".xlsx": "an Excel spreadsheet",
    ".ppt": "a PowerPoint file",
    ".pptx": "a PowerPoint file",
    ".odt": "an OpenDocument file",
    ".png": "an image",
    ".jpg": "an image",
    ".jpeg": "an image",
    ".gif": "an image",
    ".bmp": "an image",
    ".tiff": "an image",
    ".webp": "an image",
    ".ico": "an image",
    ".mp3": "an audio file",
    ".mp4": "a video file",
    ".mov": "a video file",
    ".avi": "a video file",
    ".zip": "a compressed archive",
    ".tgz": "a compressed archive",
    ".7z": "a compressed archive",
    ".rar": "a compressed archive",
    ".tar": "an archive",
    ".exe": "a binary executable",
    ".dll": "a binary executable",
    ".so": "a binary executable",
    ".bin": "a binary file",
    ".o": "a binary object file",
    ".class": "a compiled class file",
    ".pyc": "a compiled Python file",
    ".sqlite": "a database file",
    ".db": "a database file",
}

_COMPRESSED_EXT = {".tgz", ".7z", ".rar", ".zip"}


class InvalidSourceError(Exception):
    """Raised when a source cannot be read as a plain-text log."""


def _looks_binary(sample: bytes) -> bool:
    """Heuristic: does this byte sample look like binary rather than text?"""
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    try:
        sample.decode("utf-8")
        return False
    except UnicodeDecodeError:
        pass
    # Fall back to latin-1 (always decodes) and count non-printable bytes.
    text = sample.decode("latin-1")
    printable = sum(1 for ch in text if ch in "\t\n\r\f\v" or 32 <= ord(ch) < 127 or ord(ch) >= 160)
    nonprintable_ratio = 1 - (printable / len(text))
    return nonprintable_ratio > 0.30


def check_source(source: str) -> None:
    if not source:
        raise InvalidSourceError("No source given.")

    lowered = source.lower()
    if source in ("-", "stdin"):
        return
    if lowered.startswith(("http://", "https://", "cmd:")):
        return

    if not os.path.exists(source):
        raise InvalidSourceError(
            f"Source not found: '{source}'. Check the path, or use '-' for stdin."
        )
    if os.path.isdir(source):
        raise InvalidSourceError(
            f"'{source}' is a directory. Point LogLens at a single log file "
            f"(e.g. {source.rstrip('/')}/app.log)."
        )

    ext = os.path.splitext(source)[1].lower()
    if ext in _REJECT_EXT:
        label = _REJECT_EXT[ext]
        hint = ""
        if ext in _COMPRESSED_EXT:
            hint = (
                " Extract the log file first (single-file .gz, .bz2 and .xz logs are"
                " read directly)."
            )
        raise InvalidSourceError(
            f"'{source}' looks like {label}, which LogLens can't parse. "
            f"LogLens reads plain-text logs.{hint}"
        )

    from loglens.detection.textio import head_text

    try:
        # Decompressed and decoded (gzip/bz2/xz, UTF-16/32), re-encoded as UTF-8.
        sample, _enc = head_text(source, _SNIFF_BYTES)
    except EOFError as e:
        raise InvalidSourceError(
            f"'{source}' looks like a truncated or corrupt compressed file. "
            "Check the download/copy, or decompress it yourself to see the error."
        ) from e
    except (OSError, ValueError) as e:
        if "gzip" in str(e).lower() or "compressed" in str(e).lower():
            raise InvalidSourceError(
                f"'{source}' looks like a truncated or corrupt compressed file: {e}"
            ) from e
        raise InvalidSourceError(f"Can't read '{source}': {e}") from e

    if _looks_binary(sample):
        raise InvalidSourceError(
            f"'{source}' looks like a binary file, not a text log. LogLens reads plain-text logs."
        )
