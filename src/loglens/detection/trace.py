from __future__ import annotations

import re
from dataclasses import dataclass

_PY = re.compile(r'File "(?P<file>[^"]+)", line (?P<line>\d+)(?:, in (?P<func>\S+))?')
_JAVA = re.compile(r"at (?P<func>[\w$.<>]+)\((?P<file>[\w$.]+\.\w+):(?P<line>\d+)\)")
_NODE = re.compile(
    r"at (?:(?P<func>[^\s(]+) )?\(?(?P<file>(?:/|\.|[A-Za-z]:\\)[^\s():]+):(?P<line>\d+)(?::\d+)?\)?"
)
_GO = re.compile(r"(?P<file>[\w./-]+\.go):(?P<line>\d+)")
_GENERIC = re.compile(
    r"(?P<file>(?:[\w./\\-]+[/\\])?[\w.-]+\.(?:py|js|ts|go|rb|java|rs|c|cc|cpp|h|hpp|php|cs|kt|scala|swift|ex|exs)):(?P<line>\d+)"
)
_FRAME_HINT = re.compile(r'^\s*(?:at |File ")|^\s*\.{3}|Traceback|Caused by:')
_LIB_HINT = re.compile(
    r"(site-packages|dist-packages|/usr/lib|node_modules|/lib/python|runtime|<frozen)"
)
_NEW_RECORD = re.compile(
    r"^(?:\d{4}[-/]\d{2}[-/]\d{2}|\d{1,2}:\d{2}:\d{2}|\d{10,13}\b|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{1,2}:\d{2})"
)


@dataclass
class Frame:
    file: str
    line: int | None = None
    func: str = ""
    lang: str = ""
    raw: str = ""

    @property
    def is_library(self) -> bool:
        return bool(_LIB_HINT.search(self.file))

    @property
    def basename(self) -> str:
        return re.split(r"[/\\]", self.file)[-1] if self.file else self.file

    def location(self) -> str:
        loc = self.file + (f":{self.line}" if self.line is not None else "")
        return f"{loc} in {self.func}" if self.func else loc


def _mk(lang: str, m: re.Match, raw: str) -> Frame:
    gd = m.groupdict()
    ln = gd.get("line")
    return Frame(
        file=gd.get("file", "") or "",
        line=int(ln) if ln and ln.isdigit() else None,
        func=(gd.get("func") or "").strip(),
        lang=lang,
        raw=raw.strip(),
    )


def extract_frames(text: str) -> list[Frame]:
    frames: list[Frame] = []
    if not text:
        return frames
    for raw in text.splitlines() or [text]:
        for lang, pat in (("python", _PY), ("java", _JAVA), ("node", _NODE), ("go", _GO)):
            m = pat.search(raw)
            if m:
                frames.append(_mk(lang, m, raw))
                break
        else:
            m = _GENERIC.search(raw)
            if m:
                frames.append(_mk("generic", m, raw))
    return frames


def is_new_record(raw: str) -> bool:
    return bool(_NEW_RECORD.match(raw or ""))


def looks_like_frame(raw: str) -> bool:
    if not raw:
        return False
    if raw[0] in " \t":
        return True
    return bool(_FRAME_HINT.search(raw)) or bool(extract_frames(raw))


def reconstruct_trace(entries: list, idx: int, max_lines: int = 40) -> list[Frame]:
    if not (0 <= idx < len(entries)):
        return []
    anchor = entries[idx]
    text = getattr(anchor, "raw", "") or getattr(anchor, "message", "") or ""
    frames = extract_frames(text)
    j = idx + 1
    while j < len(entries) and (j - idx) <= max_lines:
        raw = getattr(entries[j], "raw", "") or getattr(entries[j], "message", "") or ""
        if not raw.strip() or is_new_record(raw):
            break
        frames.extend(extract_frames(raw))
        j += 1
    return frames


def raw_block(entries: list, idx: int, max_lines: int = 40) -> str:
    if not (0 <= idx < len(entries)):
        return ""
    parts = [getattr(entries[idx], "raw", "") or getattr(entries[idx], "message", "") or ""]
    j = idx + 1
    while j < len(entries) and (j - idx) <= max_lines:
        raw = getattr(entries[j], "raw", "") or getattr(entries[j], "message", "") or ""
        if not raw.strip() or is_new_record(raw):
            break
        parts.append(raw)
        j += 1
    return "\n".join(parts)


def primary_site(frames: list[Frame]) -> Frame | None:
    if not frames:
        return None
    app = [f for f in frames if not f.is_library and f.file]
    if app:
        for f in reversed(app):
            if f.line is not None:
                return f
        return app[-1]
    return frames[-1]
