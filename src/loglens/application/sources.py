from __future__ import annotations

import os
import re
from dataclasses import dataclass

_ID_SANITISE = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(text: str) -> str:
    s = _ID_SANITISE.sub("_", text.strip()).strip("_")
    return s or "source"


@dataclass(frozen=True, slots=True)
class SourceSpec:
    id: str
    path: str | None = None
    url: str | None = None
    cmd: str | None = None
    fmt: str | None = None
    weight: float = 1.0

    def __post_init__(self) -> None:
        given = [v for v in (self.path, self.url, self.cmd) if v]
        if len(given) != 1:
            raise ValueError(
                f"SourceSpec {self.id!r} needs exactly one of path/url/cmd (got {len(given)})"
            )
        if self.weight <= 0:
            raise ValueError(f"SourceSpec {self.id!r} weight must be > 0 (got {self.weight})")

    @property
    def kind(self) -> str:
        if self.path:
            return "file"
        if self.url:
            return "url"
        return "cmd"

    @property
    def target(self) -> str:
        return self.path or self.url or self.cmd or ""

    @property
    def is_file(self) -> bool:
        return self.kind == "file"

    @property
    def is_stream(self) -> bool:
        return self.kind in ("url", "cmd")

    def state_key(self, namespace: str = "baseline") -> str:
        return f"{namespace}:{self.id}"

    def size_bytes(self) -> int:
        if self.is_file and self.path and os.path.exists(self.path):
            try:
                return os.path.getsize(self.path)
            except OSError:
                return 0
        return 0


def _parse_one(item: str, used: set[str]) -> SourceSpec:
    name: str | None = None
    target = item
    if "=" in item:
        head, _, tail = item.partition("=")
        if (
            head
            and _ID_SANITISE.sub("", head) == head
            and not head.lower().startswith(("http", "cmd", "https"))
        ):
            name, target = head, tail

    target = target.strip()
    if not target:
        raise ValueError(f"empty source target in {item!r}")

    if target.startswith("cmd:"):
        kw = {"cmd": target[4:].strip()}
        default_id = _slug(kw["cmd"].split()[0] if kw["cmd"] else "cmd")
    elif target.startswith(("http://", "https://")):
        kw = {"url": target}
        default_id = _slug(os.path.basename(target.rstrip("/")) or "url")
    else:
        kw = {"path": target}
        default_id = _slug(os.path.basename(target) or target)

    sid = _slug(name) if name else default_id
    base = sid
    n = 2
    while sid in used:
        sid = f"{base}-{n}"
        n += 1
    used.add(sid)
    return SourceSpec(id=sid, fmt=None, **kw)  # type: ignore[arg-type]


def parse_sources(items: list[str], fmt: str | None = None) -> list[SourceSpec]:
    used: set[str] = set()
    specs: list[SourceSpec] = []
    for item in items:
        spec = _parse_one(item, used)
        if fmt:
            spec = SourceSpec(
                id=spec.id,
                path=spec.path,
                url=spec.url,
                cmd=spec.cmd,
                fmt=fmt,
                weight=spec.weight,
            )
        specs.append(spec)
    return specs
