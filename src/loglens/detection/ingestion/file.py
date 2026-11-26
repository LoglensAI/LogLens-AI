import asyncio
from collections.abc import AsyncIterator
from typing import IO

from loglens.detection.textio import needs_transcode, open_text

# Lines are read in ~1 MiB batches, one thread hop per batch. Reading line by
# line through an async file wrapper costs one thread hop *per line* (~100 µs),
# which made reading and parsing take ~38% of an exact-mode run on 100k lines.
BATCH_BYTES = 1 << 20


def _open_plain(path: str) -> IO[str]:
    # Same decoding as before (UTF-8, bad bytes replaced, universal newlines).
    return open(path, encoding="utf-8", errors="replace")


class AsyncFileReader:
    def __init__(self, path: str):
        self.path = path

    async def __aiter__(self) -> AsyncIterator[str]:
        loop = asyncio.get_running_loop()
        # gzip/bz2/xz or UTF-16/32 need decoding; plain UTF-8 is opened directly.
        opener = open_text if needs_transcode(self.path) else _open_plain
        f = await loop.run_in_executor(None, opener, self.path)
        try:
            while True:
                batch = await loop.run_in_executor(None, f.readlines, BATCH_BYTES)
                if not batch:
                    break
                for line in batch:
                    yield line.rstrip("\r\n")
        finally:
            f.close()
