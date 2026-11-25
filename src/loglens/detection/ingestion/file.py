import asyncio
from collections.abc import AsyncIterator

import aiofiles

from loglens.detection.textio import needs_transcode, open_text

CHUNK_LINES = 1000


class AsyncFileReader:
    def __init__(self, path: str):
        self.path = path

    async def __aiter__(self) -> AsyncIterator[str]:
        if needs_transcode(self.path):  # gzip/bz2/xz or UTF-16/32
            loop = asyncio.get_running_loop()
            f = await loop.run_in_executor(None, open_text, self.path)
            try:
                while True:
                    batch = await loop.run_in_executor(None, f.readlines, 1 << 20)
                    if not batch:
                        break
                    for line in batch:
                        yield line.rstrip("\r\n")
            finally:
                f.close()
            return
        async with aiofiles.open(self.path, encoding="utf-8", errors="replace") as f:
            async for line in f:
                yield line.rstrip("\r\n")
