from .file import AsyncFileReader
from .stdin import AsyncStdinReader
from .http import AsyncHTTPReader
from .command import AsyncCommandReader, CommandError, stream_command
from typing import AsyncIterator

__all__ = ["AsyncFileReader", "AsyncStdinReader", "AsyncHTTPReader",
           "AsyncCommandReader", "CommandError",
           "get_reader", "stream_lines", "stream_command"]


def get_reader(source: str):
    if source == "stdin" or source == "-":
        return AsyncStdinReader()
    elif source.startswith("cmd:"):
        return AsyncCommandReader(source[len("cmd:"):])
    elif source.startswith("http://") or source.startswith("https://"):
        return AsyncHTTPReader(source)
    else:
        return AsyncFileReader(source)

async def stream_lines(source: str) -> AsyncIterator[str]:
    reader = get_reader(source)
    async for line in reader:
        yield line