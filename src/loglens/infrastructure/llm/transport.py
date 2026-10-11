from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field


class LLMError(RuntimeError):
    """Raised when an LLM call fails (bad config, HTTP error, or exhausted retries)."""


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class LLMResponse:
    """The result of a chat completion — content plus usage, no mutable state."""

    content: str
    usage: TokenUsage = field(default_factory=TokenUsage)
    model: str = ""
    provider: str = ""


def _read_detail(err: urllib.error.HTTPError) -> str:
    try:
        return err.read().decode("utf-8")[:400]
    except Exception:
        return ""


# Only transient, server-side or rate-limit failures are worth retrying.
# 400/401/403/404 are caller errors — retrying just wastes time and quota.
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


class HttpTransport:
    def __init__(self, timeout: int = 60, retries: int = 2):
        self.timeout = timeout
        self.retries = retries

    def post_json(
        self,
        url: str,
        headers: dict[str, str],
        payload: dict,
        *,
        on_http_error: Callable[[int, str], str | None] | None = None,
    ) -> dict:
        body = json.dumps(payload).encode("utf-8")
        last_err: Exception | None = None

        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(
                    url,
                    data=body,
                    headers={
                    **headers,
                    "User-Agent": "curl/8.5.0",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                detail = _read_detail(e)
                if e.code in RETRYABLE_STATUS and attempt < self.retries:
                    time.sleep(2**attempt)  # backoff and retry transient errors
                    last_err = e
                    continue
                message = on_http_error(e.code, detail) if on_http_error else None
                raise LLMError(message or f"HTTP {e.code}: {detail}") from e
            except (urllib.error.URLError, OSError) as e:
                # Connection reset / DNS / timeout — transient, retry then give up.
                last_err = e
                if attempt < self.retries:
                    time.sleep(2**attempt)
                    continue

        raise LLMError(f"request failed after retries: {last_err}")
