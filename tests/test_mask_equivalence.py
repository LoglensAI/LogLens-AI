from __future__ import annotations

import random
import string

from loglens.detection.templates import _MASKS, _WS, template_key


def _reference_template_key(message: str) -> str:
    t = message.strip()
    for pattern, repl in _MASKS:
        t = pattern.sub(repl, t)
    return _WS.sub(" ", t).lower()


_KNOWN_CASES = [
    "12.5.3",
    "1.2.3.4",
    "10.0.0.1:8080",
    "request 0xDEADBEEF failed",
    "deadbeefcafebabe12 allocated",
    "550e8400-e29b-41d4-a716-446655440000 created",
    "2024-01-01T12:00:00Z ready",
    "2024-01-01 12:00:00.123 started",
    "took 12.5ms to respond",
    "used 512MB of 1024MB",
    'said "hello world" to user',
    "value is 'abc123' now",
    "worker-7 node-3b exited",
    "no digits or quotes here at all",
    "",
    "   ",
    "plain",
    "GET /orders/4821 200 in 13ms",
    "cache hit for key user:99381",
    "disk usage at 87 percent",
    "mix 0xFF and 12.5.3 and 'q1' and \"d2\" and uuid 550e8400-e29b-41d4-a716-446655440000",
]


def test_known_cases_byte_identical():
    for msg in _KNOWN_CASES:
        assert template_key(msg) == _reference_template_key(msg), msg


def test_divergence_trap_12_5_3():
    assert template_key("12.5.3") == _reference_template_key("12.5.3")
    assert template_key("12.5.3") == "<num>.<num>"


def _random_message(rng: random.Random) -> str:
    alphabet = string.ascii_letters + string.digits + " .:-_/|,;%\"'=[]()x" + "       "
    n = rng.randrange(0, 60)
    return "".join(rng.choice(alphabet) for _ in range(n))


def test_fuzz_random_inputs_byte_identical():
    rng = random.Random(1234)
    for _ in range(20_000):
        msg = _random_message(rng)
        assert template_key(msg) == _reference_template_key(msg), repr(msg)


def test_fuzz_structured_tokens():
    rng = random.Random(99)
    tokens = [
        "12.5.3",
        "1.2.3.4",
        "0xAB12",
        "deadbeefcafebabe",
        "550e8400-e29b-41d4-a716-446655440000",
        "2024-01-01T00:00:00Z",
        "2024-01-01 00:00:00.5",
        "13ms",
        "5GB",
        "42",
        '"str"',
        "'str'",
        "node-9",
        "plain",
    ]
    for _ in range(20_000):
        k = rng.randrange(1, 6)
        msg = " ".join(rng.choice(tokens) for _ in range(k))
        assert template_key(msg) == _reference_template_key(msg), repr(msg)


def test_real_log_lines_byte_identical():
    lines = [
        "handled request 4821 in 13ms",
        "connection pool size 20",
        "retry 3 for upstream call",
        "token refreshed for session ab12cd34",
        "GET /orders/4821 200",
        "Exception in thread main java.lang.NullPointerException",
        "  at com.example.Foo.bar(Foo.java:42)",
        "Started ApplicationController in 2.5 seconds (JVM running for 3.1)",
        "upstream timed out (110: Connection timed out) while reading response",
        "Failed password for invalid user admin from 192.168.1.10 port 22",
        "[2024-01-01 12:00:00,123] ERROR worker Task 7 failed after 3 retries",
        "block blk_-1608999687919862906 allocated on 10.251.73.220:50010",
    ]
    for msg in lines:
        assert template_key(msg) == _reference_template_key(msg), msg
