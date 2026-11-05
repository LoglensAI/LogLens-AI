from __future__ import annotations

SEVERITY_RANK: dict[str, int] = {
    "EMERGENCY": 0,
    "EMERG": 0,
    "PANIC": 0,
    "ALERT": 1,
    "FATAL": 1,
    "CRITICAL": 2,
    "CRIT": 2,
    "ERROR": 3,
    "ERR": 3,
    "WARN": 4,
    "WARNING": 4,
    "NOTICE": 5,
    "INFO": 6,
    "DEBUG": 7,
    "TRACE": 7,
}
DEFAULT_SEVERITY = 6  # unknown levels are treated as INFO-ish
HARD_FLAG_SEVERITY = 1  # levels at or below this rank are surfaced immediately


def get_severity(level: str) -> int:
    """Ordinal severity for a level name (0 = worst). Unknown → DEFAULT_SEVERITY."""
    return SEVERITY_RANK.get(level.upper(), DEFAULT_SEVERITY)


# Base anomaly-score contribution by severity rank (detection tuning).
SEVERITY_BASE: dict[int, float] = {
    0: 1.0,
    1: 1.0,  # hard-flagged anyway
    2: 0.70,  # CRITICAL
    3: 0.55,  # ERROR (graded down: routine errors are common)
    4: 0.42,  # WARN
    5: 0.08,  # NOTICE
    6: 0.0,  # INFO
    7: 0.0,  # DEBUG/TRACE
}

# Display order, worst first (levels not present are simply skipped by callers).
CATEGORY_ORDER = [
    "EMERGENCY",
    "ALERT",
    "FATAL",
    "CRITICAL",
    "ERROR",
    "WARN",
    "WARNING",
    "NOTICE",
    "INFO",
    "DEBUG",
    "TRACE",
]

# Python `logging` level names → LogLens canonical display level.
LOGGING_ALIASES: dict[str, str] = {
    "WARNING": "WARN",
    "CRITICAL": "CRITICAL",
    "FATAL": "CRITICAL",
    "ERROR": "ERROR",
    "INFO": "INFO",
    "DEBUG": "DEBUG",
    "NOTSET": "INFO",
}


def canonical_level(level: str) -> str:
    """Normalize a (logging) level name to a LogLens display level."""
    up = level.upper()
    return LOGGING_ALIASES.get(up, up)


WEB_COLORS: dict[str, str] = {
    "EMERGENCY": "#ff2d55",
    "FATAL": "#ff375f",
    "CRITICAL": "#ff453a",
    "ERROR": "#ff6b6b",
    "WARN": "#ffd60a",
    "WARNING": "#ffd60a",
    "NOTICE": "#ffe28a",
    "INFO": "#8b949e",
    "DEBUG": "#6e7681",
}
WEB_COLOR_DEFAULT = "#8b949e"

# Muted palette for chat cards (Teams/Slack theme colors).
CARD_COLORS: dict[str, str] = {
    "EMERGENCY": "#d13438",
    "FATAL": "#d13438",
    "CRITICAL": "#d13438",
    "ERROR": "#ff8c00",
    "WARN": "#ffd700",
}
CARD_COLOR_DEFAULT = "#0078d4"

# Emoji for chat cards.
EMOJI: dict[str, str] = {
    "EMERGENCY": "🟥",
    "ALERT": "🟥",
    "FATAL": "🟥",
    "CRITICAL": "🔴",
    "ERROR": "🟠",
    "WARN": "🟡",
}
EMOJI_DEFAULT = "🔵"

# Rich terminal styles for the CLI.
RICH_STYLES: dict[str, str] = {
    "EMERGENCY": "bold red",
    "ALERT": "bold red",
    "FATAL": "bold red",
    "CRITICAL": "bold red",
    "ERROR": "red",
    "WARN": "bold yellow",
    "WARNING": "bold yellow",
    "NOTICE": "yellow",
    "INFO": "dim",
    "DEBUG": "dim",
    "TRACE": "dim",
}
RICH_STYLE_DEFAULT = "white"
