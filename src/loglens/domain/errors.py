from __future__ import annotations


class LogLensError(Exception):
    """A predictable, user-facing error with a clean, friendly message.

    Raise this for problems the user can fix — bad input, the wrong ``--format``,
    a missing optional dependency, an unreadable source. The CLI entry point
    prints the message as a single ``[LogLens] …`` line and exits 1; it never
    shows a traceback for these. Keep the message short and actionable (what
    went wrong + what to try).
    """
