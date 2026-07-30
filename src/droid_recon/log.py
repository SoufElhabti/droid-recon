"""Bracket-tag console output, optionally tee'd to a session log.

Human progress goes to stderr; machine-readable JSON goes to stdout. This keeps
`droid-recon static x.apk > surface.json` clean while the operator still sees progress.
"""

from __future__ import annotations

import sys
from pathlib import Path

_LOG_FILE: Path | None = None
_QUIET = False


def set_log_file(path: Path | None) -> None:
    """Tee all subsequent output to `path` (append mode)."""
    global _LOG_FILE
    _LOG_FILE = path
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)


def set_quiet(quiet: bool) -> None:
    global _QUIET
    _QUIET = quiet


def _emit(tag: str, msg: str) -> None:
    line = f"[{tag}] {msg}"
    if not _QUIET:
        print(line, file=sys.stderr, flush=True)
    if _LOG_FILE is not None:
        with _LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def say(tag: str, msg: str) -> None:
    _emit(tag, msg)


def warn(msg: str) -> None:
    _emit("!", msg)


def ok(msg: str) -> None:
    _emit("+", msg)


def die(msg: str, code: int = 1) -> None:
    _emit("x", msg)
    raise SystemExit(code)
