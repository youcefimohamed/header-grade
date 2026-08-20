"""Shared console factory — UTF-8 safe on Windows."""

from __future__ import annotations

import io
import sys

from rich.console import Console


def make_console(stderr: bool = False) -> Console:
    """
    Return a Rich Console that always writes UTF-8, even on Windows terminals
    whose default encoding is cp1252.

    Without this wrapper, any Unicode character outside cp1252 (em-dashes,
    box-drawing chars, emoji …) causes a UnicodeEncodeError on the legacy
    Windows renderer.
    """
    target = sys.stderr if stderr else sys.stdout
    if hasattr(target, "buffer"):
        file: io.TextIOWrapper = io.TextIOWrapper(
            target.buffer, encoding="utf-8", newline=""
        )
        return Console(file=file, highlight=False)
    return Console(file=target, highlight=False, stderr=stderr)
