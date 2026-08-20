"""Base class for all header checkers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import HeaderFinding


class BaseHeaderChecker(ABC):
    """
    Every concrete checker implements `check(headers)` and returns a
    HeaderFinding that describes whether the header is good, weak, or
    missing — and exactly what to do about it.
    """

    # Subclasses set these as class attributes
    header_name: str = ""          # canonical HTTP header name (lowercase)
    max_penalty: int = 0           # points deducted when missing/invalid
    bonus: int = 0                 # extra points when perfectly configured

    @abstractmethod
    def check(self, headers: dict[str, str]) -> HeaderFinding:
        """
        Evaluate one or more headers from the response.

        Args:
            headers: All response headers, keys already lowercased.

        Returns:
            A HeaderFinding with the result.
        """

    def _get(self, headers: dict[str, str], name: str | None = None) -> str | None:
        """Retrieve a header value (case-insensitive)."""
        key = (name or self.header_name).lower()
        return headers.get(key)
