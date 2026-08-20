"""Cross-Origin-Opener-Policy (COOP) checker."""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

_STRONG_VALUES = {"same-origin", "same-origin-allow-popups"}
_VALID_VALUES = _STRONG_VALUES | {"unsafe-none"}


class COOPChecker(BaseHeaderChecker):
    """
    COOP isolates your browsing context from cross-origin documents,
    enabling Spectre mitigations and cross-origin isolation.
    """

    header_name = "cross-origin-opener-policy"
    max_penalty = 5
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)

        if value is None:
            return HeaderFinding(
                header="Cross-Origin-Opener-Policy",
                status=FindingStatus.MISSING,
                severity=Severity.LOW,
                score_impact=-self.max_penalty,
                title="Cross-Origin-Opener-Policy (COOP) is missing",
                description=(
                    "COOP prevents cross-origin windows from accessing your window object, "
                    "isolating your browsing context. This is a prerequisite for enabling "
                    "SharedArrayBuffer and high-resolution timers, and helps mitigate "
                    "Spectre-type side-channel attacks."
                ),
                recommendation=(
                    "For full isolation:\n\n"
                    "  Cross-Origin-Opener-Policy: same-origin\n\n"
                    "If your app opens cross-origin popups:\n\n"
                    "  Cross-Origin-Opener-Policy: same-origin-allow-popups"
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
                    "https://web.dev/coop-coep/",
                ],
                exploit_scenario=(
                    "Without COOP, windows share an opener reference across origins:\n\n"
                    "XS-Leak via window.opener:\n"
                    "1. Attacker page at evil.com opens target.com via window.open()\n"
                    "2. If target.com loads without COOP, evil.com keeps a reference\n"
                    "   to target.com's window object\n"
                    "3. Attacker can probe: opener.frames.length, opener.history.length,\n"
                    "   opener.name — all cross-origin readable properties\n"
                    "4. By timing the load or counting frames, attacker infers the user's\n"
                    "   state on target.com (logged in? Has admin access? Owns item X?)\n\n"
                    "Spectre timing attack:\n"
                    "Without cross-origin isolation, SharedArrayBuffer is unavailable.\n"
                    "But without COOP, high-res timers via SharedArrayBuffer can be used\n"
                    "to perform cache-timing side-channel attacks reading cross-origin memory."
                ),
                exploit_references=[
                    "https://xsleaks.dev/",
                    "https://xsleaks.dev/docs/attacks/frame-counting/",
                    "https://portswigger.net/research/xs-leak",
                    "https://web.dev/coop-coep/",
                    "https://developer.chrome.com/blog/enabling-shared-array-buffer/",
                ],
            )

        normalized = value.strip().lower()
        if normalized not in _VALID_VALUES:
            return HeaderFinding(
                header="Cross-Origin-Opener-Policy",
                status=FindingStatus.INVALID,
                severity=Severity.LOW,
                score_impact=-3,
                title=f"COOP has an unrecognised value: '{value}'",
                description="The value is not a valid COOP token and will be ignored by browsers.",
                current_value=value,
                recommendation="Use 'same-origin' or 'same-origin-allow-popups'.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
                ],
            )

        if normalized == "unsafe-none":
            return HeaderFinding(
                header="Cross-Origin-Opener-Policy",
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                score_impact=-3,
                title="COOP is set to 'unsafe-none' (no isolation)",
                description=(
                    "'unsafe-none' is the default browser behaviour — it provides no isolation. "
                    "Setting it explicitly is harmless but pointless."
                ),
                current_value=value,
                recommendation="Change to 'same-origin' for actual cross-origin isolation.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
                ],
            )

        return HeaderFinding(
            header="Cross-Origin-Opener-Policy",
            status=FindingStatus.PRESENT,
            severity=Severity.LOW,
            score_impact=0,
            title=f"Cross-Origin-Opener-Policy: {normalized}",
            description="COOP is active — your browsing context is isolated from cross-origin openers.",
            current_value=value,
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
            ],
        )
