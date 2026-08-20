"""X-Frame-Options checker."""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

_VALID_VALUES = {"deny", "sameorigin"}

_CLICKJACK_SCENARIO = (
    "1. Attacker creates: https://evil.com/prize.html\n"
    "2. Page embeds your site in a transparent iframe (opacity: 0) over a 'Click to win!' button\n"
    "3. Victim sees the fake button and clicks it\n"
    "4. The click lands on your site's 'Confirm Transfer' / 'Delete Account' / 'Follow' button\n"
    "5. Action executes with the victim's authenticated session — no credentials needed\n\n"
    "Real-world cases:\n"
    "• 2009 Twitter 'Don't Click' worm spread via clickjacked retweet buttons\n"
    "• Adobe Flash settings page clickjacking gave attackers camera/mic access\n"
    "• Facebook 'Like' button abuse drove millions of fake engagement interactions"
)

_CLICKJACK_REFS = [
    "https://portswigger.net/web-security/clickjacking",
    "https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected",
    "https://owasp.org/www-community/attacks/Clickjacking",
    "https://www.w3.org/Security/wiki/Clickjacking_Threats",
    "https://github.com/samyk/clickjacking",
]


class XFrameChecker(BaseHeaderChecker):
    """
    X-Frame-Options prevents the page from being embedded in an iframe,
    blocking clickjacking attacks.

    Note: CSP frame-ancestors is the modern replacement. We give credit
    if either is configured correctly.
    """

    header_name = "x-frame-options"
    max_penalty = 15
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        xfo_value = self._get(headers)
        csp_value = self._get(headers, "content-security-policy")

        # Check if CSP frame-ancestors covers this
        csp_covers = _csp_has_frame_ancestors(csp_value)

        if xfo_value is None and not csp_covers:
            return HeaderFinding(
                header="X-Frame-Options",
                status=FindingStatus.MISSING,
                severity=Severity.HIGH,
                score_impact=-self.max_penalty,
                title="X-Frame-Options is missing (no CSP frame-ancestors either)",
                description=(
                    "Without X-Frame-Options or CSP frame-ancestors, your page can be "
                    "embedded in an iframe on any malicious site. Attackers use this for "
                    "clickjacking — overlaying invisible frames to trick users into clicking "
                    "buttons they can't see."
                ),
                recommendation=(
                    "Modern approach (CSP):\n\n"
                    "  Content-Security-Policy: frame-ancestors 'self';\n\n"
                    "Legacy fallback (still supported by all browsers):\n\n"
                    "  X-Frame-Options: DENY\n\n"
                    "Use both for maximum compatibility."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
                    "https://owasp.org/www-community/attacks/Clickjacking",
                ],
                exploit_scenario=_CLICKJACK_SCENARIO,
                exploit_references=_CLICKJACK_REFS,
            )

        if csp_covers and xfo_value is None:
            return HeaderFinding(
                header="X-Frame-Options",
                status=FindingStatus.PRESENT,
                severity=Severity.HIGH,
                score_impact=0,
                title="Clickjacking protection via CSP frame-ancestors",
                description=(
                    "The CSP header includes a frame-ancestors directive, which is the "
                    "modern replacement for X-Frame-Options and takes precedence in "
                    "browsers that support it."
                ),
                recommendation=(
                    "For older browser compatibility, also add:\n\n"
                    "  X-Frame-Options: DENY  (or SAMEORIGIN)"
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"
                ],
            )

        # XFO is set — validate value
        normalized = (xfo_value or "").strip().lower()
        if normalized not in _VALID_VALUES and not normalized.startswith("allow-from"):
            return HeaderFinding(
                header="X-Frame-Options",
                status=FindingStatus.INVALID,
                severity=Severity.HIGH,
                score_impact=-10,
                title=f"X-Frame-Options has an invalid value: '{xfo_value}'",
                description=(
                    "The X-Frame-Options header is present but the value is not recognized. "
                    "Browsers treat an unrecognized value differently — some ignore the header "
                    "entirely, leaving the page vulnerable to clickjacking."
                ),
                current_value=xfo_value,
                recommendation="Set it to 'DENY' or 'SAMEORIGIN'.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                ],
                exploit_scenario=_CLICKJACK_SCENARIO,
                exploit_references=_CLICKJACK_REFS,
            )

        if "allow-from" in normalized:
            return HeaderFinding(
                header="X-Frame-Options",
                status=FindingStatus.WARNING,
                severity=Severity.HIGH,
                score_impact=-5,
                title="X-Frame-Options uses deprecated ALLOW-FROM",
                description=(
                    "ALLOW-FROM is not supported in modern browsers (Chrome, Firefox, Edge "
                    "all dropped it). Use CSP frame-ancestors instead."
                ),
                current_value=xfo_value,
                recommendation=(
                    "Replace with:\n\n"
                    "  Content-Security-Policy: frame-ancestors 'self' https://trusted.example.com;"
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                ],
                exploit_scenario=(
                    "Browsers that dropped ALLOW-FROM support (Chrome, Firefox 18+, Edge)\n"
                    "ignore this header entirely when they see an unsupported value.\n"
                    "The page behaves as if no X-Frame-Options is set at all,\n"
                    "making it fully embeddable and vulnerable to clickjacking."
                ),
                exploit_references=_CLICKJACK_REFS,
            )

        return HeaderFinding(
            header="X-Frame-Options",
            status=FindingStatus.PRESENT,
            severity=Severity.HIGH,
            score_impact=0,
            title=f"X-Frame-Options: {normalized.upper()}",
            description=(
                f"Clickjacking protection is active — this page cannot be embedded in "
                f"a third-party iframe (value: {normalized.upper()})."
            ),
            current_value=xfo_value,
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
            ],
        )


def _csp_has_frame_ancestors(csp: str | None) -> bool:
    if not csp:
        return False
    directives = {d.strip().lower().split()[0] for d in csp.split(";") if d.strip()}
    return "frame-ancestors" in directives
