"""Referrer-Policy checker."""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

# Policies that don't leak path/query strings cross-origin
_STRONG = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",  # Chrome's default since v85 — recommended
}
# Policies that leak the full URL to cross-origin HTTPS destinations
_MEDIUM = {
    "no-referrer-when-downgrade",  # sends FULL URL cross-HTTPS — old default, now deprecated
}
_WEAK = {
    "origin",
    "origin-when-cross-origin",
    "unsafe-url",
}
_ALL_VALID = _STRONG | _MEDIUM | _WEAK | {""}

_REFERER_LEAK_SCENARIO = (
    "Token leakage via Referer header:\n\n"
    "1. User receives password-reset link: https://example.com/reset?token=SECRET123\n"
    "2. They click it and the reset page loads a third-party analytics script\n"
    "3. Browser sends the analytics request with:\n"
    "     Referer: https://example.com/reset?token=SECRET123\n"
    "4. Analytics server logs the full URL — token now in a third-party database\n"
    "5. Attacker with analytics access (or a breach) extracts the token\n"
    "6. Token replayed → account takeover without password knowledge\n\n"
    "Same attack applies to: session IDs in URLs, OAuth codes, API keys in query strings."
)

_REFERER_REFS = [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    "https://portswigger.net/web-security/information-disclosure",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture",
    "https://web.dev/referrer-best-practices/",
    "https://github.com/dxa4481/Pastejacking",
]


class ReferrerPolicyChecker(BaseHeaderChecker):
    """
    Referrer-Policy controls how much of the URL is included in the
    Referer header when navigating away from your site.
    """

    header_name = "referrer-policy"
    max_penalty = 10
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)

        if value is None:
            return HeaderFinding(
                header="Referrer-Policy",
                status=FindingStatus.MISSING,
                severity=Severity.MEDIUM,
                score_impact=-self.max_penalty,
                title="Referrer-Policy is missing",
                description=(
                    "Without Referrer-Policy the browser defaults to "
                    "'no-referrer-when-downgrade', which sends the full URL (including "
                    "query strings with tokens or IDs) to third-party sites over HTTPS. "
                    "This can leak sensitive information to analytics, CDNs, and external "
                    "resources you embed."
                ),
                recommendation=(
                    "Recommended — strict origin only, no path leaked cross-site:\n\n"
                    "  Referrer-Policy: strict-origin-when-cross-origin\n\n"
                    "Or for maximum privacy:\n\n"
                    "  Referrer-Policy: no-referrer"
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                    "https://web.dev/referrer-best-practices/",
                ],
                exploit_scenario=_REFERER_LEAK_SCENARIO,
                exploit_references=_REFERER_REFS,
            )

        # A policy can list multiple comma-separated tokens (fallback chain)
        tokens = [t.strip().lower() for t in value.split(",")]
        effective = tokens[0]  # browsers use the first recognised value

        if effective == "unsafe-url":
            return HeaderFinding(
                header="Referrer-Policy",
                status=FindingStatus.WARNING,
                severity=Severity.MEDIUM,
                score_impact=-8,
                title="Referrer-Policy is set to 'unsafe-url' — sends full URL everywhere",
                description=(
                    "'unsafe-url' always sends the full URL (scheme + host + path + query) "
                    "in the Referer header, even across origins and over HTTP. "
                    "This leaks URL-embedded tokens, session IDs, and user data to "
                    "every external resource on your page."
                ),
                current_value=value,
                recommendation=(
                    "Change to:\n\n"
                    "  Referrer-Policy: strict-origin-when-cross-origin"
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
                ],
                exploit_scenario=_REFERER_LEAK_SCENARIO,
                exploit_references=_REFERER_REFS,
            )

        if effective == "no-referrer-when-downgrade":
            return HeaderFinding(
                header="Referrer-Policy",
                status=FindingStatus.WARNING,
                severity=Severity.MEDIUM,
                score_impact=-6,
                title="Referrer-Policy: no-referrer-when-downgrade — leaks full URL cross-origin",
                description=(
                    "'no-referrer-when-downgrade' was the old browser default (before Chrome 85 "
                    "changed it in 2020). It sends the full URL — including path and query "
                    "strings — to all cross-origin HTTPS destinations. This means every "
                    "third-party script, analytics service, CDN, and external link on your "
                    "page can see sensitive URL parameters like reset tokens, session IDs, "
                    "and user identifiers."
                ),
                current_value=value,
                recommendation=(
                    "Switch to the modern recommended policy:\n\n"
                    "  Referrer-Policy: strict-origin-when-cross-origin\n\n"
                    "This sends only the origin (no path/query) to cross-origin destinations "
                    "while preserving the full URL for same-origin requests."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                    "https://web.dev/referrer-best-practices/",
                ],
                exploit_scenario=_REFERER_LEAK_SCENARIO,
                exploit_references=_REFERER_REFS,
            )

        if effective in _WEAK:
            return HeaderFinding(
                header="Referrer-Policy",
                status=FindingStatus.WARNING,
                severity=Severity.MEDIUM,
                score_impact=-7,
                title=f"Referrer-Policy '{effective}' leaks URL information cross-origin",
                description=(
                    f"'{effective}' sends sensitive URL data to external sites. "
                    "For most applications, this is unnecessary and risks leaking "
                    "tokens, user IDs, or internal path structure in the Referer header."
                ),
                current_value=value,
                recommendation="Change to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
                ],
                exploit_scenario=_REFERER_LEAK_SCENARIO,
                exploit_references=_REFERER_REFS,
            )

        if effective not in _STRONG:
            return HeaderFinding(
                header="Referrer-Policy",
                status=FindingStatus.INVALID,
                severity=Severity.MEDIUM,
                score_impact=-8,
                title=f"Referrer-Policy has an unknown value: '{effective}'",
                description=(
                    f"'{effective}' is not a recognised Referrer-Policy token. "
                    "Browsers fall back to their default when the value is unrecognised."
                ),
                current_value=value,
                recommendation="Use one of: no-referrer, same-origin, strict-origin, strict-origin-when-cross-origin.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
                ],
            )

        return HeaderFinding(
            header="Referrer-Policy",
            status=FindingStatus.PRESENT,
            severity=Severity.MEDIUM,
            score_impact=0,
            title=f"Referrer-Policy: {effective}",
            description=f"Referrer information is restricted to '{effective}', limiting cross-site URL leakage.",
            current_value=value,
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
            ],
        )
