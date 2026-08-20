"""Cache-Control security checker."""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

# Directives that prevent sensitive content from being stored
_SAFE_DIRECTIVES = {"no-store", "no-cache", "private", "must-revalidate"}

_WCD_SCENARIO = (
    "Web Cache Deception Attack (Omer Gil, 2017):\n\n"
    "1. Target site has no Cache-Control on /account/profile (serves user PII)\n"
    "2. Attacker sends victim a link: https://example.com/account/profile/nonexistent.css\n"
    "3. Server ignores the suffix and serves /account/profile response\n"
    "4. CDN/proxy sees .css extension → caches the response as a static asset\n"
    "5. Attacker fetches the same URL without authentication\n"
    "6. CDN serves the CACHED authenticated profile page → PII exposed\n\n"
    "Affected sites: PayPal, OpenAI, GitLab, and dozens of Fortune 500 companies."
)

_WCD_REFS = [
    "https://portswigger.net/web-security/web-cache-deception",
    "https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-path-mapping",
    "https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html",
    "https://cvedetails.com/cve/CVE-2017-9415/",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses",
]


class CacheControlChecker(BaseHeaderChecker):
    """
    Checks whether Cache-Control is configured to prevent sensitive
    responses from being stored in shared caches (proxies, CDNs) or
    the browser's disk cache.
    """

    header_name = "cache-control"
    max_penalty = 5
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)

        if value is None:
            # Check Pragma (legacy)
            pragma = self._get(headers, "pragma")
            if pragma and "no-cache" in pragma.lower():
                return HeaderFinding(
                    header="Cache-Control",
                    status=FindingStatus.WARNING,
                    severity=Severity.LOW,
                    score_impact=-3,
                    title="Only legacy Pragma: no-cache is set — Cache-Control is missing",
                    description=(
                        "Pragma: no-cache is an HTTP/1.0 header. Modern browsers and "
                        "proxies rely on Cache-Control. Without Cache-Control, "
                        "responses may be cached despite the Pragma header."
                    ),
                    current_value=f"Pragma: {pragma}",
                    recommendation=(
                        "Add Cache-Control alongside Pragma:\n\n"
                        "  Cache-Control: no-store, no-cache, must-revalidate\n"
                        "  Pragma: no-cache"
                    ),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
                    ],
                    exploit_scenario=_WCD_SCENARIO,
                    exploit_references=_WCD_REFS,
                )

            return HeaderFinding(
                header="Cache-Control",
                status=FindingStatus.MISSING,
                severity=Severity.LOW,
                score_impact=-self.max_penalty,
                title="Cache-Control is not set",
                description=(
                    "Without Cache-Control, browsers and proxies apply their own "
                    "heuristics to decide what to cache. For pages containing "
                    "user-specific content, session tokens, or sensitive data, "
                    "this can result in private information being stored in shared "
                    "caches or the browser's disk cache and exposed to other users."
                ),
                recommendation=(
                    "For authenticated / sensitive pages:\n\n"
                    "  Cache-Control: no-store, no-cache, must-revalidate\n\n"
                    "For public, static assets (CSS, JS, images):\n\n"
                    "  Cache-Control: public, max-age=31536000, immutable"
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses",
                ],
                exploit_scenario=_WCD_SCENARIO,
                exploit_references=_WCD_REFS,
            )

        directives = {d.strip().lower() for d in value.split(",")}

        if "public" in directives and not directives & {"no-store", "no-cache"}:
            return HeaderFinding(
                header="Cache-Control",
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                score_impact=-3,
                title="Cache-Control: public — ensure this page contains no sensitive data",
                description=(
                    "Cache-Control: public allows CDNs and shared proxies to cache this "
                    "response and serve it to any user. This is perfectly fine for static "
                    "assets but dangerous for authenticated or personalised content."
                ),
                current_value=value,
                recommendation=(
                    "For authenticated content, change to:\n\n"
                    "  Cache-Control: no-store, no-cache, must-revalidate\n\n"
                    "For public static assets, the current value is correct."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
                ],
                exploit_scenario=_WCD_SCENARIO,
                exploit_references=_WCD_REFS,
            )

        return HeaderFinding(
            header="Cache-Control",
            status=FindingStatus.PRESENT,
            severity=Severity.LOW,
            score_impact=0,
            title=f"Cache-Control: {value}",
            description="Cache-Control is configured.",
            current_value=value,
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
            ],
        )
