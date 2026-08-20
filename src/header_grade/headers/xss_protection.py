"""X-XSS-Protection checker (deprecated header)."""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker


class XSSProtectionChecker(BaseHeaderChecker):
    """
    X-XSS-Protection was an IE/Chrome heuristic XSS filter.
    It's deprecated and removed from modern browsers.
    Having it set to '1; mode=block' was once best practice;
    now it's neutral. Having '1' without mode=block can introduce
    new vulnerabilities in older browsers.
    """

    header_name = "x-xss-protection"
    max_penalty = 0   # missing is not penalised
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)

        if value is None:
            return HeaderFinding(
                header="X-XSS-Protection",
                status=FindingStatus.MISSING,
                severity=Severity.INFO,
                score_impact=0,
                title="X-XSS-Protection is not set (expected)",
                description=(
                    "X-XSS-Protection was a browser heuristic filter for XSS. "
                    "It has been deprecated and removed from Chrome, Firefox, and Edge. "
                    "Not setting it is the correct modern behaviour. "
                    "Use Content-Security-Policy instead."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
                ],
            )

        normalized = value.strip()
        if normalized == "0":
            return HeaderFinding(
                header="X-XSS-Protection",
                status=FindingStatus.PRESENT,
                severity=Severity.INFO,
                score_impact=0,
                title="X-XSS-Protection: 0 (filter disabled — fine)",
                description=(
                    "Setting X-XSS-Protection: 0 explicitly disables the old XSS filter, "
                    "which is safe and avoids the mode=block vulnerabilities in older IE. "
                    "Modern browsers ignore this header anyway."
                ),
                current_value=value,
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
                ],
            )

        if "1" in normalized and "mode=block" in normalized.lower():
            return HeaderFinding(
                header="X-XSS-Protection",
                status=FindingStatus.WARNING,
                severity=Severity.INFO,
                score_impact=0,
                title="X-XSS-Protection: 1; mode=block (deprecated but harmless)",
                description=(
                    "This was the old best-practice. Modern browsers (Chrome 78+, Firefox, Edge) "
                    "have removed this feature entirely — the header has no effect. "
                    "No action required, but consider removing it to reduce header bloat."
                ),
                current_value=value,
                recommendation="You can safely remove this header; rely on CSP for XSS protection.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
                ],
            )

        # X-XSS-Protection: 1 without mode=block is actively harmful in IE 8/9:
        # the filter rewrites the page to neutralise what it thinks is an XSS,
        # but the rewriting itself can introduce new script execution vectors.
        if normalized.strip() == "1":
            return HeaderFinding(
                header="X-XSS-Protection",
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                score_impact=-3,
                title="X-XSS-Protection: 1 (without mode=block) — can introduce XSS in IE",
                description=(
                    "Setting X-XSS-Protection: 1 (without 'mode=block') enabled the old IE/Chrome "
                    "XSS filter in 'sanitise and render' mode. The filter's rewriting has a "
                    "known class of vulnerabilities where it creates new XSS vectors while "
                    "trying to block others (CVE-2009-4078 pattern). Modern browsers have "
                    "removed this feature entirely."
                ),
                current_value=value,
                recommendation=(
                    "Set to 0 to disable it (safe) and rely on CSP for XSS protection:\n\n"
                    "  X-XSS-Protection: 0\n\n"
                    "Or remove the header entirely."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
                    "https://portswigger.net/daily-swig/xss-protection-header-not-as-effective-as-first-thought",
                ],
                exploit_scenario=(
                    "Internet Explorer 8/9 XSS filter bypass via filter rewriting:\n\n"
                    "1. Target page has a reflected parameter: page.html?name=value\n"
                    "2. IE's XSS filter scans the response looking for script patterns\n"
                    "3. When it finds one, it tries to 'neutralise' it by rewriting the HTML\n"
                    "4. The rewriting changes the DOM structure in predictable ways\n"
                    "5. An attacker crafts a payload that the filter rewrites INTO a\n"
                    "   working XSS vector:\n"
                    "     Input: <s<script>cript>alert(1)</script>\n"
                    "     Filter removes inner 'script' → leaves: <script>alert(1)</script>\n"
                    "6. The filter itself caused the XSS it was trying to prevent\n\n"
                    "This class of bugs was demonstrated by Masato Kinugawa and others\n"
                    "and is why X-XSS-Protection: 0 is now recommended over value '1'."
                ),
                exploit_references=[
                    "https://portswigger.net/daily-swig/xss-protection-header-not-as-effective-as-first-thought",
                    "https://cure53.de/fp170.pdf",
                    "https://blog.innerht.ml/the-misunderstood-x-xss-protection/",
                    "https://owasp.org/www-community/attacks/xss/",
                ],
            )

        return HeaderFinding(
            header="X-XSS-Protection",
            status=FindingStatus.WARNING,
            severity=Severity.INFO,
            score_impact=0,
            title=f"X-XSS-Protection: '{value}' (deprecated — remove it)",
            description=(
                "X-XSS-Protection is deprecated and ignored by Chrome, Firefox, and Edge. "
                "Remove it and use Content-Security-Policy instead."
            ),
            current_value=value,
            recommendation="Remove this header. Use Content-Security-Policy for XSS protection.",
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
            ],
        )
