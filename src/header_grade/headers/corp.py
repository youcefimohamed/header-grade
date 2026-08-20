"""Cross-Origin-Resource-Policy (CORP) checker."""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

_VALID_VALUES = {"same-site", "same-origin", "cross-origin"}


class CORPChecker(BaseHeaderChecker):
    """
    CORP tells browsers which origins can embed this resource,
    helping protect against cross-origin data leaks (e.g. Spectre).
    """

    header_name = "cross-origin-resource-policy"
    max_penalty = 5
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)

        if value is None:
            return HeaderFinding(
                header="Cross-Origin-Resource-Policy",
                status=FindingStatus.MISSING,
                severity=Severity.LOW,
                score_impact=-self.max_penalty,
                title="Cross-Origin-Resource-Policy (CORP) is missing",
                description=(
                    "CORP tells browsers whether this resource can be read cross-origin. "
                    "Without it, any page can embed your resources and — in the context of "
                    "Spectre-class attacks — potentially leak their contents."
                ),
                recommendation=(
                    "For resources that should only be used by your own site:\n\n"
                    "  Cross-Origin-Resource-Policy: same-origin\n\n"
                    "For same-site subdomains:\n\n"
                    "  Cross-Origin-Resource-Policy: same-site\n\n"
                    "For intentionally public resources (CDN assets):\n\n"
                    "  Cross-Origin-Resource-Policy: cross-origin"
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
                    "https://resourcepolicy.fyi/",
                ],
                exploit_scenario=(
                    "Cross-origin resource inclusion → Spectre pixel-stealing:\n\n"
                    "1. Attacker hosts evil.com which includes your private resource:\n"
                    "     <img src='https://api.example.com/user/avatar?id=123'>\n"
                    "2. Without CORP, the browser loads it into the page's process memory\n"
                    "3. Using Spectre-class CPU timing attacks (SharedArrayBuffer + Atomics),\n"
                    "   the attacker reads the resource bytes from cross-process memory\n"
                    "4. Private user data (avatars, documents, reports) is reconstructed\n\n"
                    "Also blocks XS-Search attacks where resource existence leaks information:\n"
                    "  - 404 vs 200 timing reveals whether a private object exists\n"
                    "  - The timing difference can be measured with a high-precision clock"
                ),
                exploit_references=[
                    "https://xsleaks.dev/docs/attacks/xs-leaks/",
                    "https://resourcepolicy.fyi/",
                    "https://spectreattack.com/",
                    "https://portswigger.net/research/xs-leak",
                    "https://web.dev/why-coop-coep/",
                ],
            )

        normalized = value.strip().lower()
        if normalized not in _VALID_VALUES:
            return HeaderFinding(
                header="Cross-Origin-Resource-Policy",
                status=FindingStatus.INVALID,
                severity=Severity.LOW,
                score_impact=-3,
                title=f"CORP has an unrecognised value: '{value}'",
                description="The value is not a valid CORP token and will be ignored.",
                current_value=value,
                recommendation="Use 'same-origin', 'same-site', or 'cross-origin'.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
                ],
            )

        return HeaderFinding(
            header="Cross-Origin-Resource-Policy",
            status=FindingStatus.PRESENT,
            severity=Severity.LOW,
            score_impact=0,
            title=f"Cross-Origin-Resource-Policy: {normalized}",
            description=f"Resources are restricted to '{normalized}' — Spectre-class leaks mitigated.",
            current_value=value,
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
            ],
        )
