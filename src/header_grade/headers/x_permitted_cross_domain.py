"""X-Permitted-Cross-Domain-Policies checker."""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

# Values that allow some or all cross-domain access — risky
_PERMISSIVE = {"all", "master-only", "by-content-type", "by-ftp-filename"}
# The only safe value
_SAFE = "none"

_FLASH_SCENARIO = (
    "Adobe Flash cross-domain data theft:\n\n"
    "1. Attacker hosts evil.com/steal.swf (a Flash SWF file)\n"
    "2. Victim visits evil.com (while logged into victim's bank or app)\n"
    "3. steal.swf makes a cross-domain HTTP request to example.com/api/account\n"
    "4. Without X-Permitted-Cross-Domain-Policies: none, Flash checks for:\n"
    "   - https://example.com/crossdomain.xml\n"
    "   - If the file grants access (or server returns permissive defaults),\n"
    "     Flash reads the authenticated response\n"
    "5. Attacker's SWF sends extracted data back to evil.com\n\n"
    "Although Flash is EOL (Dec 2020), some enterprise environments still run\n"
    "legacy IE+Flash or Adobe Reader PDF viewers. The fix costs nothing — one header."
)

_FLASH_REFS = [
    "https://owasp.org/www-project-secure-headers/",
    "https://portswigger.net/web-security/cors",
    "https://helpx.adobe.com/flash-player/kb/cross-domain-policy-file-overview.html",
    "https://www.adobe.com/devnet-docs/acrobat/android/en/crossdomain.html",
]


class XPermittedCrossDomainPoliciesChecker(BaseHeaderChecker):
    """
    X-Permitted-Cross-Domain-Policies controls whether Adobe Flash,
    Adobe Reader, and legacy Silverlight clients can load data from
    your domain by reading a crossdomain.xml policy file.

    Attack prevented: cross-domain data theft via Flash/Silverlight SWF files
    embedded on attacker-controlled pages.

    Although Flash is end-of-life, some enterprise environments still run
    old plugin versions. Setting this to 'none' costs nothing and closes
    the vector permanently.
    """

    header_name = "x-permitted-cross-domain-policies"
    max_penalty = 4
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)

        if value is None:
            return HeaderFinding(
                header="X-Permitted-Cross-Domain-Policies",
                status=FindingStatus.MISSING,
                severity=Severity.LOW,
                score_impact=-self.max_penalty,
                title="X-Permitted-Cross-Domain-Policies is missing",
                description=(
                    "Without this header, Adobe Flash and legacy plugin runtimes apply "
                    "their own heuristics to decide whether cross-domain access is permitted. "
                    "An attacker with a Flash SWF on their site could load data from your "
                    "domain if any crossdomain.xml exists or if the plugin falls back to "
                    "permissive defaults. Setting 'none' prevents this entirely."
                ),
                recommendation=(
                    "Add the header:\n\n"
                    "  X-Permitted-Cross-Domain-Policies: none"
                ),
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Permitted-Cross-Domain-Policies",
                ],
                exploit_scenario=_FLASH_SCENARIO,
                exploit_references=_FLASH_REFS,
            )

        normalized = value.strip().lower()

        if normalized == _SAFE:
            return HeaderFinding(
                header="X-Permitted-Cross-Domain-Policies",
                status=FindingStatus.PRESENT,
                severity=Severity.LOW,
                score_impact=0,
                title="X-Permitted-Cross-Domain-Policies: none (correct)",
                description=(
                    "Flash/plugin cross-domain access is fully restricted. "
                    "No crossdomain.xml policy file will be honoured."
                ),
                current_value=value,
                references=["https://owasp.org/www-project-secure-headers/"],
            )

        if normalized in _PERMISSIVE:
            penalty = self.max_penalty if normalized == "all" else 3
            return HeaderFinding(
                header="X-Permitted-Cross-Domain-Policies",
                status=FindingStatus.WARNING,
                severity=Severity.MEDIUM if normalized == "all" else Severity.LOW,
                score_impact=-penalty,
                title=f"X-Permitted-Cross-Domain-Policies: '{value}' — allows cross-domain plugin access",
                description=(
                    f"The value '{value}' allows Flash/plugin SWF files on other domains "
                    "to load resources from your domain. "
                    + (
                        "  'all' means any cross-domain policy file is honoured — maximum exposure."
                        if normalized == "all"
                        else f"  '{normalized}' still permits plugin access under certain conditions."
                    )
                ),
                current_value=value,
                recommendation="Change to:\n\n  X-Permitted-Cross-Domain-Policies: none",
                references=["https://owasp.org/www-project-secure-headers/"],
                exploit_scenario=_FLASH_SCENARIO,
                exploit_references=_FLASH_REFS,
            )

        return HeaderFinding(
            header="X-Permitted-Cross-Domain-Policies",
            status=FindingStatus.INVALID,
            severity=Severity.LOW,
            score_impact=-2,
            title=f"X-Permitted-Cross-Domain-Policies has an unrecognised value: '{value}'",
            description=(
                f"'{value}' is not a valid token. Plugins may apply default behaviour."
            ),
            current_value=value,
            recommendation="Set to 'none'.",
            references=["https://owasp.org/www-project-secure-headers/"],
        )
