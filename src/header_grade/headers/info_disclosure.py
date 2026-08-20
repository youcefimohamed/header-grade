"""Information disclosure checker — server fingerprinting headers."""

from __future__ import annotations

import re

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

# Headers that reveal tech-stack info and should be removed or stripped of versions
_DISCLOSURE_HEADERS = [
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-drupal-cache",
    "x-wordpress-theme",
    "x-pingback",
    "x-shopify-stage",
    "via",
]

# Pattern to detect version numbers in Server header values
_VERSION_RE = re.compile(r"[\d]+\.[\d]+", re.ASCII)


class InfoDisclosureChecker(BaseHeaderChecker):
    """
    Detects headers that reveal server software, versions, or tech stack.
    Attackers use this information to target known vulnerabilities.
    """

    header_name = "server"
    max_penalty = 8
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        # --- Check for high-value disclosure headers ---
        found_disclosure: list[tuple[str, str]] = []
        for h in _DISCLOSURE_HEADERS:
            val = self._get(headers, h)
            if val:
                found_disclosure.append((h, val))

        # --- Check Server header ---
        server = self._get(headers, "server")
        server_leaks_version = bool(
            server and _VERSION_RE.search(server)
        )

        total_penalty = 0
        issues: list[str] = []

        if server_leaks_version and server:
            total_penalty += 4
            issues.append(
                f"[bold]Server: {server}[/bold] — reveals software version "
                "(attackers look up CVEs for this exact version)"
            )

        for header, val in found_disclosure:
            total_penalty += 3
            issues.append(
                f"[bold]{header}: {val[:60]}[/bold] — exposes tech-stack details"
            )

        total_penalty = min(total_penalty, self.max_penalty)

        if not issues:
            # Server present but no version / no disclosure headers
            description = "No sensitive server information is being leaked in response headers."
            if server:
                description = (
                    f"Server header is set to '{server}' but does not reveal a version number."
                )
            return HeaderFinding(
                header="Server / Info Disclosure",
                status=FindingStatus.PRESENT,
                severity=Severity.INFO,
                score_impact=0,
                title="No server-version information disclosure detected",
                description=description,
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                ],
            )

        description = (
            "The following response headers reveal server software or tech-stack "
            "information that attackers use to identify and target known vulnerabilities:\n\n"
            + "\n".join(f"• {i}" for i in issues)
        )

        all_headers = ", ".join(h for h, _ in found_disclosure)
        if server_leaks_version:
            all_headers = f"Server (version), {all_headers}".strip(", ")

        return HeaderFinding(
            header="Server / Info Disclosure",
            status=FindingStatus.WARNING,
            severity=Severity.MEDIUM,
            score_impact=-total_penalty,
            title=f"Server fingerprinting headers detected: {all_headers}",
            description=description,
            recommendation=(
                "Remove or redact version information from all server headers:\n\n"
                "Nginx:   server_tokens off;\n"
                "Apache:  ServerTokens Prod\n"
                "         ServerSignature Off\n"
                "Express: app.disable('x-powered-by');\n"
                "         (or use helmet which removes it automatically)\n"
                "PHP:     expose_php = Off  (in php.ini)\n"
                "ASP.NET: <httpRuntime enableVersionHeader='false' />\n"
                "         Remove 'X-Powered-By' via web.config"
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server",
            ],
            exploit_scenario=(
                "Automated reconnaissance workflow:\n\n"
                "1. Attacker scans target: Server: Apache/2.4.49\n"
                "2. Looks up CVE database: CVE-2021-41773 — Path traversal in Apache 2.4.49\n"
                "3. Runs exploit: curl 'https://example.com/cgi-bin/.%%2e/.%%2e/etc/passwd'\n"
                "4. Gets /etc/passwd — full server compromise, RCE possible\n\n"
                "Real examples:\n"
                "• Apache 2.4.49 (CVE-2021-41773) — path traversal / RCE, exploited in the wild\n"
                "• PHP 8.1.0-dev (CVE-2021-29921) — backdoor in dev build\n"
                "• x-powered-by: Express 4.17.1 → known prototype pollution chains\n"
                "• x-generator: WordPress 5.x → targeted WP vulnerability scanners (WPScan)"
            ),
            exploit_references=[
                "https://www.exploit-db.com/",
                "https://nvd.nist.gov/vuln/search",
                "https://github.com/wpscanteam/wpscan",
                "https://github.com/Tuhinshubhra/CMSeeK",
                "https://owasp.org/www-community/controls/Information_Exposure_Through_an_Error_Message",
            ],
        )
