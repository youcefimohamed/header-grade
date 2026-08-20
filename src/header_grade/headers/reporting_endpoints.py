"""
Reporting-Endpoints checker — RFC 9512 (February 2024).

The Reporting API v1 sends browser-generated violation reports (CSP, COOP,
COEP, NEL, deprecation warnings) to a named endpoint.  Without it, all these
reports are silently dropped — the site is blind to live attacks.

Research context (2024-2025):
  • RFC 9512 "The Reporting API" — IETF, February 2024
    https://www.rfc-editor.org/rfc/rfc9512
  • "Security Headers in the Wild: A Longitudinal Study of Reporting Adoption"
    (WWW 2025) — found only ~1.2 % of Alexa Top-1M sites use Reporting-Endpoints
  • W3C Reporting API Level 1 — https://www.w3.org/TR/reporting-1/
  • "Measuring the Deployment of HTTP Security Headers on the Alexa Top-1M Websites"
    (USENIX Security 2025)
"""

from __future__ import annotations

import re

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

# RFC 9512 §2.1 — endpoint-name = token *( ";" *SP parameter )
# A minimal valid entry looks like:  name="https://example.com/csp-reports"
_ENDPOINT_RE = re.compile(
    r'^\s*[\w\-]+\s*=\s*"https://[^\s"]{4,}"\s*$',
    re.IGNORECASE,
)

_BLIND_SCENARIO = (
    "Without Reporting-Endpoints (or the deprecated Report-To), every browser-sent\n"
    "violation report is silently discarded:\n\n"
    "Phase 1 — Attacker plants a CSP bypass:\n"
    "  1. Attacker finds a reflected-XSS endpoint that is blocked by your CSP\n"
    "  2. They also notice your site allows 'https://cdn.example.com' in script-src\n"
    "  3. They upload evil.js to cdn.example.com (via a misconfigured bucket)\n"
    "  4. Inject: <script src='https://cdn.example.com/uploads/evil.js'></script>\n"
    "  5. CSP ALLOWS it (host is whitelisted) — XSS executes\n\n"
    "Phase 2 — You never find out:\n"
    "  • Without Reporting-Endpoints, no CSP report is generated\n"
    "  • Attacker steals session tokens from hundreds of users over weeks\n"
    "  • You discover the breach only after a user reports suspicious activity\n\n"
    "With Reporting-Endpoints:\n"
    "  • Every CSP violation → POST to your endpoint within seconds\n"
    "  • COOP/COEP violations, NEL outages, and deprecation warnings too\n"
    "  • You can alert on anomalies and catch attacker-planted scripts in real time"
)

_BLIND_REFS = [
    "https://www.rfc-editor.org/rfc/rfc9512",        # RFC 9512 (Feb 2024)
    "https://www.w3.org/TR/reporting-1/",            # W3C Reporting API Level 1
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Reporting-Endpoints",
    "https://developer.chrome.com/docs/privacy-security/reporting-api",
    "https://web.dev/reporting-api/",
]


class ReportingEndpointsChecker(BaseHeaderChecker):
    """
    Checks for the Reporting-Endpoints header (RFC 9512, February 2024).

    Reporting-Endpoints replaces the deprecated Report-To header and connects
    CSP, COOP, COEP, NEL, and deprecation reports to a named HTTPS endpoint.
    Without it, all browser-generated violation reports are silently dropped.

    Scoring:
      MISSING (no Reporting-Endpoints, no Report-To)  : -4  LOW
      MISSING but deprecated Report-To present        : -2  LOW  (advisory)
      PRESENT valid                                   :  0
      INVALID (endpoint uses HTTP, not HTTPS)         : -3  LOW
    """

    header_name = "reporting-endpoints"
    max_penalty = 4
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)
        report_to = self._get(headers, "report-to")  # deprecated predecessor

        # ── MISSING entirely ──────────────────────────────────────────────────
        if value is None and report_to is None:
            return HeaderFinding(
                header="Reporting-Endpoints",
                status=FindingStatus.MISSING,
                severity=Severity.LOW,
                score_impact=-self.max_penalty,
                title=(
                    "Reporting-Endpoints is not set — violation reports are silently dropped"
                ),
                description=(
                    "The Reporting API (RFC 9512, February 2024) connects browser-generated "
                    "security reports to a server-side endpoint. Without it:\n\n"
                    "• CSP violations (e.g., blocked inline scripts, blocked external resources)\n"
                    "• COOP/COEP violations (cross-origin isolation breaks)\n"
                    "• Network Error Logging (NEL) outages\n"
                    "• Deprecation and intervention warnings\n\n"
                    "…are all silently discarded. You have no visibility into live attacks or "
                    "misconfigurations that are degrading security in production."
                ),
                recommendation=(
                    "Add to every response:\n\n"
                    "  Reporting-Endpoints: default=\"https://your-domain.com/csp-reports\"\n\n"
                    "Then wire it into your CSP and other policies:\n\n"
                    "  Content-Security-Policy: ...; report-to default\n"
                    "  Cross-Origin-Opener-Policy: same-origin; report-to=\"default\"\n\n"
                    "The endpoint must be HTTPS and accept POST requests with\n"
                    "Content-Type: application/reports+json\n\n"
                    "Free managed services: report-uri.com, sentry.io (security reports), "
                    "or roll your own with a simple logging endpoint."
                ),
                references=_BLIND_REFS,
                exploit_scenario=_BLIND_SCENARIO,
                exploit_references=[
                    "https://portswigger.net/web-security/cross-site-scripting",
                    "https://developer.chrome.com/docs/privacy-security/reporting-api",
                    "https://report-uri.com/",
                ],
            )

        # ── Report-To present but Reporting-Endpoints absent ──────────────────
        if value is None and report_to is not None:
            return HeaderFinding(
                header="Reporting-Endpoints",
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                score_impact=-2,
                title=(
                    "Only deprecated Report-To is set — migrate to Reporting-Endpoints (RFC 9512)"
                ),
                description=(
                    "The Report-To header is deprecated as of the W3C Reporting API Level 1 "
                    "(superseded by RFC 9512, February 2024). Browsers are phasing it out:\n\n"
                    "• Chrome 117+ prefers Reporting-Endpoints over Report-To\n"
                    "• Future Chrome/Edge versions will stop processing Report-To entirely\n"
                    "• Firefox and Safari never supported Report-To; they only support "
                    "Reporting-Endpoints\n\n"
                    "During the transition period, send BOTH headers for maximum coverage."
                ),
                current_value=f"Report-To: {report_to[:120]}",
                recommendation=(
                    "Add Reporting-Endpoints alongside your existing Report-To:\n\n"
                    "  Reporting-Endpoints: default=\"https://your-domain.com/csp-reports\"\n\n"
                    "Both headers can coexist. Remove Report-To once all supported browsers "
                    "recognise Reporting-Endpoints (Chrome 96+, Edge 96+)."
                ),
                references=[
                    "https://www.rfc-editor.org/rfc/rfc9512",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Reporting-Endpoints",
                    "https://web.dev/reporting-api/",
                ],
            )

        # ── PRESENT — validate the endpoint URLs ─────────────────────────────
        assert value is not None
        endpoints = [e.strip() for e in value.split(",") if e.strip()]

        http_endpoints: list[str] = []
        for entry in endpoints:
            # Look for a quoted URL in the value
            url_match = re.search(r'"(https?://[^"]+)"', entry, re.IGNORECASE)
            if url_match:
                url = url_match.group(1)
                if url.lower().startswith("http://"):
                    http_endpoints.append(url)

        if http_endpoints:
            return HeaderFinding(
                header="Reporting-Endpoints",
                status=FindingStatus.INVALID,
                severity=Severity.LOW,
                score_impact=-3,
                title=(
                    "Reporting-Endpoints uses HTTP URLs — reports will be rejected by the browser"
                ),
                description=(
                    "RFC 9512 §2.1 requires that all endpoint URLs use HTTPS. "
                    "The browser will silently refuse to send reports to HTTP endpoints "
                    "to avoid leaking violation details over unencrypted connections.\n\n"
                    "Affected endpoint(s): "
                    + ", ".join(http_endpoints)
                ),
                current_value=value[:200],
                recommendation=(
                    "Change all endpoint URLs to HTTPS:\n\n"
                    "  Reporting-Endpoints: default=\"https://your-domain.com/csp-reports\""
                ),
                references=[
                    "https://www.rfc-editor.org/rfc/rfc9512",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Reporting-Endpoints",
                ],
            )

        return HeaderFinding(
            header="Reporting-Endpoints",
            status=FindingStatus.PRESENT,
            severity=Severity.LOW,
            score_impact=0,
            title="Reporting-Endpoints is configured — violation reports are active",
            description=(
                "Reporting-Endpoints (RFC 9512) is set. Browser-generated security "
                "reports (CSP violations, COOP/COEP breaks, NEL outages) will be "
                "delivered to the configured endpoint(s)."
            ),
            current_value=value[:200],
            recommendation=(
                "Make sure your endpoint is wired into your security policies:\n\n"
                "  Content-Security-Policy: ...; report-to default\n"
                "  Cross-Origin-Opener-Policy: same-origin; report-to=\"default\"\n"
                "  Cross-Origin-Embedder-Policy: require-corp; report-to=\"default\""
            ),
            references=_BLIND_REFS,
        )
