"""Strict-Transport-Security (HSTS) checker."""

from __future__ import annotations

import re

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

_MIN_MAX_AGE = 180 * 24 * 3600   # 180 days — minimum for preload
_GOOD_MAX_AGE = 365 * 24 * 3600  # 1 year

_SSLSTRIP_SCENARIO = (
    "1. User types 'example.com' in browser bar (no https:// prefix)\n"
    "2. Browser sends plain HTTP request: GET http://example.com/\n"
    "3. Network attacker (coffee-shop WiFi, ISP, rogue AP) intercepts the request\n"
    "4. Attacker replies with a fake HTTP page — user never reaches HTTPS\n"
    "5. sslstrip rewrites all HTTPS links on every subsequent page to HTTP,\n"
    "   keeping the victim on unencrypted HTTP indefinitely\n"
    "6. Attacker reads plaintext passwords, session cookies, and form data"
)

_SSLSTRIP_REFS = [
    "https://github.com/moxie0/sslstrip",
    "https://moxie.org/papers/sslstrip/",
    "https://owasp.org/www-community/attacks/SSL_Stripping",
    "https://portswigger.net/web-security/information-disclosure",
    "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/hsts",
]


class HSTSChecker(BaseHeaderChecker):
    """
    HSTS tells browsers to always use HTTPS for this domain,
    even if the user types http://.
    """

    header_name = "strict-transport-security"
    max_penalty = 25
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)

        if value is None:
            return HeaderFinding(
                header="Strict-Transport-Security",
                status=FindingStatus.MISSING,
                severity=Severity.CRITICAL,
                score_impact=-self.max_penalty,
                title="Strict-Transport-Security (HSTS) is missing",
                description=(
                    "Without HSTS, users visiting http:// are vulnerable to SSL-stripping "
                    "attacks — a MITM can intercept the initial HTTP request before the "
                    "redirect to HTTPS happens. HSTS instructs browsers to never send "
                    "plain HTTP requests to your domain."
                ),
                recommendation=(
                    "Add the header — start with a short max-age during testing:\n\n"
                    "  Strict-Transport-Security: max-age=300\n\n"
                    "Once confident, increase to at least 1 year and add includeSubDomains:\n\n"
                    "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\n"
                    "Then submit your domain to https://hstspreload.org/ for browser-level preloading."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                    "https://hstspreload.org/",
                ],
                exploit_scenario=_SSLSTRIP_SCENARIO,
                exploit_references=_SSLSTRIP_REFS,
            )

        max_age = _parse_max_age(value)
        has_include_subdomains = "includesubdomains" in value.lower()
        has_preload = "preload" in value.lower()

        if max_age is None:
            return HeaderFinding(
                header="Strict-Transport-Security",
                status=FindingStatus.INVALID,
                severity=Severity.CRITICAL,
                score_impact=-20,
                title="HSTS header is malformed (no valid max-age)",
                description=(
                    "The Strict-Transport-Security header is present but the browser "
                    "cannot parse a max-age directive. A malformed HSTS header is "
                    "treated as absent by compliant browsers."
                ),
                current_value=value,
                recommendation=(
                    "Ensure the header includes a numeric max-age:\n\n"
                    "  Strict-Transport-Security: max-age=31536000; includeSubDomains"
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
                ],
                exploit_scenario=_SSLSTRIP_SCENARIO,
                exploit_references=_SSLSTRIP_REFS,
            )

        # max-age=0 is an active HSTS opt-out — it instructs browsers to DELETE
        # any cached HSTS record for the domain, re-enabling HTTP downgrade attacks.
        if max_age == 0:
            return HeaderFinding(
                header="Strict-Transport-Security",
                status=FindingStatus.INVALID,
                severity=Severity.CRITICAL,
                score_impact=-self.max_penalty,
                title="HSTS max-age=0 — actively removes HSTS protection from browsers!",
                description=(
                    "max-age=0 tells browsers to immediately DELETE their stored HSTS "
                    "record for this domain. Any user who previously had HSTS cached will "
                    "lose that protection, making them vulnerable again to SSL-stripping "
                    "and HTTP downgrade attacks. This is the correct way to intentionally "
                    "opt OUT of HSTS — but almost certainly a misconfiguration here."
                ),
                current_value=value,
                recommendation=(
                    "If this is unintentional, set a long max-age:\n\n"
                    "  Strict-Transport-Security: max-age=31536000; includeSubDomains\n\n"
                    "Only use max-age=0 deliberately if you are decommissioning HSTS."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                    "https://tools.ietf.org/html/rfc6797#section-6.1.1",
                ],
                exploit_scenario=(
                    "An attacker who can briefly inject a response (MITM on first HTTP visit,\n"
                    "XSS, or DNS spoofing) sends:\n\n"
                    "  Strict-Transport-Security: max-age=0\n\n"
                    "Every browser that receives this immediately DELETES its cached HSTS\n"
                    "pin for the domain. From that point, subsequent visits to http:// are\n"
                    "no longer force-upgraded — the SSL-stripping window reopens.\n\n"
                    "This is the HSTS 'opt-out' attack described in RFC 6797 §14.4."
                ),
                exploit_references=_SSLSTRIP_REFS,
            )

        if max_age < 86400:  # < 1 day
            return HeaderFinding(
                header="Strict-Transport-Security",
                status=FindingStatus.WARNING,
                severity=Severity.HIGH,
                score_impact=-15,
                title=f"HSTS max-age is dangerously short ({max_age}s — {max_age // 3600}h)",
                description=(
                    f"A max-age of {max_age} seconds ({max_age // 3600} hours) means browsers "
                    "stop enforcing HSTS shortly after each visit. A gap between visits leaves "
                    "users exposed to SSL-stripping attacks. Minimum recommended: 31536000 (1 year)."
                ),
                current_value=value,
                recommendation="Set max-age to at least 31536000 (1 year).",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
                ],
                exploit_scenario=(
                    f"A user visits the site, gets HSTS cached for {max_age // 3600} hour(s).\n"
                    "If they don't return within that window, the HSTS pin expires.\n"
                    "On the next visit, the browser again sends plain HTTP — sslstrip\n"
                    "can intercept that gap and silently downgrade the connection.\n\n"
                    "For infrequent users (weekly/monthly logins), this creates a wide window."
                ),
                exploit_references=_SSLSTRIP_REFS,
            )

        # preload without includeSubDomains is invalid for preload list inclusion
        if has_preload and not has_include_subdomains:
            return HeaderFinding(
                header="Strict-Transport-Security",
                status=FindingStatus.WARNING,
                severity=Severity.MEDIUM,
                score_impact=-5,
                title="HSTS 'preload' requires 'includeSubDomains' — currently invalid for preloading",
                description=(
                    "The 'preload' directive signals intent to join the HSTS preload list "
                    "(browsers that preload your domain never send HTTP). However, preload "
                    "list requirements mandate 'includeSubDomains'. Without it, your domain "
                    "will be rejected by https://hstspreload.org/."
                ),
                current_value=value,
                recommendation=(
                    "Add includeSubDomains:\n\n"
                    "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                ),
                references=[
                    "https://hstspreload.org/",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                ],
            )

        impact = -5 if max_age < _MIN_MAX_AGE else 0

        notes: list[str] = []
        if not has_include_subdomains:
            notes.append("Consider adding 'includeSubDomains' to protect all subdomains.")
        if not has_preload and max_age >= _MIN_MAX_AGE and has_include_subdomains:
            notes.append(
                "You qualify for HSTS preloading — add 'preload' and submit to "
                "https://hstspreload.org/ to be hardcoded into browsers."
            )

        recommendation = "\n".join(notes) if notes else None
        status = FindingStatus.PRESENT if impact == 0 else FindingStatus.WARNING

        return HeaderFinding(
            header="Strict-Transport-Security",
            status=status,
            severity=Severity.CRITICAL,  # always mark as critical-category header
            score_impact=impact,
            title="Strict-Transport-Security is set"
            + (f" (max-age={max_age}s)" if impact else ""),
            description=(
                f"HSTS is active with max-age={max_age}s"
                + (", includeSubDomains" if has_include_subdomains else "")
                + (", preload" if has_preload else "")
                + "."
            ),
            current_value=value,
            recommendation=recommendation,
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                "https://hstspreload.org/",
            ],
        )


def _parse_max_age(value: str) -> int | None:
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    return int(match.group(1)) if match else None
