"""Deprecated and dangerous header detector.

Checks for headers that should NOT be present:
  - Public-Key-Pins (HPKP) — can permanently lock users out of your site
  - Expect-CT — obsolete since CT is now mandatory for all public certs
  - P3P — dead privacy standard, ignored by all modern browsers
"""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker


class DeprecatedHeadersChecker(BaseHeaderChecker):
    """
    Detects HTTP response headers that are deprecated, dangerous, or obsolete
    and should be removed from production servers.

    Unlike most checkers, a MISSING result here is the CORRECT state.
    """

    header_name = "public-key-pins"
    max_penalty = 0   # missing = correct; present = penalty
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        issues: list[tuple[str, str, int]] = []  # (header, description, penalty)

        # ── HPKP — the most dangerous ────────────────────────────────────────
        hpkp = self._get(headers, "public-key-pins")
        hpkp_ro = self._get(headers, "public-key-pins-report-only")

        if hpkp:
            max_age_hpkp = _extract_max_age(hpkp)
            if max_age_hpkp and max_age_hpkp > 0:
                issues.append((
                    "Public-Key-Pins",
                    (
                        "HPKP (HTTP Public Key Pinning) is an extremely dangerous deprecated "
                        "header. A single misconfiguration — wrong key, expired cert, lost "
                        "CA — can permanently render your site unreachable for all users who "
                        "visited during the pinning window. Chrome removed HPKP support in "
                        "v67 (2018), Firefox in v72 (2020). The header serves no purpose in "
                        "modern browsers and actively harms users on legacy ones."
                    ),
                    8,
                ))
            else:
                # max-age=0 is the intentional removal of a pin — acknowledge it
                issues.append((
                    "Public-Key-Pins",
                    "HPKP is present with max-age=0 (opt-out / removal). "
                    "Safe to remove the header entirely — no browser enforces it anymore.",
                    2,
                ))

        if hpkp_ro:
            issues.append((
                "Public-Key-Pins-Report-Only",
                "HPKP report-only is set. No browser processes HPKP reports anymore. "
                "This header is dead weight — remove it.",
                1,
            ))

        # ── Expect-CT ─────────────────────────────────────────────────────────
        expect_ct = self._get(headers, "expect-ct")
        if expect_ct:
            # Expect-CT with enforce is the dangerous variant
            if "enforce" in expect_ct.lower():
                issues.append((
                    "Expect-CT",
                    (
                        "Expect-CT with 'enforce' is set. This header was deprecated by "
                        "Chrome in January 2022 and ignored by all modern browsers — "
                        "Certificate Transparency is now mandatory for all publicly-trusted "
                        "certs. The 'enforce' flag can cause certificate errors on older "
                        "clients that still parse it. Remove this header."
                    ),
                    3,
                ))
            else:
                issues.append((
                    "Expect-CT",
                    "Expect-CT is deprecated (CT is now mandatory). The header is ignored "
                    "by modern browsers. Remove it to reduce header noise.",
                    1,
                ))

        # ── P3P ───────────────────────────────────────────────────────────────
        p3p = self._get(headers, "p3p")
        if p3p:
            issues.append((
                "P3P",
                "P3P (Platform for Privacy Preferences) is a W3C standard from 2002 that "
                "was never widely implemented. All major browsers stopped supporting it. "
                "Remove this header — it conveys no meaningful privacy information.",
                1,
            ))

        # ── All good ──────────────────────────────────────────────────────────
        if not issues:
            return HeaderFinding(
                header="Deprecated Headers",
                status=FindingStatus.PRESENT,
                severity=Severity.INFO,
                score_impact=0,
                title="No dangerous or deprecated headers detected",
                description=(
                    "None of the dangerous deprecated headers (HPKP, Expect-CT, P3P) "
                    "are present in this response."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT",
                ],
            )

        total_penalty = min(sum(p for _, _, p in issues), 10)
        description = (
            "The following deprecated or dangerous headers were found:\n\n"
            + "\n\n".join(f"• [{h}] {desc}" for h, desc, _ in issues)
        )

        header_names = ", ".join(h for h, _, _ in issues)

        # Build exploit scenario based on what's found
        hpkp_present = any(h == "Public-Key-Pins" for h, _, _ in issues)
        exploit_scenario = None
        exploit_refs: list[str] = []

        if hpkp_present:
            exploit_scenario = (
                "HPKP 'HTTP Public Key Pinning' Denial-of-Service (pin bombing):\n\n"
                "1. Attacker with temporary MITM position (e.g. rogue CA, BGP hijack)\n"
                "   injects a response with:\n"
                "     Public-Key-Pins: pin-sha256='ATTACKER_KEY='; max-age=31536000\n"
                "2. All victims who loaded this response now have a ONE YEAR pin\n"
                "   for an attacker-controlled key that your server will never serve\n"
                "3. Every subsequent HTTPS visit fails with certificate error — ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN\n"
                "4. Users are locked out of your site for up to 1 year on that browser\n\n"
                "This happened to Github in 2016 when an HPKP misconfiguration caused\n"
                "browsers to reject GitHub's certificates globally for weeks."
            )
            exploit_refs = [
                "https://scotthelme.co.uk/hpkp-is-no-more/",
                "https://scotthelme.co.uk/im-giving-up-on-hpkp/",
                "https://www.rfc-editor.org/rfc/rfc7469",
                "https://developer.chrome.com/blog/removing-hpkp/",
            ]

        return HeaderFinding(
            header="Deprecated Headers",
            status=FindingStatus.WARNING,
            severity=Severity.HIGH if any(p >= 5 for _, _, p in issues) else Severity.MEDIUM,
            score_impact=-total_penalty,
            title=f"Dangerous/deprecated headers present: {header_names}",
            description=description,
            recommendation=(
                "Remove all deprecated headers from your server configuration.\n\n"
                "HPKP removal:\n"
                "  Nginx:   remove the add_header Public-Key-Pins line\n"
                "  Apache:  remove the Header set Public-Key-Pins line\n"
                "  Express: ensure helmet is up to date (removed HPKP support)\n\n"
                "If you previously served HPKP with a long max-age, serve max-age=0 "
                "briefly to clear cached pins from browsers, then remove the header."
            ),
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT",
                "https://scotthelme.co.uk/hpkp-is-no-more/",
            ],
            exploit_scenario=exploit_scenario,
            exploit_references=exploit_refs,
        )


def _extract_max_age(value: str) -> int | None:
    import re
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    return int(m.group(1)) if m else None
