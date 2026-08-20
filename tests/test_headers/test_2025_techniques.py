"""
Tests for 2025-2026 security header techniques:
  - ReportingEndpointsChecker (RFC 9512, Feb 2024)
  - CSP Trusted Types advisory
  - Cookie Partitioned / CHIPS (Chrome 114+, 2023)
"""

import pytest

from header_grade.headers.cookies import CookieChecker
from header_grade.headers.csp import CSPChecker
from header_grade.headers.reporting_endpoints import ReportingEndpointsChecker
from header_grade.models import FindingStatus, Severity

# ── ReportingEndpointsChecker ─────────────────────────────────────────────────

class TestReportingEndpoints:
    @pytest.fixture
    def checker(self):
        return ReportingEndpointsChecker()

    def test_missing_entirely(self, checker):
        """No Reporting-Endpoints and no Report-To → MISSING, -4."""
        finding = checker.check({})
        assert finding.status == FindingStatus.MISSING
        assert finding.severity == Severity.LOW
        assert finding.score_impact == -4
        assert finding.exploit_scenario is not None
        assert "silently discarded" in finding.description.lower() or \
               "silently dropped" in finding.title.lower()

    def test_missing_with_legacy_report_to(self, checker):
        """Report-To present but Reporting-Endpoints absent → WARNING (advisory)."""
        finding = checker.check({
            "report-to": '{"group":"csp","max_age":86400,"endpoints":[{"url":"https://e.com"}]}'
        })
        assert finding.status == FindingStatus.WARNING
        assert finding.severity == Severity.LOW
        assert finding.score_impact == -2
        assert "deprecated" in finding.title.lower() or "deprecated" in finding.description.lower()

    def test_valid_https_endpoint(self, checker):
        """Valid HTTPS endpoint → PRESENT."""
        finding = checker.check({
            "reporting-endpoints": 'default="https://example.com/csp-reports"'
        })
        assert finding.status == FindingStatus.PRESENT
        assert finding.score_impact == 0

    def test_multiple_endpoints(self, checker):
        """Multiple named endpoints → PRESENT."""
        finding = checker.check({
            "reporting-endpoints": (
                'default="https://example.com/reports", '
                'csp-endpoint="https://csp.example.com/csp"'
            )
        })
        assert finding.status == FindingStatus.PRESENT

    def test_http_endpoint_is_invalid(self, checker):
        """HTTP (not HTTPS) endpoint → INVALID, -3."""
        finding = checker.check({
            "reporting-endpoints": 'default="http://example.com/csp-reports"'
        })
        assert finding.status == FindingStatus.INVALID
        assert finding.score_impact == -3
        assert "http" in finding.title.lower() or "http" in finding.description.lower()

    def test_exploit_references_present_when_missing(self, checker):
        """Exploit references populated when header is missing."""
        finding = checker.check({})
        assert len(finding.exploit_references) > 0

    def test_rfc_9512_in_references(self, checker):
        """RFC 9512 should appear in references."""
        finding = checker.check({})
        all_refs = finding.references + finding.exploit_references
        assert any("rfc9512" in ref or "rfc-editor" in ref for ref in all_refs)

    def test_present_has_reporting_wiring_recommendation(self, checker):
        """Present checker gives hint about wiring into CSP/COOP."""
        finding = checker.check({
            "reporting-endpoints": 'default="https://example.com/reports"'
        })
        assert finding.recommendation is not None
        assert "report-to" in finding.recommendation.lower()


# ── CSP Trusted Types advisory ────────────────────────────────────────────────

class TestCSPTrustedTypes:
    @pytest.fixture
    def checker(self):
        return CSPChecker()

    def test_no_trusted_types_advisory_in_good_csp(self, checker):
        """A well-configured CSP without Trusted Types → advisory in recommendation."""
        finding = checker.check({
            "content-security-policy": (
                "default-src 'self'; "
                "script-src 'self' 'nonce-abc123'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            )
        })
        assert finding.status == FindingStatus.PRESENT
        # Recommendation or references should mention Trusted Types
        text = (finding.recommendation or "") + " ".join(finding.references)
        assert "trusted" in text.lower() or "trusted-types" in text.lower()

    def test_trusted_types_directive_present(self, checker):
        """CSP with require-trusted-types-for → no advisory about it."""
        finding = checker.check({
            "content-security-policy": (
                "default-src 'self'; "
                "script-src 'self' 'nonce-abc123'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "form-action 'self'; "
                "require-trusted-types-for 'script'"
            )
        })
        assert finding.status == FindingStatus.PRESENT
        # Recommendation should NOT say "Add Trusted Types" as an action item
        if finding.recommendation:
            assert "require-trusted-types-for" not in finding.recommendation

    def test_trusted_types_advisory_in_warning_recommendation(self, checker):
        """CSP with issues should mention Trusted Types in recommendation."""
        finding = checker.check({
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"
        })
        assert finding.status == FindingStatus.WARNING
        assert finding.recommendation is not None
        # Should mention Trusted Types in the recommendation
        assert "trusted" in finding.recommendation.lower()


# ── Cookie Partitioned / CHIPS ────────────────────────────────────────────────

class TestCookiePartitioned:
    @pytest.fixture
    def checker(self):
        return CookieChecker()

    def test_samesite_none_without_partitioned_is_advisory(self, checker):
        """SameSite=None; Secure without Partitioned → advisory in issues."""
        finding = checker.check({
            "set-cookie": "embed_session=abc; SameSite=None; Secure; HttpOnly"
        })
        assert finding.status == FindingStatus.WARNING
        # The description should mention Partitioned
        assert "partitioned" in finding.description.lower()

    def test_samesite_none_with_partitioned_no_advisory(self, checker):
        """SameSite=None; Secure; Partitioned → no Partitioned advisory."""
        finding = checker.check({
            "set-cookie": "embed_session=abc; SameSite=None; Secure; HttpOnly; Partitioned"
        })
        # Should not mention Partitioned as an issue
        if not finding.is_ok:
            assert "partitioned" not in finding.description.lower()

    def test_partitioned_without_samesite_none_ignored(self, checker):
        """SameSite=Strict cookie — Partitioned is irrelevant (not checked)."""
        finding = checker.check({
            "set-cookie": "session=xyz; SameSite=Strict; Secure; HttpOnly"
        })
        # Should be PRESENT (all flags ok, Partitioned only applies to SameSite=None)
        assert finding.status == FindingStatus.PRESENT

    def test_samesite_none_partitioned_exploit_scenario(self, checker):
        """Missing Partitioned → exploit scenario mentions cross-site tracking."""
        finding = checker.check({
            "set-cookie": "widget=123; SameSite=None; Secure"
        })
        assert finding.exploit_scenario is not None
        assert "partitioned" in finding.exploit_scenario.lower() or \
               "cross-site" in finding.exploit_scenario.lower()

    def test_chips_reference_in_recommendation(self, checker):
        """Missing Partitioned → recommendation mentions CHIPS / Privacy Sandbox."""
        finding = checker.check({
            "set-cookie": "widget=123; SameSite=None; Secure; HttpOnly"
        })
        assert finding.recommendation is not None
        assert "partitioned" in finding.recommendation.lower()

    def test_missing_all_flags_prioritises_high_penalty(self, checker):
        """When all flags are missing, Partitioned advisory doesn't dominate."""
        finding = checker.check({
            "set-cookie": "session=abc"  # no Secure, HttpOnly, SameSite
        })
        assert finding.status == FindingStatus.WARNING
        # Penalty should be capped but reflects core missing flags
        assert finding.score_impact <= -10

    def test_partitioned_only_advisory_penalty_is_low(self, checker):
        """Only Partitioned missing (all other flags ok) → small penalty."""
        finding = checker.check({
            "set-cookie": "embed=xyz; SameSite=None; Secure; HttpOnly"
        })
        # Penalty should be low since only the advisory Partitioned flag is missing
        assert finding.score_impact >= -5

    def test_exploit_references_populated_for_cookie_issues(self, checker):
        """Cookie issues should have exploit references."""
        finding = checker.check({
            "set-cookie": "session=abc"
        })
        assert len(finding.exploit_references) > 0


# ── Fixgen platform integration ───────────────────────────────────────────────

class TestFixgenNewPlatforms:
    """Basic smoke tests — verify new platform builders produce non-empty output."""

    def _make_report(self):
        """Create a minimal GradeReport with a MISSING CSP finding."""
        from unittest.mock import MagicMock

        from header_grade.models import FindingStatus, GradeReport, HeaderFinding, Severity

        finding = HeaderFinding(
            header="Content-Security-Policy",
            status=FindingStatus.MISSING,
            severity=Severity.CRITICAL,
            score_impact=-30,
            title="CSP missing",
            description="no csp",
        )
        report = MagicMock(spec=GradeReport)
        report.findings = [finding]
        report.url = "https://example.com"
        return report

    @pytest.mark.parametrize("platform_id", [
        "cloudflare", "deno", "bun", "hono", "remix",
        "astro", "traefik", "haproxy", "rust-axum", "elixir",
    ])
    def test_new_platform_generates_output(self, platform_id):
        from header_grade.fixgen import generate_fix
        report = self._make_report()
        result = generate_fix(report, platform_id)
        assert isinstance(result, str)
        assert len(result) > 50  # non-trivial output

    @pytest.mark.parametrize("platform_id", [
        "cloudflare", "deno", "bun", "hono", "remix",
        "astro", "traefik", "haproxy", "rust-axum", "elixir",
    ])
    def test_new_platform_contains_csp_header(self, platform_id):
        """Every platform snippet should include the CSP header value."""
        from header_grade.fixgen import generate_fix
        report = self._make_report()
        result = generate_fix(report, platform_id)
        # Should reference Content-Security-Policy somewhere
        assert "content-security-policy" in result.lower() or \
               "contentSecurityPolicy" in result or \
               "content_security_policy" in result.lower() or \
               "csp" in result.lower()

    def test_all_new_platforms_in_platform_ids(self):
        """All new platform IDs should be in PLATFORM_IDS."""
        from header_grade.fixgen import PLATFORM_IDS
        new_platforms = [
            "cloudflare", "deno", "bun", "hono", "remix",
            "astro", "traefik", "haproxy", "rust-axum", "elixir",
        ]
        for pid in new_platforms:
            assert pid in PLATFORM_IDS, f"'{pid}' not found in PLATFORM_IDS"

    def test_platform_count_is_correct(self):
        """Should have 27 platforms total (17 original + 10 new)."""
        from header_grade.fixgen import PLATFORM_IDS
        assert len(PLATFORM_IDS) == 27

    def test_invalid_platform_raises(self):
        from header_grade.fixgen import generate_fix
        report = self._make_report()
        with pytest.raises(ValueError, match="Unknown platform"):
            generate_fix(report, "nonexistent-platform")
