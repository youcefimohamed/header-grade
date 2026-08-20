"""Tests for new and deeply-fixed checkers."""

import pytest

from header_grade.headers.cors import CORSChecker
from header_grade.headers.deprecated_headers import DeprecatedHeadersChecker
from header_grade.headers.hsts import HSTSChecker
from header_grade.headers.referrer import ReferrerPolicyChecker
from header_grade.headers.x_permitted_cross_domain import XPermittedCrossDomainPoliciesChecker
from header_grade.headers.xss_protection import XSSProtectionChecker
from header_grade.models import FindingStatus, Severity

# ── HSTS new cases ────────────────────────────────────────────────────────────

class TestHSTSDeep:
    @pytest.fixture
    def checker(self):
        return HSTSChecker()

    def test_max_age_zero_is_critical(self, checker):
        """max-age=0 is an active HSTS opt-out — should be CRITICAL."""
        finding = checker.check({"strict-transport-security": "max-age=0"})
        assert finding.status == FindingStatus.INVALID
        assert finding.severity == Severity.CRITICAL
        assert finding.score_impact == -25

    def test_preload_without_include_subdomains(self, checker):
        """preload requires includeSubDomains — invalid combo."""
        finding = checker.check({
            "strict-transport-security": "max-age=31536000; preload"
        })
        assert finding.status == FindingStatus.WARNING
        assert "preload" in finding.title.lower()
        assert finding.score_impact < 0

    def test_very_short_max_age(self, checker):
        finding = checker.check({"strict-transport-security": "max-age=3600"})
        assert finding.status == FindingStatus.WARNING
        assert finding.score_impact == -15

    def test_good_hsts(self, checker):
        finding = checker.check({
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
        })
        assert finding.status == FindingStatus.PRESENT
        assert finding.score_impact == 0


# ── Referrer-Policy fix ───────────────────────────────────────────────────────

class TestReferrerPolicyDeep:
    @pytest.fixture
    def checker(self):
        return ReferrerPolicyChecker()

    def test_no_referrer_when_downgrade_is_weak(self, checker):
        """no-referrer-when-downgrade leaks full URL cross-HTTPS — should be penalised."""
        finding = checker.check({"referrer-policy": "no-referrer-when-downgrade"})
        assert finding.status == FindingStatus.WARNING
        assert finding.score_impact < 0

    def test_strict_origin_is_good(self, checker):
        finding = checker.check({"referrer-policy": "strict-origin-when-cross-origin"})
        assert finding.status == FindingStatus.PRESENT
        assert finding.score_impact == 0

    def test_no_referrer_is_good(self, checker):
        finding = checker.check({"referrer-policy": "no-referrer"})
        assert finding.status == FindingStatus.PRESENT
        assert finding.score_impact == 0

    def test_unsafe_url_penalised(self, checker):
        finding = checker.check({"referrer-policy": "unsafe-url"})
        assert finding.status == FindingStatus.WARNING
        assert finding.score_impact <= -7


# ── X-Permitted-Cross-Domain-Policies ────────────────────────────────────────

class TestXPermittedCrossDomain:
    @pytest.fixture
    def checker(self):
        return XPermittedCrossDomainPoliciesChecker()

    def test_missing(self, checker):
        finding = checker.check({})
        assert finding.status == FindingStatus.MISSING
        assert finding.score_impact == -4

    def test_none_is_correct(self, checker):
        finding = checker.check({"x-permitted-cross-domain-policies": "none"})
        assert finding.status == FindingStatus.PRESENT
        assert finding.score_impact == 0

    def test_all_is_dangerous(self, checker):
        finding = checker.check({"x-permitted-cross-domain-policies": "all"})
        assert finding.status == FindingStatus.WARNING
        assert finding.score_impact < 0
        assert finding.severity == Severity.MEDIUM

    def test_master_only_penalised(self, checker):
        finding = checker.check({"x-permitted-cross-domain-policies": "master-only"})
        assert finding.status == FindingStatus.WARNING
        assert finding.score_impact < 0


# ── Deprecated Headers ────────────────────────────────────────────────────────

class TestDeprecatedHeaders:
    @pytest.fixture
    def checker(self):
        return DeprecatedHeadersChecker()

    def test_clean_response_passes(self, checker):
        finding = checker.check({})
        assert finding.status == FindingStatus.PRESENT
        assert finding.score_impact == 0

    def test_hpkp_detected_as_critical(self, checker):
        finding = checker.check({
            "public-key-pins": "pin-sha256='abc='; max-age=2592000; includeSubDomains"
        })
        assert finding.status == FindingStatus.WARNING
        assert finding.severity == Severity.HIGH
        assert finding.score_impact < 0
        assert "Public-Key-Pins" in finding.title

    def test_hpkp_max_age_zero_lower_penalty(self, checker):
        """max-age=0 on HPKP means intentional removal — still a warning but lighter."""
        finding = checker.check({"public-key-pins": "pin-sha256='abc='; max-age=0"})
        assert finding.status == FindingStatus.WARNING
        # Lower penalty than active pinning
        assert finding.score_impact >= -3

    def test_expect_ct_enforce_detected(self, checker):
        finding = checker.check({"expect-ct": "enforce, max-age=86400"})
        assert finding.status == FindingStatus.WARNING
        assert finding.score_impact < 0

    def test_expect_ct_report_only_lighter(self, checker):
        finding = checker.check({"expect-ct": "max-age=86400"})
        assert finding.status == FindingStatus.WARNING
        # Lighter penalty than enforce
        enforce_finding = DeprecatedHeadersChecker().check(
            {"expect-ct": "enforce, max-age=86400"}
        )
        assert finding.score_impact >= enforce_finding.score_impact

    def test_hpkp_and_expect_ct_compound(self, checker):
        """Multiple deprecated headers accumulate penalty."""
        finding = checker.check({
            "public-key-pins": "pin-sha256='abc='; max-age=2592000",
            "expect-ct": "enforce, max-age=86400",
        })
        assert finding.score_impact < -4


# ── XSS Protection fix ───────────────────────────────────────────────────────

class TestXSSProtectionDeep:
    @pytest.fixture
    def checker(self):
        return XSSProtectionChecker()

    def test_absent_is_correct(self, checker):
        finding = checker.check({})
        assert finding.status == FindingStatus.MISSING
        assert finding.score_impact == 0

    def test_zero_is_safe(self, checker):
        finding = checker.check({"x-xss-protection": "0"})
        assert finding.status == FindingStatus.PRESENT
        assert finding.score_impact == 0

    def test_one_without_mode_block_penalised(self, checker):
        """X-XSS-Protection: 1 (without mode=block) can introduce XSS in IE."""
        finding = checker.check({"x-xss-protection": "1"})
        assert finding.score_impact < 0

    def test_mode_block_info_only(self, checker):
        """1; mode=block is deprecated but not actively harmful in modern context."""
        finding = checker.check({"x-xss-protection": "1; mode=block"})
        assert finding.score_impact == 0  # harmless, just noise


# ── CORS Vary: Origin ─────────────────────────────────────────────────────────

class TestCORSVary:
    @pytest.fixture
    def checker(self):
        return CORSChecker()

    def test_specific_origin_without_vary_penalised(self, checker):
        """Specific CORS origin without Vary: Origin = cache poisoning risk."""
        finding = checker.check({"access-control-allow-origin": "https://app.example.com"})
        assert finding.status == FindingStatus.WARNING
        assert finding.score_impact < 0
        assert "vary" in finding.description.lower()

    def test_specific_origin_with_vary_passes(self, checker):
        finding = checker.check({
            "access-control-allow-origin": "https://app.example.com",
            "vary": "Origin",
        })
        assert finding.status == FindingStatus.PRESENT
        assert finding.score_impact == 0

    def test_wildcard_no_credentials_flagged(self, checker):
        finding = checker.check({"access-control-allow-origin": "*"})
        assert finding.status == FindingStatus.WARNING
        assert finding.score_impact == -15

    def test_null_origin_flagged(self, checker):
        finding = checker.check({"access-control-allow-origin": "null"})
        assert finding.status == FindingStatus.WARNING
        assert finding.score_impact < 0
