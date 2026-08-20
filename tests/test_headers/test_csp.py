"""Tests for the CSP checker (deep misconfiguration analysis)."""

import pytest

from header_grade.headers.csp import CSPChecker
from header_grade.models import FindingStatus, Severity

_GOOD_CSP = (
    "default-src 'self'; "
    "script-src 'nonce-abc123'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


@pytest.fixture
def checker():
    return CSPChecker()


def test_missing_csp(checker):
    finding = checker.check({})
    assert finding.status == FindingStatus.MISSING
    assert finding.severity == Severity.CRITICAL
    assert finding.score_impact == -30


def test_report_only_without_enforce(checker):
    """Report-only mode counts as missing (no enforcement)."""
    headers = {"content-security-policy-report-only": "default-src 'self'"}
    finding = checker.check(headers)
    assert finding.status == FindingStatus.WARNING
    assert finding.score_impact == -20
    assert "report-only" in finding.title.lower()


def test_good_csp_present(checker):
    """A well-formed policy with no dangerous tokens and all critical directives."""
    headers = {"content-security-policy": _GOOD_CSP}
    finding = checker.check(headers)
    assert finding.status == FindingStatus.PRESENT
    assert finding.score_impact == 0


def test_unsafe_inline_no_nonce(checker):
    headers = {"content-security-policy": "default-src 'self' 'unsafe-inline'"}
    finding = checker.check(headers)
    assert finding.status == FindingStatus.WARNING
    assert finding.score_impact < 0
    assert "unsafe-inline" in finding.description


def test_unsafe_inline_with_nonce_is_ok(checker):
    """'unsafe-inline' is ignored by CSP3 browsers when a nonce is present."""
    csp = (
        "script-src 'nonce-RANDOM' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'self'; form-action 'self'"
    )
    finding = checker.check({"content-security-policy": csp})
    # Should be PRESENT — nonce overrides unsafe-inline in CSP3
    assert finding.status == FindingStatus.PRESENT
    assert finding.score_impact == 0


def test_unsafe_eval_detected(checker):
    csp = "script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'self'; form-action 'self'"
    finding = checker.check({"content-security-policy": csp})
    assert finding.status == FindingStatus.WARNING
    assert finding.score_impact < 0
    assert "unsafe-eval" in finding.description


def test_wildcard_in_script_src(checker):
    csp = "script-src * 'self'; object-src 'none'; base-uri 'self'; form-action 'self'"
    finding = checker.check({"content-security-policy": csp})
    assert finding.status == FindingStatus.WARNING
    assert finding.score_impact < 0


def test_https_scheme_wildcard(checker):
    """https: scheme in script-src allows any HTTPS host — very common misconfiguration."""
    csp = "script-src 'self' https:; object-src 'none'; base-uri 'self'; form-action 'self'"
    finding = checker.check({"content-security-policy": csp})
    assert finding.status == FindingStatus.WARNING
    assert finding.score_impact < 0
    assert "https:" in finding.description


def test_missing_base_uri_flagged(checker):
    """Missing base-uri directive should be flagged even if other directives are OK."""
    csp = "default-src 'self'; object-src 'none'; form-action 'self'"
    finding = checker.check({"content-security-policy": csp})
    assert finding.status == FindingStatus.WARNING
    assert "base-uri" in finding.description


def test_missing_form_action_flagged(checker):
    """Missing form-action directive should be flagged."""
    csp = "default-src 'self'; object-src 'none'; base-uri 'self'"
    finding = checker.check({"content-security-policy": csp})
    assert finding.status == FindingStatus.WARNING
    assert "form-action" in finding.description


def test_only_upgrade_insecure_requests(checker):
    headers = {"content-security-policy": "upgrade-insecure-requests"}
    finding = checker.check(headers)
    assert finding.status == FindingStatus.WARNING
    assert finding.score_impact == -20
    # title should convey that the policy is effectively useless for XSS protection
    assert "xss" in finding.title.lower() or "meta" in finding.title.lower()


def test_data_uri_in_script_src(checker):
    csp = "script-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'"
    finding = checker.check({"content-security-policy": csp})
    assert finding.status == FindingStatus.WARNING
    assert "data:" in finding.description


def test_recommendation_present_when_missing(checker):
    finding = checker.check({})
    assert finding.recommendation is not None


def test_references_present(checker):
    finding = checker.check({})
    assert len(finding.references) > 0
