"""Tests for the HSTS checker."""

import pytest

from header_grade.headers.hsts import HSTSChecker
from header_grade.models import FindingStatus, Severity


@pytest.fixture
def checker():
    return HSTSChecker()


def test_missing_hsts(checker):
    finding = checker.check({})
    assert finding.status == FindingStatus.MISSING
    assert finding.severity == Severity.CRITICAL
    assert finding.score_impact == -25


def test_good_hsts(checker):
    headers = {"strict-transport-security": "max-age=31536000; includeSubDomains"}
    finding = checker.check(headers)
    assert finding.status == FindingStatus.PRESENT
    assert finding.score_impact == 0


def test_hsts_with_preload(checker):
    headers = {"strict-transport-security": "max-age=31536000; includeSubDomains; preload"}
    finding = checker.check(headers)
    assert finding.status == FindingStatus.PRESENT
    assert finding.score_impact == 0


def test_short_max_age(checker):
    headers = {"strict-transport-security": "max-age=3600"}
    finding = checker.check(headers)
    # 3600s < 86400s → too short
    assert finding.status == FindingStatus.WARNING
    assert finding.score_impact < 0


def test_very_short_max_age(checker):
    headers = {"strict-transport-security": "max-age=60"}
    finding = checker.check(headers)
    assert finding.score_impact == -15


def test_malformed_hsts(checker):
    headers = {"strict-transport-security": "includeSubDomains"}  # no max-age
    finding = checker.check(headers)
    assert finding.status == FindingStatus.INVALID
    assert finding.score_impact == -20


def test_no_include_subdomains_note(checker):
    headers = {"strict-transport-security": "max-age=31536000"}
    finding = checker.check(headers)
    # Should pass but recommend includeSubDomains
    assert finding.score_impact == 0
    assert finding.recommendation is not None
    assert "includeSubDomains" in finding.recommendation


def test_preload_recommendation(checker):
    headers = {"strict-transport-security": "max-age=31536000; includeSubDomains"}
    finding = checker.check(headers)
    assert finding.recommendation is not None
    assert "preload" in finding.recommendation.lower()
