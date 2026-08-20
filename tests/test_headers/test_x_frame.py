"""Tests for the X-Frame-Options checker."""

import pytest

from header_grade.headers.x_frame import XFrameChecker
from header_grade.models import FindingStatus


@pytest.fixture
def checker():
    return XFrameChecker()


def test_missing_no_csp(checker):
    finding = checker.check({})
    assert finding.status == FindingStatus.MISSING
    assert finding.score_impact == -15


def test_deny(checker):
    finding = checker.check({"x-frame-options": "DENY"})
    assert finding.status == FindingStatus.PRESENT
    assert finding.score_impact == 0


def test_sameorigin(checker):
    finding = checker.check({"x-frame-options": "SAMEORIGIN"})
    assert finding.status == FindingStatus.PRESENT
    assert finding.score_impact == 0


def test_csp_frame_ancestors_covers_missing_xfo(checker):
    headers = {"content-security-policy": "frame-ancestors 'self';"}
    finding = checker.check(headers)
    assert finding.status == FindingStatus.PRESENT
    assert finding.score_impact == 0


def test_allow_from_deprecated(checker):
    finding = checker.check({"x-frame-options": "ALLOW-FROM https://example.com"})
    assert finding.status == FindingStatus.WARNING
    assert finding.score_impact < 0


def test_invalid_value(checker):
    finding = checker.check({"x-frame-options": "ALLOWED"})
    assert finding.status == FindingStatus.INVALID
    assert finding.score_impact < 0
