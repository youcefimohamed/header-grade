"""Tests for score computation and Grade mapping."""

from header_grade.grader import compute_score
from header_grade.models import FindingStatus, Grade, HeaderFinding, Severity


def _finding(impact: int, status: FindingStatus = FindingStatus.MISSING) -> HeaderFinding:
    return HeaderFinding(
        header="Test-Header",
        status=status,
        severity=Severity.HIGH,
        score_impact=impact,
        title="Test",
        description="Test finding",
    )


def test_perfect_score():
    findings = [_finding(0, FindingStatus.PRESENT)] * 10
    score = compute_score(findings)
    assert score == 100


def test_score_clamped_at_zero():
    findings = [_finding(-50)] * 5  # -250 total
    score = compute_score(findings)
    assert score == 0


def test_http_penalty():
    findings = [_finding(0, FindingStatus.PRESENT)] * 5
    score_https = compute_score(findings, is_https=True)
    score_http = compute_score(findings, is_https=False)
    assert score_https - score_http == 10


def test_grade_from_score():
    assert Grade.from_score(100) == Grade.A_PLUS
    assert Grade.from_score(95) == Grade.A_PLUS
    assert Grade.from_score(94) == Grade.A
    assert Grade.from_score(80) == Grade.A
    assert Grade.from_score(79) == Grade.B
    assert Grade.from_score(65) == Grade.B
    assert Grade.from_score(64) == Grade.C
    assert Grade.from_score(50) == Grade.C
    assert Grade.from_score(49) == Grade.D
    assert Grade.from_score(35) == Grade.D
    assert Grade.from_score(34) == Grade.E
    assert Grade.from_score(20) == Grade.E
    assert Grade.from_score(19) == Grade.F
    assert Grade.from_score(0) == Grade.F


def test_grade_comparison():
    assert Grade.A_PLUS >= Grade.A
    assert Grade.A >= Grade.B
    assert Grade.B >= Grade.C
    assert Grade.C >= Grade.D
    assert Grade.D >= Grade.E
    assert Grade.E >= Grade.F
    assert Grade.F < Grade.A


def test_grade_comparison_equal():
    assert Grade.A >= Grade.A
    assert not (Grade.B < Grade.B)


def test_realistic_score():
    """Missing CSP (-30) and HSTS (-25) → score 45 → Grade D."""
    findings = [
        _finding(-30),  # CSP
        _finding(-25),  # HSTS
        _finding(0, FindingStatus.PRESENT),  # X-Frame-Options OK
        _finding(0, FindingStatus.PRESENT),  # X-Content-Type-Options OK
        _finding(0, FindingStatus.PRESENT),  # Referrer-Policy OK
        _finding(-10),  # Permissions-Policy missing
    ]
    score = compute_score(findings)
    assert score == 35
    assert Grade.from_score(score) == Grade.D
