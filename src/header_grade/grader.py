"""Score computation from a list of HeaderFindings."""

from __future__ import annotations

from .models import HeaderFinding

# Extra penalty when the site is served over plain HTTP
_HTTP_PENALTY = 10


def compute_score(findings: list[HeaderFinding], *, is_https: bool = True) -> int:
    """
    Calculate a 0–100 score from the list of findings.

    The base score is 100. Each finding contributes a score_impact
    (negative for problems, 0 for passing). The total is then clamped
    to [0, 100].

    An HTTP (non-HTTPS) site gets an additional penalty.
    """
    score = 100

    for finding in findings:
        score += finding.score_impact  # impacts are ≤0 for problems

    if not is_https:
        score -= _HTTP_PENALTY

    return max(0, min(100, score))
