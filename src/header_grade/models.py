"""Shared data models for header-grade."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    """How serious a finding is."""
    CRITICAL = "critical"   # >25 pts penalty
    HIGH = "high"           # 15–25 pts penalty
    MEDIUM = "medium"       # 5–15 pts penalty
    LOW = "low"             # <5 pts penalty
    INFO = "info"           # informational only


class FindingStatus(str, Enum):
    """Outcome of a header check."""
    PRESENT = "present"       # header present, value OK
    WARNING = "warning"       # header present but value is weak/deprecated
    MISSING = "missing"       # header completely absent
    INVALID = "invalid"       # header present but value is malformed/insecure


class HeaderFinding(BaseModel):
    """Result of evaluating a single security header."""
    header: str
    status: FindingStatus
    severity: Severity
    score_impact: int          # negative = penalty, positive = bonus
    title: str                 # short human title
    description: str           # what this header does and why it matters
    current_value: str | None = None   # what we got (None if missing)
    recommendation: str | None = None  # what to set it to
    references: list[str] = []         # MDN / spec / RFC links
    # ── Attack knowledge ──────────────────────────────────────────────────────
    exploit_scenario: str | None = None
    # Step-by-step explanation of how an attacker exploits the missing/weak
    # header. Written from the attacker's perspective so developers understand
    # the concrete threat, not just an abstract risk label.
    exploit_references: list[str] = []
    # PortSwigger Web Security Academy labs, OWASP Testing Guide entries,
    # CVEs, PoC tools, and research papers that demonstrate the attack.

    @property
    def is_ok(self) -> bool:
        return self.status == FindingStatus.PRESENT


class Grade(str, Enum):
    """Letter grade A+…F."""
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"

    @classmethod
    def from_score(cls, score: int) -> Grade:
        if score >= 95:
            return cls.A_PLUS
        if score >= 80:
            return cls.A
        if score >= 65:
            return cls.B
        if score >= 50:
            return cls.C
        if score >= 35:
            return cls.D
        if score >= 20:
            return cls.E
        return cls.F

    def numeric_rank(self) -> int:
        """Higher is better. Used for --min-grade comparison."""
        return {
            Grade.A_PLUS: 7,
            Grade.A: 6,
            Grade.B: 5,
            Grade.C: 4,
            Grade.D: 3,
            Grade.E: 2,
            Grade.F: 1,
        }[self]

    def __ge__(self, other: Grade) -> bool:  # type: ignore[override]
        return self.numeric_rank() >= other.numeric_rank()

    def __lt__(self, other: Grade) -> bool:  # type: ignore[override]
        return self.numeric_rank() < other.numeric_rank()


class GradeReport(BaseModel):
    """Full report for one URL."""
    url: str
    final_url: str                   # after redirects
    score: int                        # 0–100
    grade: Grade
    findings: list[HeaderFinding]
    raw_headers: dict[str, str]       # all response headers, lowercased keys
    https: bool
    redirect_chain: list[str] = []
    server: str | None = None

    @property
    def critical_findings(self) -> list[HeaderFinding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL and not f.is_ok]

    @property
    def high_findings(self) -> list[HeaderFinding]:
        return [f for f in self.findings if f.severity == Severity.HIGH and not f.is_ok]

    @property
    def warnings(self) -> list[HeaderFinding]:
        return [f for f in self.findings if f.status == FindingStatus.WARNING]

    @property
    def passed(self) -> list[HeaderFinding]:
        return [f for f in self.findings if f.is_ok]
