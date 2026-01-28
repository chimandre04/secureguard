"""Severity rating system for vulnerabilities and misconfigurations."""

from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Severity levels based on CVSS scores."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Convert CVSS score to severity level.

        Args:
            score: CVSS score (0.0 - 10.0)

        Returns:
            Severity level
        """
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score >= 0.1:
            return cls.LOW
        else:
            return cls.INFO

    def __lt__(self, other):
        """Compare severity levels."""
        if not isinstance(other, Severity):
            return NotImplemented

        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self] < order[other]

    def __le__(self, other):
        return self < other or self == other

    def __gt__(self, other):
        return not self <= other

    def __ge__(self, other):
        return not self < other


def calculate_severity(cvss_score: Optional[float] = None,
                      severity_string: Optional[str] = None) -> Severity:
    """Calculate severity from CVSS score or severity string.

    Args:
        cvss_score: Optional CVSS score
        severity_string: Optional severity string

    Returns:
        Severity level
    """
    if cvss_score is not None:
        return Severity.from_cvss(cvss_score)

    if severity_string:
        try:
            return Severity(severity_string.upper())
        except ValueError:
            pass

    return Severity.INFO
