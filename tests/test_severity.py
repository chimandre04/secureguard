"""Tests for severity module."""

import pytest
from secureguard.utils.severity import Severity, calculate_severity


def test_severity_from_cvss():
    """Test CVSS score to severity conversion."""
    assert Severity.from_cvss(9.5) == Severity.CRITICAL
    assert Severity.from_cvss(7.5) == Severity.HIGH
    assert Severity.from_cvss(5.0) == Severity.MEDIUM
    assert Severity.from_cvss(2.0) == Severity.LOW
    assert Severity.from_cvss(0.0) == Severity.INFO


def test_severity_comparison():
    """Test severity level comparisons."""
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFO

    assert Severity.INFO < Severity.CRITICAL
    assert Severity.LOW <= Severity.MEDIUM
    assert Severity.HIGH >= Severity.HIGH


def test_calculate_severity_from_cvss():
    """Test calculate_severity with CVSS score."""
    assert calculate_severity(cvss_score=9.0) == Severity.CRITICAL
    assert calculate_severity(cvss_score=7.0) == Severity.HIGH
    assert calculate_severity(cvss_score=4.0) == Severity.MEDIUM


def test_calculate_severity_from_string():
    """Test calculate_severity with severity string."""
    assert calculate_severity(severity_string="CRITICAL") == Severity.CRITICAL
    assert calculate_severity(severity_string="high") == Severity.HIGH
    assert calculate_severity(severity_string="invalid") == Severity.INFO


def test_calculate_severity_default():
    """Test calculate_severity with no inputs."""
    assert calculate_severity() == Severity.INFO
