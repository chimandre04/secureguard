"""Tests for attack detector."""

import pytest
from secureguard.sensors.attack_detector import AttackDetector


@pytest.fixture
def detector():
    """Create an attack detector instance."""
    return AttackDetector()


def test_sql_injection_detection(detector):
    """Test SQL injection detection."""
    detections = detector.detect(
        method="GET",
        path="/users/1",
        query_params={"id": "1' OR '1'='1"},
        headers={}
    )

    assert len(detections) > 0
    assert any(d["attack_type"] == "SQL_INJECTION" for d in detections)


def test_xss_detection(detector):
    """Test XSS detection."""
    detections = detector.detect(
        method="GET",
        path="/search",
        query_params={"q": "<script>alert('XSS')</script>"},
        headers={}
    )

    assert len(detections) > 0
    assert any(d["attack_type"] == "XSS" for d in detections)


def test_path_traversal_detection(detector):
    """Test path traversal detection."""
    detections = detector.detect(
        method="GET",
        path="/files",
        query_params={"file": "../../etc/passwd"},
        headers={}
    )

    assert len(detections) > 0
    assert any(d["attack_type"] == "PATH_TRAVERSAL" for d in detections)


def test_command_injection_detection(detector):
    """Test command injection detection."""
    detections = detector.detect(
        method="POST",
        path="/execute",
        query_params={},
        headers={},
        body='{"cmd": "ls; cat /etc/passwd"}'
    )

    assert len(detections) > 0
    assert any(d["attack_type"] == "COMMAND_INJECTION" for d in detections)


def test_no_attack_detection(detector):
    """Test that legitimate requests pass through."""
    detections = detector.detect(
        method="GET",
        path="/api/users/123",
        query_params={"page": "1", "limit": "10"},
        headers={"User-Agent": "Mozilla/5.0"}
    )

    # Should have no high-confidence detections
    high_confidence = [d for d in detections if d["confidence"] == "high"]
    assert len(high_confidence) == 0


def test_encoded_xss_detection(detector):
    """Test detection of encoded XSS attempts."""
    detections = detector.detect(
        method="GET",
        path="/search",
        query_params={"q": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"},
        headers={}
    )

    assert len(detections) > 0
    assert any(d["attack_type"] == "XSS" for d in detections)
