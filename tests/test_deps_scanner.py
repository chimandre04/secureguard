"""Tests for dependency scanner."""

import pytest
from pathlib import Path
from secureguard.scanners.deps_scanner import DependencyScanner


@pytest.fixture
def scanner():
    """Create a dependency scanner instance."""
    return DependencyScanner()


def test_detect_ecosystem(scanner):
    """Test ecosystem detection."""
    assert scanner._detect_ecosystem("requirements.txt") == "pip"
    assert scanner._detect_ecosystem("package.json") == "npm"
    assert scanner._detect_ecosystem("pom.xml") == "maven"
    assert scanner._detect_ecosystem("unknown.txt") is None


def test_parse_requirements_txt(scanner):
    """Test parsing requirements.txt."""
    test_file = Path("test_requirements.txt")
    test_file.write_text("""
# Test requirements
Flask==2.0.0
requests>=2.25.0
Django==3.1.0
# Comment line
pytest
""")

    try:
        deps = scanner._parse_python_dependencies(test_file)

        # Should extract Flask and Django with versions
        assert ("Flask", "2.0.0") in deps
        assert ("Django", "3.1.0") in deps

        # Should include requests but without specific version
        assert any(name == "requests" for name, _ in deps)

    finally:
        test_file.unlink()


def test_parse_package_json(scanner):
    """Test parsing package.json."""
    test_file = Path("test_package.json")
    test_file.write_text("""{
  "dependencies": {
    "express": "^4.17.1",
    "lodash": "4.17.20"
  },
  "devDependencies": {
    "jest": "^27.0.0"
  }
}
""")

    try:
        deps = scanner._parse_npm_dependencies(test_file)

        # Should extract all dependencies
        assert len(deps) >= 3

        # Check version extraction
        versions = {name: ver for name, ver in deps}
        assert "4.17.1" in versions.get("express", "")
        assert "4.17.20" in versions.get("lodash", "")

    finally:
        test_file.unlink()
