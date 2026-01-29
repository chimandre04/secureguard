"""Tests for compliance framework module."""

import pytest
from pathlib import Path

from secureguard.compliance.core.framework import FrameworkLoader, Framework
from secureguard.compliance.core.control import Control, Domain
from secureguard.utils.severity import Severity


class TestFrameworkLoader:
    """Tests for FrameworkLoader class."""

    def test_load_soc2_framework(self):
        """Test loading SOC 2 framework."""
        loader = FrameworkLoader()
        framework = loader.load("soc2")

        assert framework is not None
        assert framework.id == "SOC2_TYPE2"
        assert framework.name == "SOC 2 Type II"
        assert framework.version == "2017"
        assert len(framework.domains) > 0

    def test_load_nist_csf_framework(self):
        """Test loading NIST CSF framework."""
        loader = FrameworkLoader()
        framework = loader.load("nist_csf")

        assert framework is not None
        assert framework.id == "NIST_CSF"
        assert framework.name == "NIST Cybersecurity Framework"
        assert len(framework.domains) > 0

    def test_framework_caching(self):
        """Test that frameworks are cached."""
        loader = FrameworkLoader()

        # Load framework twice
        fw1 = loader.load("soc2")
        fw2 = loader.load("soc2")

        # Should be the same object (cached)
        assert fw1 is fw2

    def test_list_available_frameworks(self):
        """Test listing available frameworks."""
        loader = FrameworkLoader()
        frameworks = loader.list_available_frameworks()

        assert "soc2" in frameworks
        assert "nist_csf" in frameworks
        assert len(frameworks) >= 2

    def test_framework_not_found(self):
        """Test loading non-existent framework."""
        loader = FrameworkLoader()

        with pytest.raises(FileNotFoundError):
            loader.load("nonexistent_framework")

    def test_get_control(self):
        """Test getting a specific control."""
        loader = FrameworkLoader()
        framework = loader.load("soc2")

        control = framework.get_control("CC6.1")
        assert control is not None
        assert control.id == "CC6.1"
        assert control.framework_id == "SOC2_TYPE2"

    def test_get_all_controls(self):
        """Test getting all controls."""
        loader = FrameworkLoader()
        framework = loader.load("soc2")

        controls = framework.get_all_controls()
        assert len(controls) > 0
        assert all(isinstance(c, Control) for c in controls)

    def test_get_control_count(self):
        """Test getting control count."""
        loader = FrameworkLoader()
        framework = loader.load("soc2")

        count = framework.get_control_count()
        assert count > 0

    def test_control_has_mapped_checks(self):
        """Test that controls have mapped checks."""
        loader = FrameworkLoader()
        framework = loader.load("soc2")

        control = framework.get_control("CC6.1")
        assert len(control.mapped_checks) > 0
        assert all(check.check_id for check in control.mapped_checks)

    def test_control_severity(self):
        """Test control severity parsing."""
        loader = FrameworkLoader()
        framework = loader.load("soc2")

        control = framework.get_control("CC6.1")
        assert isinstance(control.severity, Severity)
        assert control.severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO
        ]

    def test_clear_cache(self):
        """Test clearing the framework cache."""
        loader = FrameworkLoader()

        # Load and cache
        fw1 = loader.load("soc2")

        # Clear cache
        loader.clear_cache()

        # Load again
        fw2 = loader.load("soc2")

        # Should be different objects
        assert fw1 is not fw2


class TestFramework:
    """Tests for Framework class."""

    def test_get_domain(self):
        """Test getting a specific domain."""
        loader = FrameworkLoader()
        framework = loader.load("soc2")

        domain = framework.get_domain("CC")
        assert domain is not None
        assert domain.id == "CC"
        assert domain.name == "Common Criteria"

    def test_get_controls_by_severity(self):
        """Test getting controls by severity."""
        loader = FrameworkLoader()
        framework = loader.load("soc2")

        high_controls = framework.get_controls_by_severity(Severity.HIGH)
        assert len(high_controls) > 0
        assert all(c.severity == Severity.HIGH for c in high_controls)

    def test_get_controls_by_category(self):
        """Test getting controls by category."""
        loader = FrameworkLoader()
        framework = loader.load("soc2")

        access_controls = framework.get_controls_by_category("Access Control")
        assert len(access_controls) > 0
        assert all(c.category == "Access Control" for c in access_controls)


class TestControl:
    """Tests for Control class."""

    def test_control_full_id(self):
        """Test control full ID property."""
        loader = FrameworkLoader()
        framework = loader.load("soc2")

        control = framework.get_control("CC6.1")
        assert control.full_id == "SOC2_TYPE2:CC6.1"

    def test_control_get_mapped_check_ids(self):
        """Test getting mapped check IDs."""
        loader = FrameworkLoader()
        framework = loader.load("soc2")

        control = framework.get_control("CC6.1")
        check_ids = control.get_mapped_check_ids()

        assert len(check_ids) > 0
        assert all(isinstance(check_id, str) for check_id in check_ids)


class TestDomain:
    """Tests for Domain class."""

    def test_domain_get_control(self):
        """Test getting control from domain."""
        loader = FrameworkLoader()
        framework = loader.load("soc2")

        domain = framework.get_domain("CC")
        control = domain.get_control("CC6.1")

        assert control is not None
        assert control.id == "CC6.1"

    def test_domain_get_control_count(self):
        """Test getting control count from domain."""
        loader = FrameworkLoader()
        framework = loader.load("soc2")

        domain = framework.get_domain("CC")
        count = domain.get_control_count()

        assert count > 0
