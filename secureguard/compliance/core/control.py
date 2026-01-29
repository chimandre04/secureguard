"""Data models for compliance controls."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from secureguard.utils.severity import Severity


@dataclass
class MappedCheck:
    """Maps a SecureGuard security check to a compliance control.

    Attributes:
        check_id: The SecureGuard check ID (e.g., "TF001", "CF002")
        scanner_type: Type of scanner ("deps", "iac", "runtime")
        weight: Importance weight (0.0 - 1.0), used in gap analysis
    """
    check_id: str
    scanner_type: str
    weight: float = 1.0

    def __post_init__(self):
        """Validate weight is between 0 and 1."""
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError(f"Weight must be between 0.0 and 1.0, got {self.weight}")


@dataclass
class EvidenceRequirement:
    """Evidence requirement for a compliance control.

    Attributes:
        evidence_type: Type of evidence required
        frequency: How often evidence should be collected
        description: Description of the evidence requirement
    """
    evidence_type: str
    frequency: str
    description: Optional[str] = None


@dataclass
class Control:
    """Compliance control representation.

    A control represents a specific compliance requirement from a framework.
    Each control maps to one or more SecureGuard security checks.

    Attributes:
        id: Unique control ID within the framework (e.g., "CC6.1")
        framework_id: ID of the parent framework (e.g., "SOC2_TYPE2")
        title: Short title of the control
        description: Detailed description
        category: Category/domain of the control
        severity: Severity level of non-compliance
        priority: Priority (1-5, 1 being highest)
        requirements: List of specific requirements
        mapped_checks: Security checks mapped to this control
        evidence_requirements: Evidence requirements
        implementation_guidance: Guidance for implementing this control
    """
    id: str
    framework_id: str
    title: str
    description: str
    category: str
    severity: Severity
    priority: int = 3
    requirements: List[str] = field(default_factory=list)
    mapped_checks: List[MappedCheck] = field(default_factory=list)
    evidence_requirements: List[EvidenceRequirement] = field(default_factory=list)
    implementation_guidance: str = ""

    def __post_init__(self):
        """Validate control data."""
        if not 1 <= self.priority <= 5:
            raise ValueError(f"Priority must be between 1 and 5, got {self.priority}")

        # Convert severity string to Severity enum if needed
        if isinstance(self.severity, str):
            self.severity = Severity[self.severity.upper()]

    @property
    def full_id(self) -> str:
        """Return full control ID including framework."""
        return f"{self.framework_id}:{self.id}"

    def get_mapped_check_ids(self) -> List[str]:
        """Return list of mapped check IDs."""
        return [check.check_id for check in self.mapped_checks]


@dataclass
class Domain:
    """Framework domain/category grouping controls.

    Attributes:
        id: Domain ID (e.g., "CC" for Common Criteria)
        name: Domain name
        description: Domain description
        controls: List of controls in this domain
    """
    id: str
    name: str
    description: str
    controls: List[Control] = field(default_factory=list)

    def get_control(self, control_id: str) -> Optional[Control]:
        """Get a specific control by ID."""
        for control in self.controls:
            if control.id == control_id:
                return control
        return None

    def get_control_count(self) -> int:
        """Return number of controls in this domain."""
        return len(self.controls)
