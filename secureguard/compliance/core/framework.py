"""Data models and loader for compliance frameworks."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml

from secureguard.compliance.core.control import Control, Domain, MappedCheck, EvidenceRequirement
from secureguard.utils.severity import Severity


@dataclass
class Framework:
    """Compliance framework.

    Represents a complete compliance framework (e.g., SOC 2, NIST CSF, PCI DSS)
    with all its domains and controls.

    Attributes:
        id: Unique framework ID (e.g., "SOC2_TYPE2")
        name: Framework name (e.g., "SOC 2 Type II")
        version: Framework version
        description: Framework description
        domains: List of domains/categories in the framework
    """
    id: str
    name: str
    version: str
    description: str
    domains: List[Domain] = field(default_factory=list)

    def get_domain(self, domain_id: str) -> Optional[Domain]:
        """Get a specific domain by ID."""
        for domain in self.domains:
            if domain.id == domain_id:
                return domain
        return None

    def get_control(self, control_id: str) -> Optional[Control]:
        """Get a specific control by ID (searches all domains)."""
        for domain in self.domains:
            control = domain.get_control(control_id)
            if control:
                return control
        return None

    def get_all_controls(self) -> List[Control]:
        """Get all controls from all domains."""
        controls = []
        for domain in self.domains:
            controls.extend(domain.controls)
        return controls

    def get_control_count(self) -> int:
        """Return total number of controls in the framework."""
        return sum(domain.get_control_count() for domain in self.domains)

    def get_controls_by_severity(self, severity: Severity) -> List[Control]:
        """Get all controls with a specific severity level."""
        return [c for c in self.get_all_controls() if c.severity == severity]

    def get_controls_by_category(self, category: str) -> List[Control]:
        """Get all controls in a specific category."""
        return [c for c in self.get_all_controls() if c.category == category]


class FrameworkLoader:
    """Loader for compliance frameworks from YAML files.

    Loads framework definitions from YAML files and creates Framework objects
    with all their domains and controls.
    """

    def __init__(self, frameworks_dir: Optional[Path] = None):
        """Initialize the framework loader.

        Args:
            frameworks_dir: Directory containing framework YAML files.
                          If None, uses the default frameworks directory.
        """
        if frameworks_dir is None:
            # Default to the frameworks directory in the package
            package_dir = Path(__file__).parent.parent
            self.frameworks_dir = package_dir / "frameworks"
        else:
            self.frameworks_dir = Path(frameworks_dir)

        self._cache: Dict[str, Framework] = {}

    def load(self, framework_id: str) -> Framework:
        """Load a framework by ID.

        Args:
            framework_id: Framework ID (e.g., "soc2", "nist_csf", "pci_dss")

        Returns:
            Framework object

        Raises:
            FileNotFoundError: If framework file doesn't exist
            ValueError: If framework YAML is invalid
        """
        # Check cache first
        if framework_id in self._cache:
            return self._cache[framework_id]

        # Load from file
        framework_file = self.frameworks_dir / f"{framework_id}.yaml"
        if not framework_file.exists():
            raise FileNotFoundError(f"Framework file not found: {framework_file}")

        with open(framework_file, "r") as f:
            data = yaml.safe_load(f)

        framework = self._parse_framework(data)

        # Cache the framework
        self._cache[framework_id] = framework

        return framework

    def _parse_framework(self, data: Dict[str, Any]) -> Framework:
        """Parse framework data from YAML.

        Args:
            data: Parsed YAML data

        Returns:
            Framework object
        """
        fw_data = data.get("framework", {})

        # Parse domains
        domains = []
        for domain_data in data.get("domains", []):
            domain = self._parse_domain(domain_data, fw_data["id"])
            domains.append(domain)

        return Framework(
            id=fw_data["id"],
            name=fw_data["name"],
            version=fw_data.get("version", "1.0"),
            description=fw_data.get("description", ""),
            domains=domains
        )

    def _parse_domain(self, data: Dict[str, Any], framework_id: str) -> Domain:
        """Parse domain data from YAML.

        Args:
            data: Domain data from YAML
            framework_id: Parent framework ID

        Returns:
            Domain object
        """
        # Parse controls
        controls = []
        for control_data in data.get("controls", []):
            control = self._parse_control(control_data, framework_id)
            controls.append(control)

        return Domain(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            controls=controls
        )

    def _parse_control(self, data: Dict[str, Any], framework_id: str) -> Control:
        """Parse control data from YAML.

        Args:
            data: Control data from YAML
            framework_id: Parent framework ID

        Returns:
            Control object
        """
        # Parse mapped checks
        mapped_checks = []
        for check_data in data.get("mapped_checks", []):
            mapped_check = MappedCheck(
                check_id=check_data["check_id"],
                scanner_type=check_data["scanner_type"],
                weight=check_data.get("weight", 1.0)
            )
            mapped_checks.append(mapped_check)

        # Parse evidence requirements
        evidence_reqs = []
        for evidence_data in data.get("evidence_requirements", []):
            evidence_req = EvidenceRequirement(
                evidence_type=evidence_data["type"],
                frequency=evidence_data["frequency"],
                description=evidence_data.get("description")
            )
            evidence_reqs.append(evidence_req)

        # Parse severity
        severity_str = data.get("severity", "MEDIUM")
        severity = Severity[severity_str.upper()] if isinstance(severity_str, str) else severity_str

        return Control(
            id=data["id"],
            framework_id=framework_id,
            title=data["title"],
            description=data.get("description", ""),
            category=data.get("category", "General"),
            severity=severity,
            priority=data.get("priority", 3),
            requirements=data.get("requirements", []),
            mapped_checks=mapped_checks,
            evidence_requirements=evidence_reqs,
            implementation_guidance=data.get("implementation_guidance", "")
        )

    def list_available_frameworks(self) -> List[str]:
        """List all available frameworks in the frameworks directory.

        Returns:
            List of framework IDs
        """
        if not self.frameworks_dir.exists():
            return []

        frameworks = []
        for file in self.frameworks_dir.glob("*.yaml"):
            frameworks.append(file.stem)

        return sorted(frameworks)

    def clear_cache(self):
        """Clear the framework cache."""
        self._cache.clear()
