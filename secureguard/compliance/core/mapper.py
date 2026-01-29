"""Compliance mapper for mapping security findings to compliance controls."""

from typing import List, Dict, Any, Set
from collections import defaultdict

from secureguard.compliance.core.framework import Framework
from secureguard.compliance.core.control import Control


class ComplianceMapper:
    """Maps security findings to compliance framework controls.

    The mapper analyzes security findings from SecureGuard scanners
    and maps them to relevant compliance controls based on check IDs.
    """

    def __init__(self, framework: Framework):
        """Initialize the compliance mapper.

        Args:
            framework: The compliance framework to map against
        """
        self.framework = framework
        self._control_map = self._build_control_map()

    def _build_control_map(self) -> Dict[str, List[Control]]:
        """Build a mapping of check IDs to controls.

        Returns:
            Dictionary mapping check IDs to list of controls
        """
        control_map = defaultdict(list)

        for control in self.framework.get_all_controls():
            for mapped_check in control.mapped_checks:
                control_map[mapped_check.check_id].append(control)

        return dict(control_map)

    def map_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Map security findings to compliance controls.

        Args:
            findings: List of security findings from scanners

        Returns:
            Dictionary mapping control IDs to their related findings
        """
        mapped_findings = defaultdict(list)

        for finding in findings:
            # Get the check ID from the finding
            # Findings can have different structures depending on scanner type
            check_id = self._extract_check_id(finding)

            if not check_id:
                continue

            # Find controls mapped to this check
            controls = self._control_map.get(check_id, [])

            for control in controls:
                # Add finding to this control's list
                mapped_findings[control.id].append(finding)

        return dict(mapped_findings)

    def _extract_check_id(self, finding: Dict[str, Any]) -> str:
        """Extract the check ID from a finding.

        Args:
            finding: Security finding dictionary

        Returns:
            Check ID or empty string if not found
        """
        # Try different possible field names
        # IaC findings have "id" field (e.g., "TF001", "CF002")
        if "id" in finding:
            return finding["id"]

        # Runtime findings have "type" field (e.g., "SQL_INJECTION")
        if "type" in finding:
            finding_type = finding["type"]
            # For runtime attacks, the type might be the full attack name
            if finding_type in ["SQL_INJECTION", "XSS", "PATH_TRAVERSAL",
                                "COMMAND_INJECTION", "XXE", "LDAP_INJECTION",
                                "SSRF", "NOSQL_INJECTION"]:
                return finding_type

        # Dependency findings
        if finding.get("type") == "DEPENDENCY_VULNERABILITY":
            return "DEPENDENCY_VULNERABILITY"

        return ""

    def get_controls_for_finding(self, finding: Dict[str, Any]) -> List[Control]:
        """Get all controls relevant to a specific finding.

        Args:
            finding: Security finding dictionary

        Returns:
            List of controls related to this finding
        """
        check_id = self._extract_check_id(finding)
        if not check_id:
            return []

        return self._control_map.get(check_id, [])

    def get_unmapped_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get findings that don't map to any control.

        Args:
            findings: List of security findings

        Returns:
            List of unmapped findings
        """
        unmapped = []

        for finding in findings:
            check_id = self._extract_check_id(finding)
            if not check_id or check_id not in self._control_map:
                unmapped.append(finding)

        return unmapped

    def get_mapping_coverage(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get mapping coverage statistics.

        Args:
            findings: List of security findings

        Returns:
            Dictionary with coverage statistics
        """
        total_findings = len(findings)
        mapped_findings = []
        unmapped_findings = []

        for finding in findings:
            check_id = self._extract_check_id(finding)
            if check_id and check_id in self._control_map:
                mapped_findings.append(finding)
            else:
                unmapped_findings.append(finding)

        coverage_percent = (len(mapped_findings) / total_findings * 100) if total_findings > 0 else 0

        return {
            "total_findings": total_findings,
            "mapped_findings": len(mapped_findings),
            "unmapped_findings": len(unmapped_findings),
            "coverage_percent": round(coverage_percent, 2),
            "unique_check_ids": len(set(self._extract_check_id(f) for f in findings if self._extract_check_id(f))),
            "mapped_controls": len(set(c.id for check_id in self._control_map for c in self._control_map[check_id]))
        }

    def get_controls_by_scanner_type(self, scanner_type: str) -> List[Control]:
        """Get all controls that map to a specific scanner type.

        Args:
            scanner_type: Scanner type (deps, iac, runtime)

        Returns:
            List of controls
        """
        controls = set()

        for control in self.framework.get_all_controls():
            for mapped_check in control.mapped_checks:
                if mapped_check.scanner_type == scanner_type:
                    controls.add(control)
                    break

        return list(controls)

    def get_check_weight(self, check_id: str, control_id: str) -> float:
        """Get the weight of a check for a specific control.

        Args:
            check_id: The check ID
            control_id: The control ID

        Returns:
            Weight value (0.0-1.0) or 0.0 if not found
        """
        control = self.framework.get_control(control_id)
        if not control:
            return 0.0

        for mapped_check in control.mapped_checks:
            if mapped_check.check_id == check_id:
                return mapped_check.weight

        return 0.0
