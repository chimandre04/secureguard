"""Data models for evidence collection and audit trails."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional
import uuid


@dataclass
class Evidence:
    """Evidence for compliance control.

    Evidence represents a specific piece of data that supports compliance
    with a control, such as a scan result, configuration snapshot, or log entry.

    Attributes:
        id: Unique evidence ID (UUID)
        control_id: ID of the control this evidence supports
        evidence_type: Type of evidence (scan_result, config_snapshot, log_entry, etc.)
        timestamp: When the evidence was collected
        source: Source of the evidence (scanner name, system, etc.)
        data: Actual evidence data
        status: Evidence status (pass, fail, manual_review, not_applicable)
        metadata: Additional metadata about the evidence
    """
    id: str
    control_id: str
    evidence_type: str
    timestamp: datetime
    source: str
    data: Dict[str, Any]
    status: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate evidence data."""
        valid_statuses = ["pass", "fail", "manual_review", "not_applicable"]
        if self.status not in valid_statuses:
            raise ValueError(f"Status must be one of {valid_statuses}, got {self.status}")

    @classmethod
    def from_finding(cls, finding: Dict[str, Any], control_id: str, source: str) -> "Evidence":
        """Create evidence from a security finding.

        Args:
            finding: Security finding dictionary
            control_id: ID of the control
            source: Source scanner name

        Returns:
            Evidence instance
        """
        return cls(
            id=str(uuid.uuid4()),
            control_id=control_id,
            evidence_type="scan_result",
            timestamp=datetime.now(),
            source=source,
            data={
                "finding_id": finding.get("id"),
                "severity": finding.get("severity"),
                "description": finding.get("description"),
                "file": finding.get("file"),
                "resource": finding.get("resource"),
                "remediation": finding.get("remediation"),
            },
            status="fail",  # Findings indicate non-compliance
            metadata={
                "scanner_type": finding.get("type"),
                "check_id": finding.get("id"),
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence to dictionary."""
        return {
            "id": self.id,
            "control_id": self.control_id,
            "evidence_type": self.evidence_type,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "data": self.data,
            "status": self.status,
            "metadata": self.metadata,
        }


@dataclass
class AuditTrail:
    """Audit trail for compliance scans.

    Maintains a record of all compliance scans performed, including
    metadata, findings, and evidence collected.

    Attributes:
        scan_id: Unique scan ID (UUID)
        timestamp: When the scan was performed
        framework_id: ID of the framework scanned against
        policy_version: Version of the policy used
        scanner_version: Version of SecureGuard
        findings_count: Total number of findings
        evidence_collected: List of evidence items
        scan_metadata: Additional scan metadata
        scan_duration: Duration of the scan in seconds
    """
    scan_id: str
    timestamp: datetime
    framework_id: str
    policy_version: str
    scanner_version: str
    findings_count: int
    evidence_collected: List[Evidence] = field(default_factory=list)
    scan_metadata: Dict[str, Any] = field(default_factory=dict)
    scan_duration: Optional[float] = None

    def add_evidence(self, evidence: Evidence):
        """Add evidence to the audit trail."""
        self.evidence_collected.append(evidence)

    def get_evidence_by_control(self, control_id: str) -> List[Evidence]:
        """Get all evidence for a specific control."""
        return [e for e in self.evidence_collected if e.control_id == control_id]

    def get_evidence_count(self) -> int:
        """Return total evidence count."""
        return len(self.evidence_collected)

    def get_passing_evidence_count(self) -> int:
        """Return count of passing evidence."""
        return sum(1 for e in self.evidence_collected if e.status == "pass")

    def get_failing_evidence_count(self) -> int:
        """Return count of failing evidence."""
        return sum(1 for e in self.evidence_collected if e.status == "fail")

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit trail to dictionary."""
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp.isoformat(),
            "framework_id": self.framework_id,
            "policy_version": self.policy_version,
            "scanner_version": self.scanner_version,
            "findings_count": self.findings_count,
            "evidence_count": self.get_evidence_count(),
            "passing_evidence": self.get_passing_evidence_count(),
            "failing_evidence": self.get_failing_evidence_count(),
            "scan_metadata": self.scan_metadata,
            "scan_duration": self.scan_duration,
        }


@dataclass
class GapAnalysisResult:
    """Gap analysis result for a compliance control.

    Represents the compliance status of a single control based on
    mapped security checks and findings.

    Attributes:
        control: The compliance control
        status: Compliance status (compliant, partial, non_compliant, not_tested)
        coverage: Coverage percentage (0-100)
        findings: List of security findings related to this control
        missing_evidence: List of missing evidence items
        recommendations: List of recommendations for remediation
        risk_level: Overall risk level for this control
    """
    control: Any  # Control type - avoiding circular import
    status: str
    coverage: float
    findings: List[Dict[str, Any]] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    risk_level: Any = None  # Severity type

    def __post_init__(self):
        """Validate gap analysis data."""
        valid_statuses = ["compliant", "partial", "non_compliant", "not_tested"]
        if self.status not in valid_statuses:
            raise ValueError(f"Status must be one of {valid_statuses}, got {self.status}")

        if not 0.0 <= self.coverage <= 100.0:
            raise ValueError(f"Coverage must be between 0 and 100, got {self.coverage}")

    @property
    def is_compliant(self) -> bool:
        """Return True if the control is compliant."""
        return self.status == "compliant"

    @property
    def findings_count(self) -> int:
        """Return number of findings."""
        return len(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        """Convert gap analysis result to dictionary."""
        return {
            "control_id": self.control.id,
            "control_title": self.control.title,
            "status": self.status,
            "coverage": self.coverage,
            "findings_count": self.findings_count,
            "findings": self.findings,
            "missing_evidence": self.missing_evidence,
            "recommendations": self.recommendations,
            "risk_level": str(self.risk_level) if self.risk_level else None,
        }


@dataclass
class ComplianceReport:
    """Complete compliance assessment report.

    Aggregates all gap analysis results for a framework into a
    comprehensive compliance report.

    Attributes:
        framework: The compliance framework
        scan_timestamp: When the scan was performed
        overall_status: Overall compliance status
        overall_score: Overall compliance score (0-100)
        gaps: List of gap analysis results
        summary: Summary statistics by status
        evidence_trail: Audit trail for this scan
    """
    framework: Any  # Framework type - avoiding circular import
    scan_timestamp: datetime
    overall_status: str
    overall_score: float
    gaps: List[GapAnalysisResult] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    evidence_trail: Optional[AuditTrail] = None

    def get_compliant_count(self) -> int:
        """Return number of compliant controls."""
        return sum(1 for gap in self.gaps if gap.status == "compliant")

    def get_non_compliant_count(self) -> int:
        """Return number of non-compliant controls."""
        return sum(1 for gap in self.gaps if gap.status == "non_compliant")

    def get_partial_count(self) -> int:
        """Return number of partially compliant controls."""
        return sum(1 for gap in self.gaps if gap.status == "partial")

    def get_not_tested_count(self) -> int:
        """Return number of untested controls."""
        return sum(1 for gap in self.gaps if gap.status == "not_tested")

    def calculate_summary(self):
        """Calculate summary statistics."""
        self.summary = {
            "compliant": self.get_compliant_count(),
            "partial": self.get_partial_count(),
            "non_compliant": self.get_non_compliant_count(),
            "not_tested": self.get_not_tested_count(),
            "total": len(self.gaps),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert compliance report to dictionary."""
        self.calculate_summary()
        return {
            "framework": {
                "id": self.framework.id,
                "name": self.framework.name,
                "version": self.framework.version,
            },
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "overall_status": self.overall_status,
            "overall_score": round(self.overall_score, 2),
            "summary": self.summary,
            "gaps": [gap.to_dict() for gap in self.gaps],
            "audit_trail": self.evidence_trail.to_dict() if self.evidence_trail else None,
        }
